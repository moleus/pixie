/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.pixie.jsse;

import java.nio.ByteBuffer;

/**
 * Captures TLS plaintext at the JSSE/Kafka boundary and forwards it to eBPF.
 *
 * <p>The advice injected into {@code SslTransportLayer} calls into here. We keep
 * all real logic in this class (rather than inlined advice) so the bytecode
 * woven into the broker class stays a single static call.
 *
 * <p>Plaintext is copied into a per-thread *direct* scratch buffer before being
 * handed to native code, because the eBPF program reads it with
 * {@code bpf_probe_read_user} and that requires a stable, resident native
 * address (an on-heap byte[] could move or be non-resident).
 */
public final class PixieCapture {
  // Values intentionally match Pixie's traffic_direction_t enum (kEgress=0,
  // kIngress=1) so the integer handed to eBPF is used verbatim.
  public static final int DIR_EGRESS = 0;  // plaintext, about to be encrypted & written
  public static final int DIR_INGRESS = 1; // decrypted, just read from the socket

  private static final int SCRATCH_CAP = 64 * 1024;
  private static final ThreadLocal<ByteBuffer> SCRATCH =
      ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(SCRATCH_CAP));

  // Re-entrancy guard: emit() must never recursively trigger capture (it won't
  // touch SSL, but be safe against unexpected instrumentation interplay).
  private static final ThreadLocal<Boolean> IN_CAPTURE = ThreadLocal.withInitial(() -> Boolean.FALSE);

  private static volatile boolean enabled = true;

  private PixieCapture() {}

  public static void setEnabled(boolean v) {
    enabled = v;
  }

  /**
   * Egress: capture exactly the plaintext consumed by one {@code write(src)}
   * call — bytes [startPos, src.position()). This avoids double-counting the
   * un-consumed tail when {@code write()} is retried under back-pressure.
   */
  public static void onWriteConsumed(Object channel, ByteBuffer src, int startPos) {
    if (!enabled || src == null || startPos < 0) {
      return;
    }
    int endPos = src.position();
    int n = endPos - startPos;
    if (n <= 0) {
      return;
    }
    // duplicate() shares content but has an independent position/limit, so we
    // never disturb the buffer Kafka is using.
    ByteBuffer view = src.duplicate();
    view.position(startPos);
    view.limit(endPos);
    capture(channel, view, n, DIR_EGRESS);
  }

  /**
   * Ingress: after {@code read()} returns, the last {@code ret} bytes written
   * into {@code dst} are freshly-decrypted plaintext.
   */
  public static void onRead(Object channel, ByteBuffer dst, int ret) {
    if (!enabled || dst == null || ret <= 0) {
      return;
    }
    ByteBuffer view = dst.duplicate();
    int end = view.position();
    int start = end - ret;
    if (start < 0) {
      return;
    }
    view.position(start);
    view.limit(end);
    capture(channel, view, ret, DIR_INGRESS);
  }

  private static void capture(Object channel, ByteBuffer view, int len, int direction) {
    int fd = FdExtractor.fdOf(channel);
    if (fd >= 0) {
      captureFd(fd, view, len, direction);
    }
  }

  /** Copy [view.position(), +len) into the per-thread direct buffer and emit it. */
  private static void captureFd(int fd, ByteBuffer view, int len, int direction) {
    if (fd < 0 || len <= 0 || IN_CAPTURE.get()) {
      return;
    }
    IN_CAPTURE.set(Boolean.TRUE);
    try {
      ByteBuffer scratch = SCRATCH.get();
      int n = Math.min(len, scratch.capacity());
      scratch.clear();
      int savedLimit = view.limit();
      view.limit(view.position() + n);
      scratch.put(view);
      view.limit(savedLimit);
      // scratch now holds plaintext in [0, n); native reads from its base addr.
      NativeBridge.emit(fd, direction, scratch, n);
    } catch (Throwable t) {
      // Never let observability break the broker.
    } finally {
      IN_CAPTURE.set(Boolean.FALSE);
    }
  }

  // ----- Generic SSLEngine path (see SSLEngineAdvice / EngineContext) -----

  /** Record the start positions of appData[offset, offset+length). */
  public static int[] enginePositions(ByteBuffer[] appData, int offset, int length) {
    if (!enabled || appData == null || length <= 0) {
      return null;
    }
    // Skip entirely when a known transport wrapper (Kafka) will capture with the
    // exact fd — avoids double-capturing the same plaintext.
    if (EngineContext.inTransport.get()) {
      return null;
    }
    try {
      int[] pos = new int[length];
      for (int i = 0; i < length; i++) {
        ByteBuffer b = appData[offset + i];
        pos[i] = (b == null) ? -1 : b.position();
      }
      return pos;
    } catch (Throwable t) {
      return null;
    }
  }

  /** wrap(): bytes consumed from each appData buffer are egress plaintext. */
  public static void onEngineWrap(ByteBuffer[] appData, int offset, int length, int[] startPositions) {
    engineDelta(appData, offset, length, startPositions, DIR_EGRESS);
  }

  /** unwrap(): bytes produced into each appData buffer are ingress plaintext. */
  public static void onEngineUnwrap(ByteBuffer[] appData, int offset, int length, int[] startPositions) {
    engineDelta(appData, offset, length, startPositions, DIR_INGRESS);
  }

  private static void engineDelta(ByteBuffer[] appData, int offset, int length, int[] start,
                                  int direction) {
    if (!enabled || start == null || appData == null) {
      return;
    }
    int fd = EngineContext.getFd();  // set by SocketChannelFdAdvice on this thread
    if (fd < 0) {
      return;
    }
    try {
      for (int i = 0; i < length; i++) {
        ByteBuffer b = appData[offset + i];
        if (b == null || start[i] < 0) {
          continue;
        }
        int end = b.position();
        int n = end - start[i];
        if (n <= 0) {
          continue;
        }
        ByteBuffer view = b.duplicate();
        view.position(start[i]);
        view.limit(end);
        captureFd(fd, view, n, direction);
      }
    } catch (Throwable t) {
      // never break the app
    }
  }
}
