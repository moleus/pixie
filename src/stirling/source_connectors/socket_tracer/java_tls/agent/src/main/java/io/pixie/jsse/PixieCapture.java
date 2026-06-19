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

  /** Egress: {@code src} holds plaintext about to be wrapped/encrypted. */
  public static void onWrite(Object channel, ByteBuffer src) {
    if (!enabled || src == null) {
      return;
    }
    int remaining = src.remaining();
    if (remaining <= 0) {
      return;
    }
    // duplicate() shares content but has an independent position/limit, so we
    // never disturb the buffer Kafka is about to consume.
    capture(channel, src.duplicate(), remaining, DIR_EGRESS);
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
    if (IN_CAPTURE.get()) {
      return;
    }
    IN_CAPTURE.set(Boolean.TRUE);
    try {
      int fd = FdExtractor.fdOf(channel);
      if (fd < 0) {
        return;
      }
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
}
