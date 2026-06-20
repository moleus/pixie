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

import net.bytebuddy.asm.Advice;

/**
 * ByteBuddy advice woven into {@code org.apache.kafka.common.network.SslTransportLayer}.
 *
 * <p>{@code SslTransportLayer} holds both the {@code SSLEngine} (which does the
 * encrypt/decrypt) and the raw {@code socketChannel}. That makes it the ideal
 * interception point: we see plaintext AND can recover the OS fd in one place.
 *
 * <ul>
 *   <li>{@code write(ByteBuffer src)} — on entry, {@code src} is plaintext that
 *       is about to be {@code sslEngine.wrap()}-ed (encrypted). [EGRESS]</li>
 *   <li>{@code read(ByteBuffer dst)} — on exit, the last {@code return}-value
 *       bytes placed into {@code dst} are freshly {@code unwrap()}-ed
 *       (decrypted) plaintext. [INGRESS]</li>
 * </ul>
 */
public final class SslTransportLayerAdvice {
  private SslTransportLayerAdvice() {}

  /**
   * Advice for {@code int write(ByteBuffer src)}.
   *
   * <p>{@code write()} may consume only part of {@code src} (the SSLEngine fills
   * netWriteBuffer, which may not fully flush under socket back-pressure); the
   * caller then retries with the same buffer. Capturing the whole remaining
   * buffer on entry would therefore double-count the un-consumed tail on the next
   * call. Instead we record the start position on entry and capture exactly the
   * bytes consumed (start..position) on exit.
   */
  public static final class Write {
    private Write() {}

    @Advice.OnMethodEnter
    public static int enter(@Advice.Argument(0) ByteBuffer src) {
      return src == null ? -1 : src.position();
    }

    @Advice.OnMethodExit
    public static void exit(
        @Advice.FieldValue("socketChannel") Object channel,
        @Advice.Argument(0) ByteBuffer src,
        @Advice.Enter int startPos) {
      PixieCapture.onWriteConsumed(channel, src, startPos);
    }
  }

  /** Advice for {@code int read(ByteBuffer dst)}. */
  public static final class Read {
    private Read() {}

    @Advice.OnMethodExit
    public static void exit(
        @Advice.FieldValue("socketChannel") Object channel,
        @Advice.Argument(0) ByteBuffer dst,
        @Advice.Return int ret) {
      PixieCapture.onRead(channel, dst, ret);
    }
  }
}
