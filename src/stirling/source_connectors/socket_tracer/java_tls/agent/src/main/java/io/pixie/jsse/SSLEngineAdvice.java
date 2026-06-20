/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
package io.pixie.jsse;

import java.nio.ByteBuffer;

import net.bytebuddy.asm.Advice;

/**
 * Generic JVM TLS hook: advice on {@code sun.security.ssl.SSLEngineImpl}.
 *
 * <p>This covers ANY JSSE {@code SSLEngine} user (generic NIO, Netty, gRPC-netty, …),
 * not just Kafka. Plaintext is read straight from the engine's app buffers:
 * <ul>
 *   <li>{@code wrap(appData[], off, len, netData)} — appData is plaintext being
 *       encrypted. On exit, the bytes consumed from each appData buffer are egress
 *       plaintext.</li>
 *   <li>{@code unwrap(netData, appData[], off, len)} — appData receives decrypted
 *       plaintext. On exit, the bytes produced into each appData buffer are ingress
 *       plaintext.</li>
 * </ul>
 *
 * <p>The fd comes from {@link EngineContext} (set by {@link SocketChannelFdAdvice}
 * on the same thread). Capture is skipped while inside a known transport wrapper
 * (Kafka's SslTransportLayer), which already captures with the exact fd — see
 * {@link EngineContext#inTransport}.
 */
public final class SSLEngineAdvice {
  private SSLEngineAdvice() {}

  /** Advice for {@code SSLEngineResult wrap(ByteBuffer[] appData, int off, int len, ByteBuffer net)}. */
  public static final class Wrap {
    private Wrap() {}

    @Advice.OnMethodEnter
    public static int[] enter(
        @Advice.Argument(0) ByteBuffer[] appData,
        @Advice.Argument(1) int offset,
        @Advice.Argument(2) int length) {
      return PixieCapture.enginePositions(appData, offset, length);
    }

    @Advice.OnMethodExit
    public static void exit(
        @Advice.Argument(0) ByteBuffer[] appData,
        @Advice.Argument(1) int offset,
        @Advice.Argument(2) int length,
        @Advice.Enter int[] startPositions) {
      PixieCapture.onEngineWrap(appData, offset, length, startPositions);
    }
  }

  /** Advice for {@code SSLEngineResult unwrap(ByteBuffer net, ByteBuffer[] appData, int off, int len)}. */
  public static final class Unwrap {
    private Unwrap() {}

    @Advice.OnMethodEnter
    public static int[] enter(
        @Advice.Argument(1) ByteBuffer[] appData,
        @Advice.Argument(2) int offset,
        @Advice.Argument(3) int length) {
      return PixieCapture.enginePositions(appData, offset, length);
    }

    @Advice.OnMethodExit
    public static void exit(
        @Advice.Argument(1) ByteBuffer[] appData,
        @Advice.Argument(2) int offset,
        @Advice.Argument(3) int length,
        @Advice.Enter int[] startPositions) {
      PixieCapture.onEngineUnwrap(appData, offset, length, startPositions);
    }
  }
}
