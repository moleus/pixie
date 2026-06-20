/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
package io.pixie.jsse;

/**
 * Per-thread context that bridges the two halves of the GENERIC (SSLEngine) hook:
 *
 *  - {@link #currentFd}: the OS fd of the last SocketChannel this thread read/wrote.
 *    An {@code SSLEngine} has no socket reference, but the thread that calls
 *    {@code engine.wrap()/unwrap()} is the same one that then (or just) called
 *    {@code channel.write()/read()} — the typical NIO event-loop pattern. So the
 *    SocketChannel advice records the fd here and the SSLEngine advice reads it.
 *
 *  - {@link #inTransport}: set while we're inside a known transport wrapper
 *    (Kafka's SslTransportLayer.read/write), which captures plaintext WITH the
 *    real fd directly. The generic SSLEngine advice skips when this is set, so
 *    Kafka traffic isn't double-captured.
 */
// Must be public: advice classes are inlined into classes in OTHER packages
// (org.apache.kafka..., sun.security.ssl..., sun.nio.ch...), and those inlined
// references can only reach public members. (A package-private class here caused
// IllegalAccessError from the woven SslTransportLayer, breaking every read/write.)
public final class EngineContext {
  public static final ThreadLocal<Integer> currentFd = new ThreadLocal<>();
  public static final ThreadLocal<Boolean> inTransport =
      ThreadLocal.withInitial(() -> Boolean.FALSE);

  private EngineContext() {}

  public static void setFd(int fd) {
    if (fd >= 0) {
      currentFd.set(fd);
    }
  }

  public static int getFd() {
    Integer v = currentFd.get();
    return v == null ? -1 : v;
  }
}
