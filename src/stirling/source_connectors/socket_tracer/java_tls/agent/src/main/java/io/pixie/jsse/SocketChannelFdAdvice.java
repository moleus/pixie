/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 */
package io.pixie.jsse;

import net.bytebuddy.asm.Advice;

/**
 * Advice on {@code sun.nio.ch.SocketChannelImpl.read/write(ByteBuffer)}: record the
 * channel's OS fd in a thread-local so the generic {@link SSLEngineAdvice} (which
 * has no socket reference) can tag its plaintext with the right connection. The
 * engine op and the socket op run back-to-back on the same NIO thread.
 */
public final class SocketChannelFdAdvice {
  private SocketChannelFdAdvice() {}

  @Advice.OnMethodEnter
  public static void enter(@Advice.This Object channel) {
    int fd = FdExtractor.fdOf(channel);
    if (fd >= 0) {
      EngineContext.setFd(fd);
    }
  }
}
