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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Extracts the underlying OS file descriptor from a {@code java.nio} SocketChannel.
 *
 * <p>This is the keystone of correlation: Pixie's syscall kprobes key every
 * connection by {@code {tgid, fd}}. By recovering the very same fd here and
 * tagging the plaintext event with it, the decrypted bytes line up with the
 * connection 4-tuple that the kernel-side tracing already established — no
 * timing heuristics required.
 *
 * <p>It reaches into {@code sun.nio.ch.SocketChannelImpl.fd} (a
 * {@link FileDescriptor}) and then {@code FileDescriptor.fd} (the int). Both are
 * encapsulated in {@code java.base}; the agent opens those packages reflectively
 * at premain time via {@code Instrumentation.redefineModule}, so no
 * {@code --add-opens} JVM flags are needed.
 */
public final class FdExtractor {
  // channelClass.getDeclaredField("fd") -> FileDescriptor
  private static volatile Field channelFdField;
  // FileDescriptor.fd -> int
  private static volatile Field fdValueField;

  // Cache fd per channel instance to avoid repeated reflection on the hot path.
  private static final Map<Object, Integer> CACHE =
      Collections.synchronizedMap(new WeakHashMap<>());

  private FdExtractor() {}

  /** Returns the OS fd for the channel, or -1 if it cannot be determined. */
  public static int fdOf(Object channel) {
    if (channel == null) {
      return -1;
    }
    Integer cached = CACHE.get(channel);
    if (cached != null) {
      return cached;
    }
    int fd = extract(channel);
    if (fd >= 0) {
      CACHE.put(channel, fd);
    }
    return fd;
  }

  private static int extract(Object channel) {
    try {
      Field cf = channelFdField;
      if (cf == null || !cf.getDeclaringClass().isInstance(channel)) {
        cf = findField(channel.getClass(), "fd");
        if (cf == null) {
          return -1;
        }
        cf.setAccessible(true);
        channelFdField = cf;
      }
      Object fdObj = cf.get(channel);
      if (!(fdObj instanceof FileDescriptor)) {
        return -1;
      }
      Field vf = fdValueField;
      if (vf == null) {
        vf = FileDescriptor.class.getDeclaredField("fd");
        vf.setAccessible(true);
        fdValueField = vf;
      }
      return vf.getInt(fdObj);
    } catch (Throwable t) {
      return -1;
    }
  }

  // Walk the class hierarchy looking for a declared field (SocketChannelImpl
  // declares "fd", but be defensive about subclasses/JDK variations).
  private static Field findField(Class<?> cls, String name) {
    for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
      try {
        return c.getDeclaredField(name);
      } catch (NoSuchFieldException ignored) {
        // keep walking
      }
    }
    return null;
  }
}
