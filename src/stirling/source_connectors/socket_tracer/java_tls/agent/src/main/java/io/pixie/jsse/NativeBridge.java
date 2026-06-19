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
 * Thin JNI surface to the native bridge library (libpixie_jsse.so).
 *
 * <p>{@link #emit} forwards a chunk of TLS plaintext to the eBPF uprobe target
 * {@code pixie_jsse_plaintext}. The {@code data} buffer MUST be a direct
 * (off-heap) {@link ByteBuffer}; the native side resolves its address via
 * {@code GetDirectBufferAddress} and Pixie's eBPF program reads {@code len}
 * bytes from it with {@code bpf_probe_read_user}.
 */
public final class NativeBridge {
  private static volatile boolean loaded = false;

  private NativeBridge() {}

  /** Loads the native library. {@code libPath} may be an explicit path to the
   *  .so, or null/empty to fall back to System.loadLibrary("pixie_jsse"). */
  public static synchronized void init(String libPath) {
    if (loaded) {
      return;
    }
    if (libPath != null && !libPath.isEmpty()) {
      System.load(libPath);
    } else {
      System.loadLibrary("pixie_jsse");
    }
    loaded = true;
  }

  public static boolean isLoaded() {
    return loaded;
  }

  /**
   * Emit one plaintext record to eBPF.
   *
   * @param fd        OS file descriptor of the underlying socket.
   * @param direction 0 = ingress (decrypted bytes), 1 = egress (pre-encryption).
   * @param data      direct ByteBuffer whose first {@code len} bytes are plaintext.
   * @param len       number of valid plaintext bytes.
   */
  public static native void emit(long fd, int direction, ByteBuffer data, int len);

  /** Returns true once the native library is loaded and callable. */
  public static native boolean isReady();
}
