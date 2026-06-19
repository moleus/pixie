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

/*
 * pixie_jsse_bridge.c
 * -------------------
 * Minimal JNI glue between the Java agent and the eBPF uprobe target.
 *
 * The Java agent intercepts TLS plaintext inside the JVM (at the JSSE /
 * SslTransportLayer boundary), copies the bytes into a per-thread *direct*
 * (off-heap) ByteBuffer, and calls NativeBridge.emit(...). We resolve the raw
 * address of that off-heap buffer with GetDirectBufferAddress and forward it to
 * pixie_jsse_plaintext(), which is the symbol Pixie's eBPF program attaches to.
 *
 * Using a direct buffer is deliberate: its backing memory is a stable,
 * resident, native allocation, so the eBPF side's bpf_probe_read_user() can
 * read it reliably (a non-resident page would EFAULT).
 */

#include <jni.h>
#include <stdint.h>

/* Defined in pixie_jsse_trampoline.c (separate TU => guaranteed ABI). */
extern void pixie_jsse_plaintext(uint64_t fd, uint32_t direction, const char* buf, uint32_t len);

/*
 * Class:     io_pixie_jsse_NativeBridge
 * Method:    emit
 * Signature: (JILjava/nio/ByteBuffer;I)V
 */
JNIEXPORT void JNICALL Java_io_pixie_jsse_NativeBridge_emit(JNIEnv* env, jclass cls, jlong fd,
                                                            jint direction, jobject direct_buf,
                                                            jint len) {
  (void)cls;
  if (direct_buf == NULL || len <= 0) {
    return;
  }
  void* p = (*env)->GetDirectBufferAddress(env, direct_buf);
  if (p == NULL) {
    return;
  }
  pixie_jsse_plaintext((uint64_t)fd, (uint32_t)direction, (const char*)p, (uint32_t)len);
}

/* Lightweight liveness check the agent can call to verify the library loaded
 * and the symbol is resolvable before it starts instrumenting. */
JNIEXPORT jboolean JNICALL Java_io_pixie_jsse_NativeBridge_isReady(JNIEnv* env, jclass cls) {
  (void)env;
  (void)cls;
  return JNI_TRUE;
}
