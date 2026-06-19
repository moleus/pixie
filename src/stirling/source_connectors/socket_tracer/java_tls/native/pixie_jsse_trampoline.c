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
 * pixie_jsse_trampoline.c
 * -----------------------
 * This file contains the single, stable uprobe target that bridges JVM/JSSE
 * plaintext to Pixie's eBPF data path.
 *
 * Design notes (these constraints are LOAD-BEARING):
 *
 *  1. The trampoline lives in its OWN translation unit, separate from the JNI
 *     glue that calls it. A same-TU call at -O2 lets the compiler do
 *     interprocedural argument elimination / constant propagation, which can
 *     leave the argument registers undefined at the function entry where the
 *     uprobe fires. By keeping this in a separate object file (and never
 *     enabling LTO), the call from the JNI glue is forced to honor the SysV
 *     AMD64 ABI: arg0->rdi, arg1->rsi, arg2->rdx, arg3->rcx.
 *
 *  2. The function is exported with default visibility and marked noinline so
 *     a stable, named symbol ("pixie_jsse_plaintext") always exists for the
 *     uprobe to attach to.
 *
 *  3. The inline asm consumes all four parameters ("r" inputs) so the compiler
 *     cannot treat them as dead and drop them before the probe point.
 *
 *  4. The body does NO work. All capture logic lives in the eBPF program that
 *     attaches to this symbol. This keeps the injected native surface area
 *     minimal (it contains no Pixie/BPF logic and ships no policy), and means
 *     the broker process pays only the cost of an empty function call.
 *
 * eBPF reads the plaintext from arg2 (buf) for arg3 (len) bytes and tags the
 * resulting data event with the file descriptor in arg0 and the direction in
 * arg1 (0 = ingress/read/decrypted, 1 = egress/write/to-be-encrypted).
 */

#include <stddef.h>
#include <stdint.h>

/*
 * void pixie_jsse_plaintext(fd, direction, buf, len)
 *
 *   fd        : OS file descriptor of the underlying socket (matches the
 *               {tgid, fd} key used by Pixie's syscall kprobes).
 *   direction : 0 = ingress (post-decrypt), 1 = egress (pre-encrypt).
 *   buf       : pointer to the plaintext bytes (off-heap / direct buffer).
 *   len       : number of valid plaintext bytes at buf.
 */
__attribute__((visibility("default"), noinline)) void pixie_jsse_plaintext(uint64_t fd,
                                                                           uint32_t direction,
                                                                           const char* buf,
                                                                           uint32_t len) {
  /* Force all four args to be materialized in their ABI registers at the
   * probe point, and prevent the call from being optimized away. */
  __asm__ __volatile__("" : : "r"(fd), "r"(direction), "r"(buf), "r"(len) : "memory");
}
