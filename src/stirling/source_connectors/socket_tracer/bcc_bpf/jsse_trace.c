/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2018- The Pixie Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

// LINT_C_FILE: Do not remove this line. It ensures cpplint treats this as a C file.

// JVM / JSSE TLS tracing.
//
// The JVM does TLS entirely in Java (sun.security.ssl.SSLEngineImpl), so there
// are no stable native libssl symbols to uprobe (AES is a JIT'd HotSpot
// intrinsic). Instead, a thin, externally-injected Java agent
// (pixie-jsse-agent) intercepts plaintext at the JSSE boundary and calls the
// native symbol `pixie_jsse_plaintext(fd, direction, buf, len)` exported by
// libpixie_jsse.so. We uprobe that symbol here.
//
// This is the JVM analogue of how Pixie already traces Go (crypto/tls) and
// Node (TLSWrap): a per-runtime probe that lands plaintext into the *same*
// process_data() pipeline used by every other TLS source. Because the agent
// hands us the real OS fd (obtained from the SocketChannel), the plaintext is
// keyed by the exact {tgid, fd} that the syscall kprobes use, so it merges with
// the connection 4-tuple with no timing heuristics.
//
// Signature being probed (SysV AMD64 ABI):
//   void pixie_jsse_plaintext(uint64_t fd, uint32_t direction,
//                             const char* buf, uint32_t len);
//     direction: kEgress(0) = pre-encryption, kIngress(1) = post-decryption.

#include "src/stirling/source_connectors/socket_tracer/bcc_bpf/macros.h"
#include "src/stirling/source_connectors/socket_tracer/bcc_bpf_intf/common.h"

int probe_entry_jsse_plaintext(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;

  int32_t fd = (int32_t)PT_REGS_PARM1(ctx);
  uint32_t direction = (uint32_t)PT_REGS_PARM2(ctx);
  const char* buf = (const char*)PT_REGS_PARM3(ctx);
  // Keep bytes_count as a 32-bit signed int, mirroring process_openssl_data():
  // a 64-bit type here can alias small negative values into huge positives and
  // confuse process_data()'s position bookkeeping.
  int bytes_count = (int)PT_REGS_PARM4(ctx);

  if (fd <= 2 || bytes_count <= 0 || buf == NULL) {
    return 0;
  }

  enum traffic_direction_t dir = (direction == kEgress) ? kEgress : kIngress;

  struct data_args_t args = {};
  args.source_fn = (dir == kEgress) ? kSSLWrite : kSSLRead;
  args.fd = fd;
  args.buf = buf;

  // Mark the connection as SSL right away so the encrypted bytes seen by the
  // syscall probes are not double-counted, and tag the source as JVM/JSSE.
  set_conn_as_ssl(tgid, fd, kJavaJSSESource);

  process_data(/* vecs */ false, ctx, id, dir, &args, bytes_count, /* ssl */ true);
  return 0;
}
