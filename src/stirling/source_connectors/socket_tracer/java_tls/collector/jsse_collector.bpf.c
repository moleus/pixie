// Copyright 2018- The Pixie Authors.
// SPDX-License-Identifier: GPL-2.0
//
// Standalone eBPF program for the pixie-jsse demo collector ("mini-PEM").
//
// This mirrors what bcc_bpf/jsse_trace.c does inside a real Pixie PEM, but is
// self-contained (no Pixie BPF headers / no kernel BTF required) so it can run
// anywhere. It attaches a uprobe to pixie_jsse_plaintext() in libpixie_jsse.so
// and ships each plaintext chunk to user space via a ring buffer.
//
// Probed signature (SysV AMD64 ABI):
//   void pixie_jsse_plaintext(uint64_t fd, uint32_t direction,
//                             const char* buf, uint32_t len);

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// We read the userspace argument registers directly out of pt_regs. Defining
// the x86-64 layout ourselves avoids any dependency on vmlinux BTF or kernel
// headers (which are absent on minimal/over-the-web environments).
struct pt_regs_x64 {
  unsigned long r15, r14, r13, r12, bp, bx;
  unsigned long r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax;
  unsigned long ip, cs, flags, sp, ss;
};

#define MAX_DATA 4096

struct jsse_event {
  unsigned long fd;
  unsigned int direction;  // 0 = egress (pre-encrypt), 1 = ingress (post-decrypt)
  unsigned int len;        // original plaintext length
  unsigned int cap;        // bytes actually captured (<= MAX_DATA)
  unsigned int tgid;
  unsigned char data[MAX_DATA];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);  // 16 MiB
} events SEC(".maps");

SEC("uprobe/pixie_jsse_plaintext")
int probe_entry_jsse_plaintext(struct pt_regs_x64 *ctx) {
  unsigned long fd = ctx->di;             // arg0
  unsigned int direction = (unsigned int)ctx->si;  // arg1
  const char *buf = (const char *)ctx->dx;         // arg2
  unsigned int len = (unsigned int)ctx->cx;        // arg3

  if ((long)fd <= 2 || buf == 0 || len == 0) {
    return 0;
  }

  struct jsse_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  unsigned int cap = len;
  // Mask to a provable [0, MAX_DATA-1] range for the verifier.
  cap &= (MAX_DATA - 1);

  e->fd = fd;
  e->direction = direction;
  e->len = len;
  e->cap = cap;
  e->tgid = bpf_get_current_pid_tgid() >> 32;

  if (bpf_probe_read_user(e->data, cap, buf) != 0) {
    bpf_ringbuf_discard(e, 0);
    return 0;
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}
