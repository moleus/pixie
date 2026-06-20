#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the demo collector: the eBPF object + the userspace loader/decoder.
set -euo pipefail
cd "$(dirname "$0")"

CLANG="${CLANG:-clang}"
# The collector runs on the node it traces, so build for the host architecture
# (the eBPF uprobe reads that arch's pt_regs argument registers).
case "$(uname -m)" in
  x86_64|amd64)  TARGET_ARCH=x86;   TRIPLE=x86_64-linux-gnu ;;
  aarch64|arm64) TARGET_ARCH=arm64; TRIPLE=aarch64-linux-gnu ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
# Multiarch include path provides <asm/types.h> on header-less environments.
ARCH_INC="${ARCH_INC:-/usr/include/$TRIPLE}"

echo "compiling BPF object (arch=$TARGET_ARCH)..."
$CLANG -O2 -g -target bpf "-D__TARGET_ARCH_${TARGET_ARCH}" -I"$ARCH_INC" \
  -c jsse_collector.bpf.c -o jsse_collector.bpf.o

echo "compiling userspace collector..."
# Record-batch decompressors: -lz (gzip), -lzstd (zstd), and lz4 frame.
# liblz4 often ships without a -dev symlink, so link the runtime .so by path.
LZ4LIB="$(ldconfig -p | awk -F'=> ' '/liblz4.so.1/{print $2; exit}')"
LZ4LIB="${LZ4LIB:-/lib/$TRIPLE/liblz4.so.1}"
$CLANG -O2 collector.c -lbpf -lelf -lz -lzstd -lsnappy "$LZ4LIB" -o collector

echo "built: $(pwd)/collector  +  jsse_collector.bpf.o"
