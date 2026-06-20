#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the demo collector: the eBPF object + the userspace loader/decoder.
set -euo pipefail
cd "$(dirname "$0")"

CLANG="${CLANG:-clang}"
# Multiarch include path provides <asm/types.h> on header-less environments.
ARCH_INC="${ARCH_INC:-/usr/include/x86_64-linux-gnu}"

echo "compiling BPF object..."
$CLANG -O2 -g -target bpf -D__TARGET_ARCH_x86 -I"$ARCH_INC" \
  -c jsse_collector.bpf.c -o jsse_collector.bpf.o

echo "compiling userspace collector..."
# -lz (gzip) and -lzstd (zstd) are used by the Kafka record-batch decompressor.
$CLANG -O2 collector.c -lbpf -lelf -lz -lzstd -o collector

echo "built: $(pwd)/collector  +  jsse_collector.bpf.o"
