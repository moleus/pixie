#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Builds libpixie_jsse.so — the JNI bridge + the stable eBPF uprobe target.
#
# IMPORTANT: the trampoline and the JNI glue are compiled to SEPARATE object
# files and linked WITHOUT LTO. This guarantees the call into
# pixie_jsse_plaintext() is a real cross-TU call that honors the SysV AMD64 ABI,
# so the argument registers are well-defined at the uprobe attach point.
set -euo pipefail
cd "$(dirname "$0")"

: "${JAVA_HOME:=/usr/lib/jvm/java-21-openjdk-amd64}"
CC="${CC:-clang}"
OUT="${OUT:-libpixie_jsse.so}"

echo "JAVA_HOME=$JAVA_HOME  CC=$CC"

# Separate translation units (do NOT enable -flto).
$CC -O2 -fPIC -fvisibility=hidden -c pixie_jsse_trampoline.c -o pixie_jsse_trampoline.o
$CC -O2 -fPIC -c \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
    pixie_jsse_bridge.c -o pixie_jsse_bridge.o

$CC -shared -o "$OUT" pixie_jsse_trampoline.o pixie_jsse_bridge.o

echo "built $OUT"
echo "--- exported symbols ---"
nm -D --defined-only "$OUT" | grep -E "pixie_jsse_plaintext|Java_io_pixie" || true
