#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Self-contained tests for kafka_parser.h — no live Kafka, no cluster.
#   test_kafka_parser : round-trips every codec (gzip/zstd/lz4/snappy, incl.
#                       multi-block) through kafka_decompress and parses a full
#                       Produce v9 frame down to records.
#   fuzz_kafka_parser : feeds truncated/byte-flipped/random frames to every
#                       entry point under ASan+UBSan to catch OOB / UB.
# Needs: clang or gcc, plus -lz -lzstd -lsnappy and liblz4 (runtime .so).
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-cc}"
LZ4LIB="$(ldconfig -p | awk -F'=> ' '/liblz4.so.1/{print $2; exit}')"
LZ4LIB="${LZ4LIB:-/lib/$(uname -m)-linux-gnu/liblz4.so.1}"
LIBS="-lz -lzstd -lsnappy $LZ4LIB"

echo "[1/2] functional round-trip + parse"
$CC -O2 -I.. test_kafka_parser.c $LIBS -o /tmp/test_kafka_parser
/tmp/test_kafka_parser

echo "[2/2] fuzz under sanitizers (gcc has the runtime preinstalled more often)"
SAN_CC="${SAN_CC:-gcc}"
if $SAN_CC -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -I.. \
      fuzz_kafka_parser.c $LIBS -o /tmp/fuzz_kafka_parser 2>/dev/null; then
  /tmp/fuzz_kafka_parser "${1:-20000}"
else
  echo "  (sanitizer runtime unavailable; building plain and running a smoke pass)"
  $SAN_CC -O1 -I.. fuzz_kafka_parser.c $LIBS -o /tmp/fuzz_kafka_parser
  /tmp/fuzz_kafka_parser "${1:-20000}"
fi
echo "ALL TESTS PASSED"
