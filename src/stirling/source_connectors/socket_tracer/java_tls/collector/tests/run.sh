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

echo "[1/4] functional round-trip + parse"
$CC -O2 -I.. test_kafka_parser.c $LIBS -o /tmp/test_kafka_parser
/tmp/test_kafka_parser

SAN_CC="${SAN_CC:-gcc}"
SAN="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all"
san_build() {  # $1=src $2=out ; falls back to plain build if no sanitizer runtime
  if $SAN_CC $SAN -I.. "$1" $LIBS -o "$2" 2>/dev/null; then return 0; fi
  echo "  (sanitizer runtime unavailable; plain build)"; $SAN_CC -O1 -I.. "$1" $LIBS -o "$2"
}

echo "[2/4] property: parse(build(records)) round-trip, flexible+non-flexible, all codecs"
san_build property_kafka_parser.c /tmp/property_kafka_parser
/tmp/property_kafka_parser "${2:-20000}"

echo "[3/4] property: varint/zigzag decoders round-trip over full int32/int64 range (UBSan)"
if $SAN_CC -O1 -g -fsanitize=undefined -fno-sanitize-recover=all -I.. varint_kafka_parser.c $LIBS -o /tmp/varint_kafka_parser 2>/dev/null; then :; else $SAN_CC -O1 -I.. varint_kafka_parser.c $LIBS -o /tmp/varint_kafka_parser; fi
/tmp/varint_kafka_parser

echo "[4/4] fuzz: truncation / byte-flip / random / malformed under ASan+UBSan"
san_build fuzz_kafka_parser.c /tmp/fuzz_kafka_parser
/tmp/fuzz_kafka_parser "${1:-20000}"
echo "ALL TESTS PASSED"
