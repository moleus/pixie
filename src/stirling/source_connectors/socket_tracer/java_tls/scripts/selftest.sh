#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Regression self-test for the pixie-jsse collector's Kafka decoder.
#
# Produces known key/value records over TLS with each compression codec and
# asserts the eBPF collector recovered the plaintext values. Exits non-zero on
# any miss. Assumes a broker is already running with the agent injected (e.g.
# started by run_demo.sh) and reachable on localhost:9092 (SSL).
#
# Env:
#   KAFKA_HOME   path to a Kafka 3.x distribution (required)
#   JT           path to the java_tls dir (default: derived from this script)
#   CLIENT_CFG   client SSL properties (default: $WORK/client-ssl.properties)
#   WORK         working dir holding client-ssl.properties (default: /tmp/pixie-jsse-demo)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
JT="${JT:-$(cd "$HERE/.." && pwd)}"
WORK="${WORK:-/tmp/pixie-jsse-demo}"
CLIENT_CFG="${CLIENT_CFG:-$WORK/client-ssl.properties}"
: "${KAFKA_HOME:?set KAFKA_HOME}"
KBIN="$KAFKA_HOME/bin"
LIB="$JT/native/libpixie_jsse.so"
COL="$JT/collector"
OUT="$(mktemp)"
TOPIC="selftest-$$"

[ -f "$CLIENT_CFG" ] || { echo "missing client config: $CLIENT_CFG (run run_demo.sh first)"; exit 2; }

"$KBIN/kafka-topics.sh" --bootstrap-server localhost:9092 --command-config "$CLIENT_CFG" \
  --create --if-not-exists --topic "$TOPIC" --partitions 1 --replication-factor 1 >/dev/null 2>&1

( cd "$COL" && ./collector "$LIB" 22 > "$OUT" 2>&1 ) &
CPID=$!
sleep 5

produce() { # codec, payload-lines
  printf "%b" "$2" | "$KBIN/kafka-console-producer.sh" --bootstrap-server localhost:9092 --topic "$TOPIC" \
    --property parse.key=true --property key.separator=: \
    --producer-property "compression.type=$1" --producer-property batch.size=16384 \
    --producer-property linger.ms=80 --producer.config "$CLIENT_CFG" >/dev/null 2>&1
}
produce none 'st-none:SELFTEST_VALUE_NONE\n'
produce gzip 'st-gzip-1:SELFTEST_VALUE_GZIP_A\nst-gzip-2:SELFTEST_VALUE_GZIP_B\n'
produce zstd 'st-zstd-1:SELFTEST_VALUE_ZSTD_A\nst-zstd-2:SELFTEST_VALUE_ZSTD_B\n'
produce lz4  'st-lz4-1:SELFTEST_VALUE_LZ4_A\nst-lz4-2:SELFTEST_VALUE_LZ4_B\n'
wait $CPID

EXPECT=(SELFTEST_VALUE_NONE SELFTEST_VALUE_GZIP_A SELFTEST_VALUE_GZIP_B \
        SELFTEST_VALUE_ZSTD_A SELFTEST_VALUE_ZSTD_B SELFTEST_VALUE_LZ4_A SELFTEST_VALUE_LZ4_B)
fail=0
echo "---- self-test results ----"
for e in "${EXPECT[@]}"; do
  if grep -q "value=\"$e\"" "$OUT"; then echo "PASS  $e"; else echo "FAIL  $e (not decoded)"; fail=1; fi
done
rm -f "$OUT"
[ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit $fail
