#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end local smoke test for the JSSE collector — no JVM, no Kafka, no
# cluster. Builds libpixie_jsse.so + the eBPF collector, then a synthetic caller
# that pushes a real length-prefixed Kafka Produce frame through
# pixie_jsse_plaintext(); the collector's uprobe must capture and decode it.
#
# Requires: root (eBPF uprobe load/attach) + clang/cc + the codec/bpf libs.
set -euo pipefail
cd "$(dirname "$0")"
ROOT=".."; JT="../.."
CC="${CC:-clang}"

if [ "$(id -u)" != "0" ]; then echo "must run as root (eBPF)"; exit 2; fi

( cd "$JT/native"  && CC="$CC" bash build.sh >/dev/null )
( cd "$ROOT"       && CC="$CC" bash build.sh >/dev/null )
LIB="$(readlink -f "$JT/native/libpixie_jsse.so")"
"$CC" -O2 e2e_driver.c "$LIB" -Wl,-rpath,"$(dirname "$LIB")" -o /tmp/e2e_driver

( cd "$ROOT" && ./collector "$LIB" 6 ) >/tmp/e2e_out.log 2>&1 &
cpid=$!; sleep 2
LD_LIBRARY_PATH="$(dirname "$LIB")" /tmp/e2e_driver
wait "$cpid" 2>/dev/null || true

if grep -q 'cmd=Produce' /tmp/e2e_out.log && grep -q 'value="payload-over-tls"' /tmp/e2e_out.log; then
  echo "E2E PASS — collector decoded the Produce record over the uprobe"
  grep -m1 'topic=orders' /tmp/e2e_out.log
else
  echo "E2E FAIL — collector output:"; cat /tmp/e2e_out.log; exit 1
fi
