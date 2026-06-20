#!/bin/bash
# Copyright 2018- The Pixie Authors.
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end demo: zero-broker-modification capture of Kafka-over-TLS plaintext
# via the pixie-jsse agent + an eBPF uprobe collector.
#
# Provisions a self-signed TLS keystore, starts a single-node KRaft broker with an
# SSL client listener (inter-broker stays plaintext, the realistic production shape)
# and the agent injected via KAFKA_OPTS, runs the collector, drives a TLS
# producer/consumer, and prints the decoded rows + a tcpdump-vs-eBPF contrast.
#
# Requirements: Java 21+, clang, libbpf-dev, a Kafka 3.x distribution, root (eBPF),
#               a kernel with CONFIG_UPROBES (mount debugfs if needed).
#
# Usage:
#   KAFKA_HOME=/path/to/kafka_2.13-3.9.0 sudo -E ./run_demo.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
JT="$(cd "$HERE/.." && pwd)"                 # the java_tls directory
: "${KAFKA_HOME:?set KAFKA_HOME to a Kafka 3.x distribution directory}"
# Default JDK path is Debian/Ubuntu arch-suffixed (amd64 / arm64).
: "${JAVA_HOME:=/usr/lib/jvm/java-21-openjdk-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
WORK="${WORK:-/tmp/pixie-jsse-demo}"
PASS=pixiepass
AGENT="$JT/agent/target/pixie-jsse-agent.jar"
LIB="$JT/native/libpixie_jsse.so"
COLLECTOR="$JT/collector/collector"

command -v "$KAFKA_HOME/bin/kafka-server-start.sh" >/dev/null || { echo "bad KAFKA_HOME"; exit 1; }
for f in "$AGENT" "$LIB" "$COLLECTOR"; do
  [ -e "$f" ] || { echo "missing build artifact: $f  (run native/build.sh, agent 'mvn package', collector/build.sh)"; exit 1; }
done
# eBPF needs debugfs/tracefs available for uprobe attach on some setups.
mount | grep -q '/sys/kernel/debug ' || mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

mkdir -p "$WORK/certs" "$WORK/data"
cd "$WORK"

echo "== [1/6] generate self-signed broker keystore + client truststore =="
if [ ! -f certs/server.keystore.jks ]; then
  keytool -genkeypair -keystore certs/server.keystore.jks -alias broker -keyalg RSA -keysize 2048 \
    -validity 3650 -storepass $PASS -keypass $PASS -dname "CN=localhost,O=Pixie,C=US" \
    -ext SAN=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1
  keytool -exportcert -keystore certs/server.keystore.jks -alias broker -file certs/broker.cer -rfc \
    -storepass $PASS >/dev/null 2>&1
  keytool -importcert -keystore certs/client.truststore.jks -alias broker -file certs/broker.cer \
    -storepass $PASS -noprompt >/dev/null 2>&1
fi

cat > server.properties <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9093
listeners=SSL://localhost:9092,CONTROLLER://localhost:9093,INTERNAL://localhost:9094
advertised.listeners=SSL://localhost:9092,INTERNAL://localhost:9094
inter.broker.listener.name=INTERNAL
controller.listener.names=CONTROLLER
listener.security.protocol.map=SSL:SSL,CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT
log.dirs=$WORK/data
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
ssl.keystore.location=$WORK/certs/server.keystore.jks
ssl.keystore.password=$PASS
ssl.key.password=$PASS
ssl.truststore.location=$WORK/certs/server.keystore.jks
ssl.truststore.password=$PASS
ssl.client.auth=none
ssl.endpoint.identification.algorithm=
EOF
cat > client-ssl.properties <<EOF
security.protocol=SSL
ssl.truststore.location=$WORK/certs/client.truststore.jks
ssl.truststore.password=$PASS
ssl.endpoint.identification.algorithm=
EOF

echo "== [2/6] format KRaft storage =="
if [ ! -f data/meta.properties ]; then
  UUID=$("$KAFKA_HOME/bin/kafka-storage.sh" random-uuid)
  "$KAFKA_HOME/bin/kafka-storage.sh" format -t "$UUID" -c server.properties >/dev/null
fi

echo "== [3/6] start broker with pixie-jsse agent (broker code UNMODIFIED) =="
export KAFKA_HEAP_OPTS="-Xmx512M -Xms256M"
export KAFKA_OPTS="-javaagent:$AGENT=$LIB"
"$KAFKA_HOME/bin/kafka-server-start.sh" server.properties > broker.log 2>&1 &
BROKER_PID=$!
trap 'kill $BROKER_PID 2>/dev/null' EXIT
for i in $(seq 1 60); do grep -q "Kafka Server started" broker.log && break; sleep 1; done
grep -q "Kafka Server started" broker.log || { echo "broker failed:"; tail -20 broker.log; exit 1; }
grep "pixie-jsse" broker.log || true

echo "== [4/6] start eBPF collector on libpixie_jsse.so =="
# The collector loads jsse_collector.bpf.o by a path relative to its CWD, so run it
# from its own directory (as selftest.sh does); collector.out stays in $WORK.
( cd "$JT/collector" && ./collector "$LIB" 25 ) > collector.out 2>&1 &
sleep 4

echo "== [5/6] produce + consume over TLS =="
SECRET="TOPSECRET_TRANSFER_50000_TO_ACME"
"$KAFKA_HOME/bin/kafka-topics.sh" --bootstrap-server localhost:9092 --command-config client-ssl.properties \
  --create --if-not-exists --topic payments --partitions 1 --replication-factor 1 >/dev/null 2>&1 || true
tcpdump -i lo -A -s0 'tcp port 9092' -w wire.pcap >/dev/null 2>&1 &
TPID=$!; sleep 1
printf "paykey:%s\n" "$SECRET" | "$KAFKA_HOME/bin/kafka-console-producer.sh" \
  --bootstrap-server localhost:9092 --topic payments --property parse.key=true --property key.separator=: \
  --producer.config client-ssl.properties >/dev/null 2>&1
timeout 10 "$KAFKA_HOME/bin/kafka-console-consumer.sh" --bootstrap-server localhost:9092 --topic payments \
  --from-beginning --max-messages 1 --consumer.config client-ssl.properties >/dev/null 2>&1 || true
sleep 2; kill $TPID 2>/dev/null || true
wait %3 2>/dev/null || true   # let the collector's timer elapse

echo
echo "================ DECODED KAFKA-OVER-TLS ROWS (via eBPF) ================"
grep -E "dir=REQ|dir=RESP" collector.out | head -24
echo
echo "================ CONTRAST: same secret, two observers ================"
echo "Secret produced over TLS: $SECRET"
strings wire.pcap | grep -q "$SECRET" \
  && echo "[wire/tcpdump] VISIBLE (leak!)" || echo "[wire/tcpdump]  NOT visible -> ENCRYPTED on the wire"
grep -q "$SECRET" collector.out \
  && echo "[pixie eBPF ]  VISIBLE -> plaintext recovered via eBPF" || echo "[pixie eBPF ]  not captured"
echo "--- carrying row ---"; grep "$SECRET" collector.out | head -1
