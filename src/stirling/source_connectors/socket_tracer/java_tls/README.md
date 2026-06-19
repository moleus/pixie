# Zero-instrumentation observability for Kafka-over-TLS (JVM/JSSE) via Pixie + eBPF

Pixie traces TLS by attaching uprobes to `SSL_read`/`SSL_write` in OpenSSL/BoringSSL
(and equivalent functions in Go's `crypto/tls` and Node's `TLSWrap`). That covers
most of the ecosystem — but **not the JVM**. Kafka (and most JVM services) terminate
TLS *inside the JVM* using the **Java Secure Socket Extension (JSSE)**:
`javax.net.ssl.SSLEngine` / `sun.security.ssl.SSLEngineImpl`. AES is a JIT-compiled
HotSpot intrinsic, so there is **no stable native libssl symbol to uprobe**. The
result: Pixie sees Kafka TLS connections as opaque ciphertext.

> Netty-based apps are the exception — they link `netty-tcnative` (a shaded
> OpenSSL), which Pixie already traces via the existing OpenSSL uprobes
> (`kLibNettyTcnativeSource`). **Kafka does not use Netty** — it uses raw
> `java.nio` + `SSLEngine` (`org.apache.kafka.common.network.SslTransportLayer`).

This directory delivers the missing JVM/JSSE path: **decrypted Kafka messages land
in Pixie's existing `kafka_events` table, with no modification to the Kafka broker.**

A live run against Kafka 3.9.0 over TLS (full output in
[`docs/sample_output.txt`](docs/sample_output.txt)):

```
Secret produced over TLS: TOPSECRET_TRANSFER_50000_TO_ACME

[1] tcpdump on the wire (:9092):  NOT visible -> ENCRYPTED on the wire
[2] Pixie eBPF JSSE collector:    VISIBLE -> plaintext recovered via eBPF

--- the eBPF row that carries it ---
fd=239  encrypted=TRUE  dir=REQ  cmd=Produce  corr=5  client=console-producer
        req=['payments' 'paykey@TOPSECRET_TRANSFER_50000_TO_ACME']
```

---

## How it works

The JVM does TLS in Java, so the only robust way to get plaintext via eBPF is to
have *something inside the JVM* hand the plaintext to a stable native symbol that
eBPF can uprobe. That "something" is a tiny, externally-injected Java agent — the
same mechanism every APM (Datadog, OpenTelemetry, New Relic) uses. **The broker's
code, JARs, and configuration are untouched**; the agent is attached through the
JVM's standard `-javaagent` entry point (set via `KAFKA_OPTS`, exactly where
operators already put JMX/APM flags).

```
   ┌─────────────────────────── Kafka broker JVM (unmodified) ───────────────────────────┐
   │                                                                                       │
   │  org.apache.kafka.common.network.SslTransportLayer                                    │
   │     read(dst)   ── decrypted plaintext (post sslEngine.unwrap) ─┐                     │
   │     write(src)  ── plaintext pre-encryption (pre sslEngine.wrap)┤                     │
   │                                                                 ▼                     │
   │   ┌─ pixie-jsse agent (ByteBuddy advice, injected via -javaagent) ──────────────┐    │
   │   │  • copies plaintext into a per-thread DIRECT ByteBuffer                      │    │
   │   │  • extracts the real OS fd from this.socketChannel (reflection)             │    │
   │   │  • NativeBridge.emit(fd, direction, directBuf, len)  ── JNI ──┐              │    │
   │   └──────────────────────────────────────────────────────────────┼──────────────┘   │
   │                                                                    ▼                  │
   │   libpixie_jsse.so:  pixie_jsse_plaintext(fd, direction, buf, len)  ◄── eBPF uprobe   │
   └────────────────────────────────────────────────────────────────────┼────────────────┘
                                                                          │ (bpf_probe_read_user)
   ┌──────────────────────── Pixie PEM (Stirling, eBPF) ──────────────────▼────────────────┐
   │  bcc_bpf/jsse_trace.c : probe_entry_jsse_plaintext                                      │
   │     set_conn_as_ssl(tgid, fd, kJavaJSSESource);                                         │
   │     process_data(ctx, id, dir, &args{fd,buf,kSSLWrite/Read}, len, ssl=true);  ──────────┼─┐
   │  (the SAME pipeline OpenSSL/Go/Node TLS plaintext flows through)                        │ │
   └────────────────────────────────────────────────────────────────────────────────────────┘ │
                                                                                                ▼
                  conn_tracker → Kafka protocol parser → kafka_events.beta table  (encrypted=TRUE)
```

The key correlation insight: `SslTransportLayer` holds **both** the `SSLEngine`
(plaintext) **and** the `SocketChannel` (the OS fd). The agent recovers that fd and
tags the plaintext with it, so it keys by the **exact same `{tgid, fd}`** that
Pixie's syscall kprobes already use for the connection 4-tuple. No timing
heuristics — the decrypted bytes merge cleanly with the connection metadata.

### Why the trampoline is shaped the way it is (load-bearing details)

These were discovered empirically (see [`RESEARCH.md`](RESEARCH.md)) and matter:

1. **The uprobe target lives in its own translation unit and is reached across a
   `.so` boundary.** If you put an empty trampoline in the same compilation unit as
   its caller and build at `-O2`, the compiler does interprocedural argument
   elimination / constant propagation and the argument registers are *undefined* at
   the probe point. A cross-`.so` (PLT) call forces the SysV AMD64 ABI:
   `arg0→rdi, arg1→rsi, arg2→rdx, arg3→rcx`.
2. **Plaintext is copied into a DIRECT (off-heap) ByteBuffer before `emit`.** eBPF
   reads it with `bpf_probe_read_user`, which EFAULTs on non-resident pages. A
   live, off-heap, resident allocation reads reliably; an on-heap `byte[]` may move
   or page out.
3. **The eBPF length argument is masked (`len &= MAX-1`)** so the verifier can prove
   the bound for `bpf_probe_read_user` (`R2 min value is negative` otherwise).

---

## What changed in Pixie (Stirling)

The plaintext path reuses Pixie's existing machinery end-to-end; the additions are
small and mirror the OpenSSL/Go/Node patterns:

| File | Change |
|------|--------|
| `bcc_bpf_intf/common.h` | New `ssl_source_t` value `kJavaJSSESource`. |
| `bcc_bpf/jsse_trace.c` | **New.** Uprobe `probe_entry_jsse_plaintext` → `process_data(..., ssl=true)`. |
| `bcc_bpf/socket_trace.c` | `#include` the new probe file alongside `openssl_trace.c`. |
| `uprobe_manager.h` | `kJavaTLSUProbes` spec; `DeployJavaTLSUProbes` / `AttachJavaTLSUProbes` decls; `java_tls_probed_binaries_`. |
| `uprobe_manager.cc` | Implement attach/deploy (mirrors `AttachOpenSSLUProbesOnDynamicLib`); wire into `DeployUProbes`. |

`DetectApplication()` already recognized `Application::kJava`, and the data-event
struct already carries `ssl_source`, so the connection tracker, Kafka parser, and
`kafka_events` table light up automatically. The only user-visible change is that
encrypted JVM Kafka traffic now appears with `encrypted=TRUE` and a populated body.

Components in this directory:

| Path | What it is |
|------|------------|
| `native/` | `libpixie_jsse.so`: the JNI bridge + the stable `pixie_jsse_plaintext` uprobe target. |
| `agent/`  | `pixie-jsse-agent.jar`: ByteBuddy agent that instruments `SslTransportLayer`. |
| `collector/` | A standalone eBPF "mini-PEM" (libbpf) that decodes Kafka and prints table rows — stands in for the full Stirling pipeline so the approach is runnable without building all of Pixie. |
| `scripts/` | `run_demo.sh` — one-shot end-to-end demo (certs → broker+agent → collector → produce/consume). |

---

## Build

```bash
# 1) native bridge  (needs a JDK for jni.h)
( cd native && JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./build.sh )

# 2) agent jar  (needs Maven; downloads ByteBuddy)
( cd agent && mvn -q -B package )           # -> agent/target/pixie-jsse-agent.jar

# 3) standalone collector  (needs clang + libbpf-dev)
( cd collector && ./build.sh )              # -> collector/collector + jsse_collector.bpf.o
```

## Run against your own broker

Attach the agent to the broker JVM — no broker changes, just an env var:

```bash
export KAFKA_OPTS="-javaagent:/abs/path/pixie-jsse-agent.jar=/abs/path/libpixie_jsse.so"
bin/kafka-server-start.sh config/server.properties
```

Then point the collector at the agent's native lib (it attaches the uprobe to all
processes mapping it):

```bash
sudo ./collector/collector /abs/path/libpixie_jsse.so          # add --hex to see raw bytes
```

In a real deployment you don't run the collector — Stirling's `uprobe_manager`
attaches `probe_entry_jsse_plaintext` automatically once it sees a `java` process
with `libpixie_jsse.so` mapped, and rows flow to `kafka_events`.

## One-shot demo

`scripts/run_demo.sh` provisions a self-signed TLS keystore, starts a single-node
KRaft broker (SSL client listener, plaintext inter-broker) with the agent, runs the
collector, produces/consumes over TLS, and prints the decoded rows plus the
tcpdump-vs-eBPF contrast. Requires: Java 21, clang, libbpf-dev, a Kafka 3.x
distribution, root (for eBPF), and a kernel with `CONFIG_UPROBES`.

---

## Approaches considered (and why this one)

See [`RESEARCH.md`](RESEARCH.md) for the full evaluation. Summary:

| Approach | Gets plaintext? | Zero broker change? | Verdict |
|---|---|---|---|
| uprobe libssl `SSL_read/write` | ❌ (JVM has no libssl on this path) | ✅ | Pixie's current gap |
| uprobe JIT'd JSSE/AES intrinsics | ❌ (no stable symbol/address) | ✅ | Not feasible |
| kprobe `tcp_sendmsg`/syscalls | ❌ (ciphertext only) | ✅ | Gives 4-tuple, not content |
| kTLS offload | ⚠️ (kernel would see plaintext) | ❌ (JSSE has no kTLS path) | Not viable without app changes |
| **Java agent → native trampoline → eBPF uprobe** | ✅ | ✅ (external `-javaagent`) | **Chosen** |

The chosen design is the JVM analogue of how Pixie already traces Go and Node: a
per-runtime shim that lands plaintext into the shared `process_data` pipeline. The
agent is auto-instrumentation (no SDK, no code, no manual spans) injected the same
way operators already inject JMX/APM agents, which preserves the
zero-(developer)-instrumentation promise while crossing the JVM boundary that pure
eBPF cannot.

### Generality beyond Kafka

`SslTransportLayer` is Kafka-specific, but the technique is not. The same agent can
target `sun.security.ssl.SSLEngineImpl.wrap/unwrap` (the JSSE engine itself) to
cover any JVM service using `SSLEngine`; fd correlation there uses the
thread-adjacent socket syscall (the technique Pixie already uses for BoringSSL's
`_syscall_fd_access` probes) instead of the channel reflection used here.
`SSLSocketImpl`-based apps (blocking I/O) are even simpler — the socket fd is
directly reachable.
