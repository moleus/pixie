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
code, JARs, and configuration are untouched.** The agent reaches the JVM two ways:

- **Zero-touch (default in the PEM):** Stirling injects the agent into an
  already-running broker JVM at runtime via the JVM Attach API — the *same*
  `px_jattach` machinery Pixie's profiler already uses to load its JVMTI
  symbolization agent. Nothing on the broker side, not even an env var; deploy the
  PEM and it auto-attaches. See [PEM-side auto-injection](#pem-side-auto-injection-zero-touch).
- **Manual:** start the broker with the agent on the JVM's standard `-javaagent`
  entry point (set via `KAFKA_OPTS`, exactly where operators already put JMX/APM
  flags). Useful for local testing or when runtime attach is disabled.

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
| `uprobe_manager.h` | `kJavaTLSUProbes` spec; `DeployJavaTLSUProbes` / `AttachJavaTLSUProbes` decls; `MaybeInjectJavaTLSAgent` / `ReapJavaTLSAttachers` + attacher state; `java_tls_probed_binaries_`. |
| `uprobe_manager.cc` | Implement attach/deploy (mirrors `AttachOpenSSLUProbesOnDynamicLib`); wire into `DeployUProbes`. Runtime **auto-injection**: when no probe attaches, fork `px_jattach` to load the baked agent into the JVM. New flags `--stirling_enable_java_tls_injection` / `--stirling_pixie_jsse_agent_jar` / `--stirling_pixie_jsse_native_libs`. |
| `perf_profiler/java/px_jattach/px_jattach.{cc,h}` | Add a **Java-agent (`instrument`) mode** alongside the existing JVMTI symbolization mode: copy the jar + `.so` into the target, `dlopen`-check the `.so` for loadability (not the profiler's `PixieJavaAgentTestFn`), and `jattach <pid> load instrument false "<jar>=<so>"`. Uses a distinct `px-jsse-agent-*` artifacts dir so it never collides with profiling the same JVM. |
| `src/stirling/BUILD.bazel`, `java_tls/agent/prebuilt/`, `java_tls/native/BUILD.bazel` | `stirling_java_tls_tools` bakes the agent jar + per-arch musl `libpixie_jsse.so` into `/px` (the defaults the injector points at). |

The Stirling-side changes are compile-validated with Bazel on this environment:
`//…/bcc_bpf:socket_trace` (the real BPF clang compile) builds successfully with
`jsse_trace.c` in the include chain — so the new probe, the `kJavaJSSESource`
enum, and the `process_data`/`set_conn_as_ssl` calls all type-check against
Pixie's actual headers. (See `RESEARCH.md` §7 for the one-time JVM-truststore flags
Bazel needs behind the sandbox's TLS-intercepting proxy.)

`DetectApplication()` already recognized `Application::kJava`, and the data-event
struct already carries `ssl_source`, so the connection tracker, Kafka parser, and
`kafka_events` table light up automatically. The only user-visible change is that
encrypted JVM Kafka traffic now appears with `encrypted=TRUE` and a populated body.

Components in this directory:

| Path | What it is |
|------|------------|
| `native/` | `libpixie_jsse.so`: the JNI bridge + the stable `pixie_jsse_plaintext` uprobe target. Bazel-built per-arch (musl-static). |
| `agent/`  | `pixie-jsse-agent.jar`: ByteBuddy agent that instruments `SslTransportLayer`. `agent/prebuilt/` holds the committed shaded jar that gets baked into the PEM image for auto-injection. |
| `collector/` | A standalone eBPF "mini-PEM" (libbpf) that decodes Kafka and prints table rows — stands in for the full Stirling pipeline so the approach is runnable without building all of Pixie. Includes `kafka_parser.h`, a real from-scratch Kafka wire decoder (request header, Produce/Fetch → RecordBatch v2 → individual key/value records; flexible/compact encodings; gzip/zstd/lz4/snappy decompression; correlation-id pairing). |
| `scripts/` | `run_demo.sh` — one-shot end-to-end demo (certs → broker+agent → collector → produce/consume). `selftest.sh` — regression test that produces known records over TLS with each codec and asserts the collector decoded them. |

### What's been validated (live, Kafka 3.9.0 / Java 21)

- Decrypted **Produce** records (topic/key/value) and **Fetch** records delivered
  to the consumer, on `encrypted=TRUE` connections where `tcpdump` saw only ciphertext.
- 10 correlation-paired Kafka APIs; **multi-partition**; **gzip/zstd/lz4/snappy** compression;
  Fetch **v17** (topic_id/UUID) — see `docs/sample_output.txt` and `RESEARCH.md` §6.
- `scripts/selftest.sh` → ALL PASS across none/gzip/zstd/lz4/snappy.
- **Runtime auto-injection**: dynamic attach (`agentmain` + retransformation) into an
  already-running, already-connected broker recovers plaintext through the eBPF
  uprobe — the `px_jattach` `instrument` mode is the native equivalent.
- Stirling BPF integration compiles via Bazel (`//…/bcc_bpf:socket_trace`); see `RESEARCH.md` §7.
- Overhead at ~20 MB/s is within run-to-run noise (`RESEARCH.md` §8).

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

## PEM-side auto-injection (zero-touch)

The deployable product needs **no broker-side action at all** — not even the
`KAFKA_OPTS` env var. The agent jar and native lib are baked into the PEM image at
`/px/pixie-jsse-agent.jar` and `/px/libpixie_jsse.so` (see `stirling_java_tls_tools`
in `src/stirling/BUILD.bazel`). When Stirling's `uprobe_manager` sees a JVM that
isn't yet carrying the agent, it injects it at runtime:

```
DeployJavaTLSUProbes(pid)
  └─ AttachJavaTLSUProbes(pid) == 0 probes attached (agent not in yet)
       └─ MaybeInjectJavaTLSAgent(upid)         # uprobe_manager.cc
            ├─ skip if libpixie_jsse.so already mapped (manual -javaagent, or prior inject)
            ├─ skip if /px/pixie-jsse-agent.jar missing
            └─ fork java::AgentAttacher(upid, "jar,so")   # px_jattach, instrument mode
                 └─ px_jattach enters the broker's PID+mount namespace, copies the
                    artifacts into the target, and calls jattach <pid> load instrument
                    false "<jar>=<so>"  → the JVM runs the agent's agentmain(),
                    which retransforms SslTransportLayer and System.load()s the .so.
```

On the next rescan the `.so` is mapped, `AttachJavaTLSUProbes` attaches
`probe_entry_jsse_plaintext`, and rows flow to `kafka_events`. Each JVM is attempted
at most once (keyed by pid + start-time); attachers are forked async and reaped.
Flags (all default-on / pointed at the baked artifacts):

| Flag | Default | Purpose |
|---|---|---|
| `--stirling_enable_java_tls_injection` | `true` | Master switch for runtime injection. |
| `--stirling_pixie_jsse_agent_jar` | `/px/pixie-jsse-agent.jar` | Agent jar baked into the image. |
| `--stirling_pixie_jsse_native_libs` | `/px/libpixie_jsse.so` | Native bridge (uprobe target). |

So the end-to-end operator experience is: deploy the PEM image on a node with a
Kafka broker, and Kafka-over-TLS shows up in `kafka_events` — no broker restart,
no `-javaagent`, nothing in Kubernetes beyond the PEM.

## Run against your own broker (manual)

For local testing, or when runtime attach is disabled, attach the agent yourself —
no broker code changes, just an env var:

```bash
export KAFKA_OPTS="-javaagent:/abs/path/pixie-jsse-agent.jar=/abs/path/libpixie_jsse.so"
bin/kafka-server-start.sh config/server.properties
```

Then point the standalone collector at the agent's native lib (it attaches the
uprobe to all processes mapping it):

```bash
sudo ./collector/collector /abs/path/libpixie_jsse.so          # add --hex to see raw bytes
```

In a real deployment you don't run the collector — Stirling injects the agent (or
finds it already attached) and wires `probe_entry_jsse_plaintext` automatically, as
above.

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
