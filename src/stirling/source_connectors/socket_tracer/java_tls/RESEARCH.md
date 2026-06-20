# Research notes: intercepting Kafka TLS plaintext via eBPF

This documents the investigation behind the JVM/JSSE TLS path: how Kafka does TLS,
where the plaintext lives, what Pixie supports today, the approaches evaluated, and
the empirical gotchas that shaped the implementation.

## 1. How Kafka does TLS (where the plaintext is)

Kafka does **not** use `SSLSocket` or Netty. It uses non-blocking `java.nio`
(`Selector` + `SocketChannel`) with a JSSE `SSLEngine`, wired together in
`org.apache.kafka.common.network.SslTransportLayer` (in the `clients` module,
shipped in every broker/client). Key fields:

```java
public class SslTransportLayer implements TransportLayer {
    private final SSLEngine sslEngine;          // does encrypt/decrypt
    private final SocketChannel socketChannel;  // the raw OS socket  <-- gives us the fd
    private ByteBuffer netReadBuffer;           // ciphertext in
    private ByteBuffer netWriteBuffer;          // ciphertext out
    private ByteBuffer appReadBuffer;           // plaintext in (post-unwrap)
    ...
}
```

The plaintext boundaries:

- `read(ByteBuffer dst)` — reads ciphertext from `socketChannel` into
  `netReadBuffer`, then `sslEngine.unwrap(netReadBuffer, appReadBuffer)` decrypts;
  the freshly-decrypted bytes are copied into `dst`. **On return, the last
  `returnValue` bytes of `dst` are plaintext (INGRESS).**
- `write(ByteBuffer src)` — `src` is plaintext; `sslEngine.wrap(src, netWriteBuffer)`
  encrypts and writes to `socketChannel`. **On entry, `src` is plaintext (EGRESS).**

Inside the JVM, the actual ciphering is `sun.security.ssl.SSLEngineImpl` →
`SSLCipher` → JCE (`com.sun.crypto.provider`), and AES-GCM is a **HotSpot
intrinsic** (hand-written assembly using AES-NI, emitted by the JIT). Consequences:

- There is **no stable native symbol** (no `libcrypto` `EVP_*`) on the JSSE path to
  uprobe. The key material lives in on-heap Java objects (`SecretKeySpec`,
  cipher state); recovering it to decrypt out-of-band would be brittle and is
  effectively re-implementing TLS.
- Therefore the only robust capture point is the Java buffer boundary above, which
  requires running code inside the JVM.

Key classes confirmed in-tree (Apache Kafka 3.9):
`clients/src/main/java/org/apache/kafka/common/network/SslTransportLayer.java`
(`read` ~L560, `write` ~L710, `sslEngine.wrap/unwrap` at L191/494/528/586),
`SslChannelBuilder`, `SslFactory`/`SslEngineFactory`.

## 2. What Pixie supports today (and the extension points)

Pixie's socket tracer captures TLS plaintext by uprobing per-runtime functions and
funneling everything into one kernel-side submission function:

- **OpenSSL/BoringSSL**: `bcc_bpf/openssl_trace.c` uprobes `SSL_read/SSL_write`
  (+`_ex`), recovers the fd from `ssl->rbio->num` (via version-specific symbol
  offsets in `openssl_symaddrs_map`) or, for BoringSSL/static, from the
  **nested write/read syscall** (`ssl_user_space_call_map`, the `_syscall_fd_access`
  probe variants).
- **Go**: `go_tls_trace.c` uprobes `crypto/tls.(*Conn).Write/Read`.
- **Node**: `node_openssl_trace.c` uprobes `TLSWrap` to map the `SSL*` to an fd.

All of them converge on:

```
process_data(vecs, ctx, id, direction, &data_args_t{fd, buf, source_fn}, bytes_count, ssl=true)
set_conn_as_ssl(tgid, fd, <ssl_source_t>)
```

which keys by `{tgid, fd}` (`conn_info_map`), runs protocol inference, and submits a
`socket_data_event_t` (carrying `ssl`, `ssl_source`, `direction`, `conn_id`) on the
`socket_data_events` perf buffer. User space (`socket_trace_connector.cc` →
`conn_tracker` → protocol parsers) turns it into table rows. Kafka already has a
parser and the `kafka_events.beta` table (columns include `encrypted`, `req_cmd`,
`client_id`, `req_body`, `resp`, `latency`).

Relevant enums/structs:
`ssl_source_t` (`bcc_bpf_intf/common.h`), `traffic_direction_t {kEgress=0,kIngress=1}`,
`source_function_t {…,kSSLWrite,kSSLRead}`, `data_args_t` (`socket_trace.h`),
`Application::kJava` (`utils/detect_application.{h,cc}`).

**Extension points used here:** add an `ssl_source_t` value, add a uprobe + a
`Deploy*/Attach*` pair in `uprobe_manager` that finds the agent's `.so` in the
target's maps (reusing `FindHostPathForPIDLibs`, the OpenSSL pattern), and feed the
existing `process_data`. Nothing downstream needed changing — confirmed there is no
exhaustive `switch` on `ssl_source_t` (it flows through `magic_enum::enum_name` and a
32-bit hash in `metrics.cc`), so adding a value is safe.

## 3. Approaches evaluated

1. **uprobe libssl `SSL_read/write`** — what Pixie does. The JVM's JSSE path never
   calls libssl, so nothing fires. (Works only for Netty's `netty-tcnative`.)
2. **uprobe the JIT'd JSSE/AES code** — AES is a HotSpot intrinsic at a dynamic,
   relocated address with no stable symbol; uprobing interpreted/JIT'd Java bytecode
   is not stable across runs or JITs. Not feasible.
3. **kprobe on `tcp_sendmsg`/`tcp_recvmsg` or the socket syscalls** — only ever sees
   ciphertext (encryption already happened in user space). Useful for the connection
   4-tuple (Pixie already does this) but never for content.
4. **kTLS (kernel TLS offload)** — if TLS were offloaded to the kernel
   (`setsockopt(TCP_ULP, "tls")` + keys), eBPF could observe plaintext on the
   kTLS/sendmsg path. **JSSE has no kTLS offload path**, so this can't be enabled
   without modifying the application/JDK. Not viable for zero-touch. (Documented as a
   future option if a kTLS-enabling JSSE provider is ever used.)
5. **JVMTI / Java agent → native trampoline → eBPF uprobe (chosen)** — a small
   externally-injected agent captures plaintext at the JSSE boundary and calls a
   stable native symbol that eBPF uprobes, landing plaintext in `process_data`. This
   is the JVM analogue of Pixie's Go/Node TLS probes. Implemented with a
   `java.lang.instrument` agent (ByteBuddy) rather than a C JVMTI agent because
   bytecode advice is simpler and version-robust; either form satisfies
   "no broker modification" (both attach via the JVM's standard agent entry point).

Why a native trampoline instead of having the agent talk to eBPF directly: Java
can't easily write to a BPF ring buffer, and keeping *all* policy in eBPF (the
trampoline is an empty function) means the injected native surface ships no Pixie
logic and the broker pays only an empty call.

## 4. Empirical findings / gotchas (validated on Linux 6.18, no kernel BTF)

These were found by building the chain incrementally on a minimal host (no
`/sys/kernel/btf/vmlinux`, no kernel headers, no BCC):

- **uprobes attach without kernel BTF.** A CO-RE-free BPF program (own `pt_regs`
  struct, helpers by number, ringbuf) loads and attaches via the perf-event uprobe
  path (`uprobe` PMU). `debugfs` may need mounting (`mount -t debugfs none
  /sys/kernel/debug`).
- **Trampoline ABI must be forced.** With the trampoline in the *same* TU as its
  caller at `-O2`, the args were dropped at the call site (registers undefined at the
  probe). Fix: separate TU + cross-`.so` PLT call (and an `asm volatile` that
  consumes all four args). Verified the JNI glue tail-calls
  `pixie_jsse_plaintext@plt` with `rdi=fd, rsi=dir, rdx=ptr, rcx=len`.
- **`bpf_probe_read_user` EFAULTs on non-resident pages.** A pointer to a `.rodata`
  string that the program never dereferenced (its `strlen` was constant-folded) was
  not paged in → `-14`. Live, off-heap, resident buffers (DIRECT ByteBuffer) read
  cleanly (`ret=0`). Hence the agent copies into a direct buffer before `emit`.
- **Verifier needs a provable length bound.** `if (len >= MAX) len = MAX-1;` was
  rejected (`R2 min value is negative`); `len &= (MAX-1)` (power-of-two) passes.
- **fd extraction needs `java.base` opened.** Reading
  `sun.nio.ch.SocketChannelImpl.fd` → `java.io.FileDescriptor.fd` requires those
  packages open. The agent does it programmatically with
  `Instrumentation.redefineModule(...extraOpens...)` at premain, so **no
  `--add-opens` flags** are required on the broker command line.
- **Request/response can't be inferred from read vs write.** Single-node KRaft makes
  the broker a TLS *client to itself* (internal admin/coordinator connections), so a
  broker `read()` may carry a response. Decode must **pair by Kafka correlation id**
  (what Pixie's parser does), not by transport direction. (Also: moving the
  inter-broker listener to plaintext keeps the SSL listener's traffic purely
  external, which is the realistic production shape anyway.)
- **Kafka request framing.** `NetworkReceive` reads the 4-byte size separately from
  the payload, so per-fd/per-direction reassembly of `[int32 size][body]` frames is
  required before parsing the `[api_key][api_ver][corr_id][client_id]` header.

## 5. Validation

Live against Kafka 3.9.0 (Java 21) with a one-way-TLS client listener and the agent
injected via `KAFKA_OPTS`. The collector recovered and correctly correlation-paired
10 distinct Kafka APIs (ApiVersions, Metadata, FindCoordinator, JoinGroup,
SyncGroup, OffsetFetch, ListOffsets, InitProducerId, Produce, Fetch), including
producer keys/values and the full Fetch payload delivered to the consumer — all on
connections where `tcpdump` on the wire showed only ciphertext. See
[`docs/sample_output.txt`](docs/sample_output.txt).

## 6. Raw Kafka parser + second-round gotchas

The standalone collector originally surfaced plaintext via a string-extraction
heuristic. It now carries a real, from-scratch Kafka wire decoder
([`collector/kafka_parser.h`](collector/kafka_parser.h)) modelled on Pixie's C++
`protocols/kafka/decoder`: a bounds-checked cursor with INT16/32/64, (un)signed
zig-zag varints, regular/compact strings & arrays, and tagged fields; request
header parsing; and descent into **Produce requests** and **Fetch responses**
down to individual records (key/value) inside RecordBatch (magic v2). Building it
against live Kafka 3.9 surfaced several gotchas — some of which also affect
Pixie's own parser:

- **Kafka protocol versions evolve and break layouts.** Kafka 3.9 clients
  negotiate **Fetch v17** and **Produce v11**. Fetch **v13+ replaced the topic
  *name* (string) with a 16-byte `topic_id` (UUID)** in the response — a breaking
  wire change. A parser written to the v12 schema reads the UUID as a string and
  every subsequent offset is wrong, yielding zero records. Pixie's `APIVersionMap`
  caps Fetch at v12 and Produce at v9, so **modern Kafka Fetch/Produce versions
  would be marked unsupported/misparsed by upstream Pixie today** — a real gap
  worth flagging. Our parser special-cases `topic_id` for Fetch ≥ v13.
- **`api_key` alone is too weak a request signal.** A response frame whose first
  two bytes happen to be `00 00` looks like a Produce (api_key 0) request. The fix
  is twofold: try correlation-id pairing first (a frame whose leading int32 is an
  outstanding request's correlation id is a response), and validate
  `api_version <= max_version(api_key)` (e.g. Produce ≤ 11) to reject coincidences.
- **Compression is real and Pixie doesn't handle it.** RecordBatch `attributes`
  bits 0–2 select gzip/snappy/lz4/zstd; the records blob after the batch header is
  then a single compressed stream. Pixie reads the attributes but not the payload,
  so compressed batches yield no records there. Our parser decompresses **all four
  codecs** in-place and re-parses: **gzip** (zlib, windowBits 31), **zstd**
  (libzstd), **lz4** (liblz4 frame API), and **snappy** (libsnappy, including
  Kafka's xerial block framing). Verified by producing with
  `compression.type=gzip|zstd|lz4|snappy` and recovering every record.
- **A capture-size mask must clamp, not wrap.** The collector's BPF masked the
  capture length with `len &= (MAX-1)` for the verifier; for `len >= MAX` that
  *wraps* (a 4096-byte message → 0 captured). Correct form is clamp-then-mask:
  `if (len > MAX-1) len = MAX-1; len &= (MAX-1);`. (The production `jsse_trace.c`
  path is unaffected — it delegates to Pixie's `process_data`, which chunks large
  messages up to `MAX_MSG_SIZE` and reassembles in user space.) Single writes
  larger than the per-event cap are still truncated in the demo; the Kafka client
  happens to write requests in sub-cap pieces that per-fd reassembly recombines,
  so even a 50 KB value decoded in testing.

## 7. Compiling Pixie here (Bazel) — and the cert gotcha

The full PEM is too large to build under the disk/time budget, but the relevant
targets *do* build once one environment quirk is solved:

- The sandbox proxy does TLS interception with a private CA that is in the system
  bundle (`curl` works) but **not in the JVM truststore Bazel uses**, so every
  `http_archive`/maven download fails with `PKIX path building failed`.
- The system already ships a Java truststore that trusts the proxy at
  `/etc/ssl/certs/java/cacerts`. Pointing Bazel at it requires **two** places,
  because downloads happen in two different JVMs:
  - the **Bazel server** JVM → `--host_jvm_args=-Djavax.net.ssl.trustStore=… -Djavax.net.ssl.trustStorePassword=changeit` (a startup flag; restarts the server);
  - the **`rules_jvm_external` coursier** subprocess (separate JVM, and
    `--incompatible_strict_action_env` strips the env) → `--repo_env="JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=… -Djavax.net.ssl.trustStorePassword=changeit"`.

With those, `//…/bcc_bpf:socket_trace_bpf_preprocess` builds and the preprocessed
output contains `probe_entry_jsse_plaintext` / `kJavaJSSESource` (the new probe
and enum compile into the BPF include chain), and **`//…/bcc_bpf:socket_trace`
(the real BPF clang compile) builds successfully** — so `jsse_trace.c` type-checks
against Pixie's actual headers, not just the preprocessor. (The full C++
`socket_tracer:cc_library` pulls Pixie's entire C++ dependency graph — abseil,
protobuf, LLVM-based tooling, etc. — which exceeds the sandbox's disk/time budget;
the `uprobe_manager.cc` changes mirror the established OpenSSL/Go deploy pattern
and were reviewed against the real signatures.)

## 8. Overhead experiment

`kafka-producer-perf-test` over TLS, 300k × 256 B records, single-node broker on a
shared 4‑vCPU / 15 GB VM (the broker JVM and the perf client compete for the same
cores, so absolute numbers are low):

| Config | rec/s | MB/s | avg latency |
|---|---|---|---|
| Baseline, no agent (run 1) | 77,700 | 18.97 | 1037 ms |
| Baseline, no agent (run 2) | 90,580 | 22.11 |  781 ms |
| Agent loaded, no collector | 82,034 | 20.03 |  907 ms |
| Agent + collector (uprobe live) | 90,744 | 22.15 |  786 ms |

The baseline alone varies ~16 % run-to-run (JIT warm-up, GC, CPU scheduling on a
contended VM), and the agent / agent+collector results land **inside that band**.
So at ~20 MB/s the cost of (a) the agent's intercept→copy→JNI→trampoline and
(b) the eBPF uprobe + ring-buffer is **below the measurement noise floor here** —
no degradation is attributable to the instrumentation. During the agent+collector
run the collector decoded ~118k Kafka records live, i.e. it kept pace with the
data path. (A rigorous overhead figure needs an isolated host, pinned CPUs, and
many iterations; this only establishes that the overhead is small relative to
normal broker variance.) The agent paths are also designed to stay cheap: fd is
cached per channel, only the consumed plaintext delta is copied, and the native
trampoline is an empty function when no eBPF probe is attached.
