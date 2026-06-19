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
