# Hard-won gotchas: building Pixie, eBPF, JVM/JSSE TLS, and Kafka

A field guide to the non-obvious problems hit while adding JVM/JSSE TLS tracing to
Pixie (Kafka-over-TLS) and building/testing it. Written for the next person who
works on Pixie from scratch, on eBPF/TLS tracing, or on building/testing the PEM —
so they don't lose the hours we lost. Each entry: **symptom → root cause → fix**.

The companion files: [`README.md`](README.md) (what the feature is),
[`RESEARCH.md`](RESEARCH.md) (the design + protocol research).

---

## 1. Building Pixie with Bazel behind a TLS-intercepting proxy

**Symptom.** Every `bazel build` dies in the loading phase:
```
Error downloading [...bazel-skylib...]: PKIX path building failed:
sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid
certification path to requested target
```
…even though `curl https://github.com` returns 200.

**Root cause.** The environment's egress proxy does TLS interception with a private
CA. `curl`/`apt` use the system CA bundle (which has the proxy CA), **but Bazel's
downloads run on the JVM**, which uses its *own* truststore (`$JAVA_HOME/lib/security/cacerts`)
that does **not** contain the proxy CA. Worse, there are **two** different JVMs that
download things:
1. the **Bazel server** (downloads `http_archive` repos like skylib);
2. the **`rules_jvm_external` / coursier** subprocess (downloads Maven jars) — a
   *separate* JVM, and `--incompatible_strict_action_env` (set in Pixie's
   `.bazelrc`) strips the environment from it.

**Fix.** Point *both* JVMs at a truststore that trusts the proxy. On Debian/Ubuntu
the system already maintains one at `/etc/ssl/certs/java/cacerts` (kept in sync by
`ca-certificates-java`). Pass it in two places:
```bash
bazel \
  --host_jvm_args=-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts \
  --host_jvm_args=-Djavax.net.ssl.trustStorePassword=changeit \
  build //target \
  --repo_env="JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts -Djavax.net.ssl.trustStorePassword=changeit"
```
- `--host_jvm_args` is a **startup** flag (must precede the command; changing it
  restarts the Bazel server).
- `--repo_env=JAVA_TOOL_OPTIONS=...` injects the truststore into repository-rule
  subprocesses (coursier). **Quote the whole flag** — the value has a space, and an
  unquoted `$VAR` splits it into a bogus second arg (`Invalid options syntax`).
- The Bazel server is **persistent**: if you first ran it without the flag, it
  keeps the old JVM. `bazel shutdown` (or just changing `--host_jvm_args`) restarts it.

**Time sink:** ~1h, because the first symptom (skylib) is fixed by `--host_jvm_args`,
then the *next* failure (Maven) looks identical but needs the *different* `--repo_env`.

## 2. The PEM C++ graph is huge; scope your targets

Building `//src/stirling/source_connectors/socket_tracer:cc_library` pulls in
essentially all of Pixie's C++ deps (abseil, protobuf, an LLVM-based toolchain, …)
— tens of GB and a long time. To **compile-check a BPF change** you don't need it:
- `//…/bcc_bpf:socket_trace_bpf_preprocess` runs only the C preprocessor (catches
  bad `#include`s / missing files fast).
- `//…/bcc_bpf:socket_trace` runs the **real** BPF `clang` compile (catches BPF
  syntax/type errors) and is far smaller than the full PEM.
Use a local `--disk_cache=/root/.cache/bazel-disk` so reruns are warm; you do **not**
need Pixie's BuildBuddy remote cache (the fork CI workflow already sets this up).

## 3. eBPF on a host with no BTF and no kernel headers

**Symptom.** No `/sys/kernel/btf/vmlinux`, no `/lib/modules/$(uname -r)/build`, no
BCC. CO-RE programs and `bpftrace` (which needs BTF) won't run. `clang -target bpf`
errors `'asm/types.h' file not found`.

**What actually works.**
- A **CO-RE-free** BPF program loads fine: define your own `struct pt_regs`, read
  helpers by number via `<bpf/bpf_helpers.h>`, use a `BPF_MAP_TYPE_RINGBUF`. No
  kernel BTF needed (kernel BTF is only required for CO-RE relocations / vmlinux types).
- `clang -target bpf` needs the multiarch include for `asm/`: add
  `-I/usr/include/x86_64-linux-gnu`.
- **uprobes attach without tracefs/BTF** via the perf-event path
  (`/sys/bus/event_source/devices/uprobe/type` present). libbpf's
  `bpf_program__attach_uprobe_opts` uses it. `debugfs` may need mounting first:
  `mount -t debugfs none /sys/kernel/debug`.
- `RLIMIT_MEMLOCK` may need raising for older loaders (`ulimit -l`), though
  ringbuf/BPF on modern kernels uses memcg accounting.

## 4. The uprobe trampoline's arguments vanish (ABI / IPA)

**Symptom.** A uprobe fires on your target function, but `arg0..argN` read as `0` /
garbage. The pointer arg is junk; `bpf_probe_read_user` then EFAULTs.

**Root cause.** If the uprobe target is an *empty* function in the **same
translation unit** as its caller and you build at `-O2`, the compiler does
interprocedural argument elimination / constant propagation and simply **doesn't
load the argument registers** at the call site (it proved the callee ignores them).
At the probe point (function entry) the ABI registers are undefined.

**Fix.** Make the trampoline a real cross-module call so the SysV AMD64 ABI is
forced (`arg0→rdi, arg1→rsi, arg2→rdx, arg3→rcx`):
- put it in its **own `.so`** (or at least its own TU), reached via PLT;
- **don't** enable LTO across that boundary;
- have the body consume all args (`asm volatile("" :: "r"(a),"r"(b)... : "memory")`)
  so they can't be treated as dead.

We verify with `objdump`: the JNI shim must `mov`/`mov` the args then
`call/jmp pixie_jsse_plaintext@plt`.

**Time sink:** ~45 min — it looks like a wrong `pt_regs` layout, but the layout was
right; the caller just never set the registers.

## 5. `bpf_probe_read_user` returns -14 (EFAULT) on a "valid" pointer

**Symptom.** The pointer looks like a normal userspace address but the read fails.

**Root cause.** `bpf_probe_read_user` does **not** fault pages in. If the page isn't
resident it EFAULTs. In our first synthetic test the target passed the address of a
`.rodata` string it never dereferenced (its `strlen` was constant-folded), so the
page was never paged in.

**Fix / implication for design.** Read memory that is actually live and resident.
For the JVM agent this is why plaintext is copied into a **direct (off-heap)
`ByteBuffer`** before handing the address to native/eBPF — its backing memory is a
stable resident native allocation. An on-heap `byte[]` can move (GC) or be non-resident.

## 6. BPF verifier: a length must be *provably* bounded

**Symptom.** `R2 min value is negative` (or "unbounded") rejecting your
`bpf_probe_read_user(dst, len, src)`.

**Root cause.** `if (len > MAX) len = MAX;` does **not** always give the verifier a
provable bound. **Beware:** `len &= (MAX-1)` (power-of-two mask) *does* — but it
**wraps** for `len >= MAX` (a 4096-byte message → 0 captured!). Use **clamp then
mask**: `if (len > MAX-1) len = MAX-1; len &= (MAX-1);` — correct *and* verifiable.

## 7. Why JVM TLS needs an agent at all (no stable native symbol)

The JVM does TLS in pure Java (`sun.security.ssl.SSLEngineImpl`); AES is a
JIT-compiled HotSpot intrinsic. So there is **no `libssl`/`libcrypto` symbol to
uprobe** (the trick Pixie uses for C/OpenSSL, and the reason Netty *is* covered —
it links `netty-tcnative`, a shaded OpenSSL). Uprobing JIT'd code is unstable
(addresses move per run/JIT). Hence: a tiny injected Java agent captures plaintext
in-JVM and hands it to a stable native uprobe target. Kafka specifically uses
`SSLEngine` + `SocketChannel` (`org.apache.kafka.common.network.SslTransportLayer`),
**not** `SSLSocket` and **not** Netty.

## 8. JVM agent details that bite

- **No `--add-opens` on the broker command line needed.** The agent reflects into
  `sun.nio.ch.SocketChannelImpl.fd` → `java.io.FileDescriptor.fd` to recover the OS
  fd. Instead of requiring operators to pass `--add-opens`, the agent opens those
  `java.base` packages to itself at premain via
  `Instrumentation.redefineModule(base, …, extraOpens=…)`.
- **Capture the *consumed* delta on write, not the whole buffer.** Kafka's
  `SslTransportLayer.write(src)` may consume only part of `src` under socket
  back-pressure; the caller retries with the same buffer. Capturing all of `src` on
  entry double-counts the tail. Record `src.position()` on entry; capture
  `[start, position)` on exit.
- **One hook covers vectored writes.** `write(ByteBuffer[])` delegates to
  `write(ByteBuffer)` internally, so hooking the single-buffer method suffices.

## 9. Kafka wire-protocol versioning will silently break a parser

- Kafka 3.9 clients negotiate **Fetch v17** and **Produce v11**. **Fetch v13+
  replaced the topic *name* (string) with a 16-byte `topic_id` (UUID)** in the
  response — parse it as a string and every later offset is wrong → **zero records
  decoded, no error**. (Upstream Pixie's `APIVersionMap` caps Fetch at v12 / Produce
  at v9, so modern Kafka would be mis/unparsed there today.)
- **Flexible versions** use compact (varint-length) strings/arrays + tagged-field
  sections; the request **header**'s `client_id` is a *regular* int16 string even in
  flexible versions, with the tag section *after* it.
- **api_key alone is a weak signal.** A response whose first two bytes are `00 00`
  looks like a Produce(0) request. Disambiguate by (a) correlation-id pairing and
  (b) `api_version <= max_version(api_key)`.
- **Compression is on by default in many setups** and upstream Pixie decodes none.
  RecordBatch `attributes` bits 0–2 = gzip/snappy/lz4/zstd; the post-header records
  blob is one compressed stream. snappy uses Kafka's **xerial framing** (16-byte
  magic + length-prefixed snappy blocks), not raw snappy.

## 10. arm64 / cross-compile

- Pixie's **dynamic** Go tracer emitted x86-only `struct pt_regs` field names
  (`ctx->ax/di/si/...`) → every uprobe failed to compile on aarch64
  (`no member named 'ax'`). Fixed by selecting the register set at compile time
  (`__aarch64__` → `ctx->regs[N]`) — see the `arm64-fix` branch.
- **The JSSE socket_tracer probe (shipped in the PEM) needed no arch work:** it uses
  BCC's `PT_REGS_PARM1..4` macros (arch-mapped to `rdi…`/`x0…`) and plain
  enums/structs, so it cross-compiles for aarch64 unchanged.
- **The standalone demo collector** (`collector/jsse_collector.bpf.c`, a dev tool not
  shipped in the PEM) hand-rolls its own `pt_regs` to avoid a BTF/kernel-headers
  dependency, so it *did* need arch work. It now selects the register layout at
  compile time (`__TARGET_ARCH_arm64`) and `collector/build.sh` derives the target
  arch + multiarch triple from `uname -m`. The args of
  `pixie_jsse_plaintext(fd,dir,buf,len)` are RDI/RSI/RDX/RCX on x86-64 but
  X0–X3 = `regs[0..3]` on arm64 — reading the x86 offsets on arm64 yields garbage
  (the same bug class as the dynamic-tracer fix above).
- Cross-compiling the PEM: `bazel build --config=aarch64_sysroot
  //src/vizier/services/agent/pem:pem_image`. BPF tests can't run under qemu, so CI
  does **build-only** for arm64 and verifies runtime on a real Graviton node.

## 11. Single-node KRaft confuses request/response direction

In single-node KRaft the broker is also a **TLS client to itself** (internal
admin/coordinator connections), so a broker `read()` can carry a *response* and a
`write()` a *request*. Don't infer req/resp from transport direction — **pair by
correlation id** (what Pixie's stitcher does). For a clean demo, move the
inter-broker listener to PLAINTEXT so the SSL listener carries only genuine external
client traffic (also the realistic production shape).

## 12. Test-harness / shell gotchas (cost real time)

- **`pkill -f <pattern>` can match your own shell.** `pkill -f 'kafka.Kafka'` run
  from a one-liner whose command line *contains* that string kills the shell itself.
  Use `pkill -x <exactname>`, match a unique token (`server.properties`), or kill by
  PID. Inside a script *file* the shell's argv is the script path, so it's safe there.
- **Don't `pkill -9 java` to restart the broker** if Bazel is building — it kills
  the Bazel server + `clang-15` jobs too. Match only the broker (`server.properties`).
- **Killing the broker doesn't free the port instantly**; a fresh broker can fail to
  bind (`Address already in use`). Wait a few seconds between stop and start.
- **`clang-15` (not `clang`) is the Bazel compile-job process name** — `pkill clang`
  misses them; and the Bazel **server** re-dispatches jobs, so kill the server first.
