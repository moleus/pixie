# PR status & audit — `arm64-fix`

A map of everything on this branch: what ships, what's dev-only, what's validated,
and what's experimental. Written after a full audit (multiple independent code
reviews + local re-runs of every test). Scope at time of writing: **~5,000
insertions, 64 files, 39 commits** vs `origin/main`.

TL;DR: **nothing here is stale or dead.** The default path — Kafka-over-TLS capture
with **zero-touch PEM-side agent injection**, plus the arm64 dynamic-tracer fix — is
validated end-to-end; one piece (the generic SSLEngine "engine" mode) is opt-in but
also validated; the dead/incorrect items found in audit were removed/fixed.

## What actually ships in the PEM image (the deployable product)

| Area | Status | Notes |
|---|---|---|
| `bcc_bpf/jsse_trace.c`, `socket_trace.c` include, `bcc_bpf_intf/common.h` (`kJavaJSSESource`) | **ACTIVE, correct** | The JVM/JSSE uprobe. Uses BCC arch-aware `PT_REGS_PARM*` — arm64-safe. Audit: 0 issues. |
| `uprobe_manager.{cc,h}` (`DeployJavaTLSUProbes`/`AttachJavaTLSUProbes`) | **ACTIVE, correct** | Mirrors the OpenSSL attach path (`FindHostPathForPIDLibs`, per-binary dedup, container paths). Audit: 0 issues. |
| `uprobe_manager.{cc,h}` runtime **auto-injection** (`MaybeInjectJavaTLSAgent`/`ReapJavaTLSAttachers` + flags) | **ACTIVE, correct** | When a JVM has no agent yet, fork `px_jattach` to load it. Deduped per JVM (pid+start-time), forked async + reaped, skips if the `.so` is already mapped or the jar is absent. |
| `perf_profiler/java/px_jattach/px_jattach.{cc,h}` Java-agent (`instrument`) mode | **ACTIVE, correct** | Reuses the profiler's namespace-entering attach machinery; loadability `dlopen` check (not the profiler `PixieJavaAgentTestFn`); distinct `px-jsse-agent-*` artifacts dir to avoid colliding with profiling the same JVM. |
| `agent/prebuilt/pixie-jsse-agent.jar`, `native/libpixie_jsse.so`, baked via `stirling_java_tls_tools` into `/px` | **ACTIVE** | The artifacts the injector points at by default. Jar is committed (CI rebuilds it; see `agent/prebuilt/README.md`); `.so` is Bazel-built per-arch (musl-static). |
| `dynamic_tracer/.../code_gen.cc`, `obj_tools/abi_model.{cc,h}` (arm64 register tables) | **ACTIVE, correct** | The actual arm64 fix. All arch-specific codegen `#if defined(__aarch64__)`-gated. Includes a real **pre-existing-Pixie UB fix** (empty-deque in SysV hidden-return path). |
| `div_u64` include, perf-profiler, linux_headers, build stubs | **ACTIVE, correct** | arm64 kernel ≥6.8 build fixes. |

This is what `kubectl set image ds/vizier-pem` deploys. **The end-to-end operator
experience is now zero-touch:** deploy the PEM on a node with a Kafka broker and
Kafka-over-TLS appears in `kafka_events` — no broker restart, no `-javaagent`,
nothing in Kubernetes beyond the PEM. The audit of all of it found **zero issues**.

## Broker-side agent (now injected by the PEM; also attachable manually)

| Area | Status |
|---|---|
| `agent/` (ByteBuddy Java agent) | **ACTIVE** — kafka mode is the proven default; **engine mode** (generic `SSLEngine` hook for any JSSE app) is opt-in via `-Dpixie.jsse.mode=engine`. Both validated (see below). Injected automatically (above) or via `-javaagent`. |
| `native/` (JNI bridge + stable trampoline symbol) | **ACTIVE** — separate-TU + PLT design is load-bearing (see GOTCHAS §4); arch-agnostic. |

## Dev / test / demo tooling (validates the feature; not in the image)

| Area | Status |
|---|---|
| `collector/` + `kafka_parser.h` (standalone libbpf collector + wire parser) | **ACTIVE** — decodes Produce/Fetch incl. Fetch v13+ topic_id and all 4 codecs (exceeds upstream Pixie's parser). Arch-aware. |
| `collector/tests/` (functional, property, varint, fuzz, e2e) | **ACTIVE** — all pass (numbers below). |
| `scripts/` (run_demo.sh, selftest.sh) | **ACTIVE** — `PIXIE_JSSE_MODE` selects kafka/engine/both. |

## CI / build

| Area | Status |
|---|---|
| `.github/workflows/arm64-dynamic-tracing-fix.yaml`, `k8s/vizier` PEM targets | **ACTIVE** — per-arch PEM build+push in parallel + `crane` multiarch manifest. Fixed tag mismatch (consistent `${GITHUB_SHA::9}`), dropped redundant arm64 DT cross-compile + stamp relink. Split into parallel `test-x86` / `build-x86-pem` / `build-arm64` jobs; optional shared BuildBuddy remote cache (graceful fallback to local disk cache); `-g0` fastbuild; per-job v2 cache keys; default-branch + weekly cache seeding. |
| `.github/workflows/java-tls-artifacts.yaml` | **ACTIVE** — builds the agent jar + per-arch native `.so` + collector and publishes a rolling `java-tls-latest` pre-release, so the broker-side artifacts are usable without local builds. |

## Docs

`README.md`, `RESEARCH.md`, `GOTCHAS.md`, `docs/LOCAL_ARM64_VALIDATION.md`,
`agent/prebuilt/README.md`, `collector/tests/README.md`, this file. All current.

## Bugs found & fixed on this branch

1. **arm64** — demo collector read x86 arg registers (`jsse_collector.bpf.c`); on arm64 those land on X14..X11, not the real args X0–X3. (The shipped eBPF was already safe via BCC macros; this was the dev collector.)
2. **UB** — `kafka_parser.h` `kd_i64` signed-shift overflow. Found by UBSan fuzz.
3. **UB (pre-existing Pixie)** — `SysVABIModel::PopLocation` popped `int_arg_registers_.front()` on an empty deque. Found by property testing.
4. **Dynamic attach captured nothing** — ByteBuddy's default REBASE adds methods, which the JVM refuses when *retransforming* already-loaded classes (the injection case), so advice was silently dropped. Fixed with `disableClassFormatChanges()` (REDEFINE). A/B test then confirmed capture.
5. **PEM injection correctness** — `absl::Substitute` has no `std::filesystem::path` overload (passed `lib` directly → compile error); fixed with `.string()` and explicit `"true"/"false"` rendering. Also, deliberately avoided two gaps in an earlier injection draft: reusing the profiler's `SelectLibWithDLOpenOrDie` (hard-requires `PixieJavaAgentTestFn`, which the jsse `.so` lacks → FATAL) and the JVMTI artifacts dir (collides when a JVM is both profiled and TLS-traced).
6. **CI correctness** — multiarch manifest tag mismatch (`MANIFEST_UNKNOWN`) from `git rev-parse --short` length varying with checkout depth; tests previously filtered out by `--config=bpf`; remote cache never enabling because the config step ran under dash (`[[` unsupported) → pinned `shell: bash`.
7. **Audit cleanups** — removed dead `rd16()` (collector.c) and `isLoaded()` (NativeBridge.java); corrected reversed direction-param docs (code was right: `kEgress=0`/write, `kIngress=1`/read).
8. **Kafka not classified on modern/loaded clusters (the empty-table blocker)** — `infer_kafka_message` required a single read to contain exactly one full frame (`count == message_size`). On real traffic (long messages split across reads, TCP coalescing, TLS/JSSE chunks) that never holds, so connections stayed `protocol=Unknown` and `kafka_events` stayed empty even after the api_version gate was raised. Relaxed to classify partial (`declared >= count`, the broker's read-4-then-payload path) and coalesced (`count >= message_size`) reads, bounded to 100 MiB. **Validated against a live Apache Kafka 4.0 broker** (strace of real produce/consume): the old code dropped 3 large split-Produce reads (e.g. a 163,706-byte read of a 2,800,295-byte request) that the new code classifies; no regression on aligned traffic.
9. **Modern Kafka api_versions rejected in framing** — the same real-broker strace showed Kafka 4.0 negotiating Produce v12 / Metadata v13 / ListOffsets v10, above the `APIVersionMap` caps (11/12/9), so `FindFrameBoundary`→`IsSupportedAPIVersion` rejected the most common operations. Bumped the three maxes to the verified versions.

## Test status (all re-run locally on this branch)

| Test | Result |
|---|---|
| Kafka-mode selftest (none/gzip/zstd/lz4/snappy over real TLS) | **ALL PASS** |
| Engine-mode selftest (generic SSLEngine hook, all 5 codecs) | **ALL PASS** |
| Dynamic-attach (agentmain + retransformation into a running, connected broker) | **captures plaintext** through the eBPF uprobe |
| Parser round-trip property (`parse(build)==records`, flex+non-flex, all codecs) | 301,060 checks / 0 failures |
| varint/zigzag full-range round-trip (UBSan) | 12,000,058 checks / 0 failures |
| Functional codec round-trip + Produce-frame parse | 29 / 0 failures |
| Parser fuzz (truncation/byte-flip/random, ASan+UBSan) | clean |
| ABI model property test (PopLocation invariants) | committed; runs in CI (`abi_model_test`) |
| Stirling BPF integration (`//…/bcc_bpf:socket_trace` real clang compile) | builds (see RESEARCH §7) |
| PEM image compile incl. px_jattach Java-agent mode + injection | builds in CI |
| Kafka classification: split / coalesced / high-version reads (`protocol_inference_test`) | **PASS** (runs in CI) |
| End-to-end: split-read Produce exchange → reassembled → decoded `kafka_events` Record (`stitcher_test`) | **PASS** (runs in CI) |
| Modern api_versions accepted by the frame-boundary gate (`parse_test`) | **PASS** (runs in CI) |
| **Real Apache Kafka 4.0 broker** (strace replay of live produce/consume) — old vs new inference | new classifies 3 split Produce reads the old code dropped; **0 regressions** on aligned traffic |

## Not done / known limits

- Full **PEM-image runtime** on a real arm64 kernel, and the **live-cluster
  confirmation** of auto-injection (PEM injecting into a real broker JVM), are
  verified on the cluster — QEMU user-mode can't load eBPF, and the injection path
  exercises namespaces + the Attach API against a real broker. Local validation
  covers codegen (disassembly) + the standalone collector e2e on x86 + the
  dynamic-attach mechanism against a local broker.
- Engine/`both` mode is validated but is opt-in; default stays kafka mode.
- The committed agent jar (~9 MB) is a pragmatic choice; a hermetic Bazel-maven
  build (via `rules_jvm_external`) is the cleaner long-term follow-up.
