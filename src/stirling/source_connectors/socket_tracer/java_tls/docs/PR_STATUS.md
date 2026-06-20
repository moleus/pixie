# PR status & audit — `arm64-fix`

A map of everything on this branch: what ships, what's dev-only, what's validated,
and what's experimental. Written after a full audit (two independent code reviews +
local re-runs of every test). Scope at time of writing: **~4,400 insertions, 54
files, 32 commits** vs `origin/main`.

TL;DR: **nothing here is stale or dead.** The default path (Kafka-mode capture +
the arm64 dynamic-tracer fix) is validated end-to-end; one piece (the generic
SSLEngine "engine" mode) is opt-in but also validated; three tiny dead/incorrect
items found in audit were removed/fixed.

## What actually ships in the PEM image (the deployable product)

| Area | Lines | Status | Notes |
|---|---|---|---|
| `bcc_bpf/jsse_trace.c`, `socket_trace.c` include, `bcc_bpf_intf/common.h` (`kJavaJSSESource`) | ~200 | **ACTIVE, correct** | The JVM/JSSE uprobe. Uses BCC arch-aware `PT_REGS_PARM*` — arm64-safe. Audit: 0 issues. |
| `uprobe_manager.{cc,h}` (`DeployJavaTLSUProbes`/`AttachJavaTLSUProbes`) | (above) | **ACTIVE, correct** | Mirrors the OpenSSL attach path (FindHostPathForPIDLibs, per-binary dedup, container paths). Audit: 0 issues. |
| `dynamic_tracer/.../code_gen.cc`, `obj_tools/abi_model.{cc,h}` (arm64 register tables) | ~336 | **ACTIVE, correct** | The actual arm64 fix. All arch-specific codegen `#if defined(__aarch64__)`-gated. Includes a real **pre-existing-Pixie UB fix** (empty-deque in SysV hidden-return path). |
| `div_u64` include, perf-profiler, linux_headers, build stubs | ~85 | **ACTIVE, correct** | arm64 kernel ≥6.8 build fixes. |

This is what `kubectl set image ds/vizier-pem` deploys. The audit of all of it found **zero issues**.

## Broker-side instrumentation (required to capture; not in the image)

| Area | Lines | Status |
|---|---|---|
| `agent/` (ByteBuddy Java agent) | ~900 | **ACTIVE** — kafka mode is the proven default; **engine mode** (generic `SSLEngine` hook for any JSSE app) is opt-in via `-Dpixie.jsse.mode=engine`. Both validated (see below). |
| `native/` (JNI bridge + stable trampoline symbol) | ~170 | **ACTIVE** — separate-TU + PLT design is load-bearing (see GOTCHAS §4); arch-agnostic. |

## Dev / test / demo tooling (validates the feature; not in the image)

| Area | Lines | Status |
|---|---|---|
| `collector/` + `kafka_parser.h` (standalone libbpf collector + wire parser) | ~826 | **ACTIVE** — decodes Produce/Fetch incl. Fetch v13+ topic_id and all 4 codecs (exceeds upstream Pixie's parser). Arch-aware. |
| `collector/tests/` (functional, property, varint, fuzz) | ~558 | **ACTIVE** — all pass (numbers below). |
| `scripts/` (run_demo.sh, selftest.sh) | ~190 | **ACTIVE** — `PIXIE_JSSE_MODE` selects kafka/engine/both. |

## CI / build

| Area | Lines | Status |
|---|---|---|
| `.github/workflows/arm64-dynamic-tracing-fix.yaml`, `k8s/vizier` PEM targets | ~266 | **ACTIVE** — per-arch PEM build+push in parallel + `crane` multiarch manifest. Fixed tag mismatch (consistent `${GITHUB_SHA::9}`), dropped redundant arm64 DT cross-compile + stamp relink, added sandbox reuse + disk-cache GC + cache seeding. |

## Docs

`README.md`, `RESEARCH.md`, `GOTCHAS.md`, `docs/LOCAL_ARM64_VALIDATION.md`, this file (~865 lines). All current.

## Bugs found & fixed on this branch

1. **arm64** — demo collector read x86 arg registers (`jsse_collector.bpf.c`); on arm64 those land on X14..X11, not the real args X0–X3. (The shipped eBPF was already safe via BCC macros; this was the dev collector.)
2. **UB** — `kafka_parser.h` `kd_i64` signed-shift overflow. Found by UBSan fuzz.
3. **UB (pre-existing Pixie)** — `SysVABIModel::PopLocation` popped `int_arg_registers_.front()` on an empty deque. Found by property testing.
4. **CI correctness** — multiarch manifest tag mismatch (`MANIFEST_UNKNOWN`) from `git rev-parse --short` length varying with checkout depth; and tests previously filtered out by `--config=bpf`.
5. **Audit cleanups** — removed dead `rd16()` (collector.c) and `isLoaded()` (NativeBridge.java); corrected reversed direction-param docs (code was right: `kEgress=0`/write, `kIngress=1`/read).

## Test status (all re-run locally on this branch)

| Test | Result |
|---|---|
| Kafka-mode selftest (none/gzip/zstd/lz4/snappy over real TLS) | **ALL PASS** |
| Engine-mode selftest (generic SSLEngine hook, all 5 codecs) | **ALL PASS** |
| Parser round-trip property (`parse(build)==records`, flex+non-flex, all codecs) | 301,060 checks / 0 failures |
| varint/zigzag full-range round-trip (UBSan) | 12,000,058 checks / 0 failures |
| Functional codec round-trip + Produce-frame parse | 29 / 0 failures |
| Parser fuzz (truncation/byte-flip/random, ASan+UBSan) | clean |
| ABI model property test (PopLocation invariants) | committed; runs in CI (`abi_model_test`) |

## Not done / known limits

- Full **PEM-image runtime** on a real arm64 kernel is verified on the cluster (QEMU user-mode can't load eBPF); local validation covers codegen (disassembly) + the standalone collector e2e on x86.
- Engine/`both` mode is validated but is opt-in; default stays kafka mode.
</content>
