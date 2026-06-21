# Bazel + remote-cache CI performance notes (hard-won, non-obvious)

Context: tuning `.github/workflows/arm64-dynamic-tracing-fix.yaml` — building & pushing the
multiarch PEM image on free 4‑vCPU GitHub runners, inside the `dev_image_with_extras` container,
with a shared **BuildBuddy remote cache** (`grpcs://remote.buildbuddy.io`) in front of a local
`--disk_cache`. Bazel 7.7.1, **WORKSPACE** mode (`--noenable_bzlmod`), `rules_docker`.

These are the things that surprised us, measured against real run logs. They are deliberately the
*counter-intuitive* findings — not a rehash of the Bazel docs. Numbers are from an actual run
(per-arch PEM job, x86_64): `INFO: Elapsed time: 289.763s, Critical Path: 12.09s. 5315 processes:
4039 remote cache hit, 1274 internal`.

## 1. The build is overhead-bound, not compute-bound — and `Critical Path` hides it
Once the remote cache is warm, ~99.96% of actions are cache hits; only **2** of 5315 actions
compile/link locally. Bazel's `Critical Path: 12.09s` is the *compute* dependency chain — but the
job's Bazel invocation took **~290s**. The gap is **not CPU**; it is I/O: ~43s cold Bazel server +
WORKSPACE/repository-rule eval, ~54s analysis (609 packages, 53,830 targets configured for a single
target), and ~191s of the execution phase spent **downloading cached outputs over the network**.
Takeaway: when optimizing a cache-hit-heavy Bazel build, ignore `Critical Path`; look at elapsed
vs. critical-path delta and at "Downloading …; remote-cache" log lines.

## 2. `run --remote_download_outputs=all` silently overrides `build --remote_download_minimal`
The single biggest cost was a one-line policy bug. The image is shipped with `bazel **run**
//k8s/vizier:pem_image_push`, and the repo `.bazelrc` had `run --remote_download_outputs=all`.
**rc precedence is by command specificity, not file/import order** — the `run`‑command option beats
*any* `build`‑command option (including a `build --remote_download_minimal` imported later from
`.bazelrc.local`). Result: Bazel hydrated **all ~5300 action outputs** (~158 MB of intermediate
`.o`/`.a` and every layer tar) to the runner before the actual push — which is **0.5s**.
- Fix: pass `--remote_download_outputs=toplevel` on the `bazel run` command line (CLI beats every rc
  file). Downloads only the final image (the push runfiles), skipping the thousands of intermediates.
- Bazel even prints `WARNING: --remote_download_outputs was expanded from both …` — but it only names
  the two *build*-level flags, hiding that the *run*-level `=all` is the one actually winning. The
  warning is a misleading red herring.
- ~100–170s saved **per arch**, on both cold and warm-disk runs (warm disk caches action *results*,
  not the output *materialization*, which a fresh `--output_base` repeats every run).

## 3. disk_cache (L1) + remote cache (L2): keep both; understand what each does NOT do
- A **warm disk_cache only saved ~2 min** (9m20s → 7m19s) because it removes per-action remote RTT
  for *lookups*, but the `outputs=all` policy still re-downloads/materializes outputs into the fresh
  `--output_base` every run. Fixing the download policy matters far more than warming L1.
- On a remote **cache hit**, layer-assembly/link actions still run **locally** (we use remote *cache*,
  not remote *execution*), so their inputs get force-downloaded — another reason `outputs=all` hurts.
- `--jobs` defaults to `auto` (≈ vCPUs ≈ 4). For a cache-hit-heavy build the actions are
  **network-bound**, so `--jobs` should be *much* greater than the core count (we use `--jobs=50`).
  `--remote_max_connections` (default 100) is not the limiter here; `--jobs` is.
- Good remote flags can hide in an rc config the workflow never activates: Pixie's `ci/github/bazelrc`
  (`--jobs=100`, `--remote_max_connections=128`) is only imported by Pixie's own CI's generated
  `github.bazelrc`, not by an ad-hoc workflow that writes `.bazelrc.local`. Check which rc files your
  command actually reads (`bazel ... --announce_rc`).

## 4. GitHub-hosted-runner container & cache gotchas
- **A 2-second `crane index append` cost 97s** purely because the job used a `container:` whose image
  had to be pulled to get `crane`. The dev-image pull is **extraction-bound** (layers download in ~7s;
  decompress+untar of the big rootfs layer is ~67s on 4 vCPU), so mirrors/pre-pull don't help — only a
  *smaller* image, or **no container at all**. crane/cosign are single static binaries; install them
  on a bare runner via `https://github.com/<org>/<repo>/releases/latest/download/<asset>` (the
  `latest/download` redirect needs no version pin; asset names are stable).
- The hosted-runner Docker image cache is **never reused across jobs** (each job = fresh ephemeral VM
  that re-pulls the `container:` image). `type=gha`/registry build caches only accelerate
  `docker build`, not the job-container pull. No setting changes this.
- `actions/cache` **save** is ~50s of `tar` (scales with *uncompressed* cache size, ~12 GB here → a
  ~590 MB artifact), not upload — and it runs on **every job, every branch**, after the build. The
  slowest build job's save sits **directly on the critical path** (a dependent assemble job waits on
  it 1:1). Consider restore-only on feature branches and save only on the seeding/default branch.
- Feature branches can restore caches created on the **default branch** (but not sibling branches),
  so seeding the cache from `main` + a scheduled run keeps feature-branch cold-starts warm.

## 5. Low-level compiler/linker: the usual "speed-ups" are traps with a remote cache
Pixie already uses `lld` (`-fuse-ld=lld`), `-O2 -g0 -ffunction-sections -fdata-sections`,
`-Wl,--gc-sections` at opt. What we learned **not** to add:
- **Do not enable ThinLTO.** It adds backend codegen to the *cold* critical path, caches poorly under
  header churn, and trips Bazel issue #26955 (`Missing digest … .o.imports`) where LTO index inputs
  aren't covered by remote-cache eviction retries → **hard build failures on a shared/GC'd cache**.
  Warm benefit here: zero. This is the opposite of the usual "LTO = faster" intuition.
- **Do not go `-O3`.** Slower compiles, bigger code/downloads, may trip `-Werror`, and rewrites every
  C++ command line → one full cold rebuild + cache re-population for ~no runtime gain in this code.
- **Do not unity/jumbo-build.** It coarsens cache granularity (a one-line edit invalidates a huge TU)
  and serializes cold compiles — exactly wrong when a remote cache makes fine-grained actions cheap.
- **`-Werror` is global on first-party code**, so *any* warning-introducing flag is a build-breaker.
  Treat "harmless" codegen tweaks as high-risk.

## 6. Cache-hit determinism is worth more than codegen flags
The shared cache only pays off if action keys match across machines/runs.
- `__DATE__/__TIME__/__TIMESTAMP__` are already redacted and `-no-canonical-prefixes` is set — good.
- **Beware `-ffile-prefix-map` "for reproducibility":** it moves path-dependence *into the command
  line*, which can *lower* a distributed-cache hit rate. With a fixed `--output_base` it is unneeded.
- **Inject CI-only copts carefully:** a CI-only `build:clang --copt=-g0` changes the command line vs.
  a developer's build → different action key → the shared cache silently *splits*. Keep the opt
  command line byte-identical across dev and CI, or scope such flags so both sides agree.

## 7. The image build/push is already optimal — don't "fix" it
- `cc_image` puts the PEM binary in its **own top layer**, with bpf/proto/deb/distroless as separate
  lower layers. `container_push` does blob-existence (HEAD) checks, so unchanged layers are skipped —
  that's why the real push is **0.5s** and the tail is *not* re-uploading layers GHCR already has.
- `format=Docker` vs OCI: no push-speed difference. gzip vs zstd: needs `rules_oci` and isn't the
  bottleneck. `crane index append` (~2s) is already minimal manifest surgery.
- `rules_docker` is archived, but its deprecation does **not** limit push speed here. Migrating to
  `rules_oci` is a large project with ~no payoff for *this* bottleneck — don't.

## 8. Measured timeline (per-arch PEM job, free 4-vCPU runner, warm remote cache)
| phase | time | cacheable across runs? |
|------|------|------------------------|
| cold Bazel server + WORKSPACE/repo-rule eval | ~43s | partially (`--repository_cache`) |
| analysis (609 pkgs, 53,830 targets) | ~54s | no (fresh `--output_base` each run) |
| execution — almost entirely cache-output downloads | ~191s | **this is what `outputs=toplevel` kills** |
| actual GHCR push | **0.5s** | n/a |
| `actions/cache` save (post-job, on critical path) | ~50s | n/a |
| dev-image pull (per job; assemble's was pure waste) | ~75–85s | no (not reused across jobs) |

## 9. Future levers (not yet applied)
- **Bazel 8.7+/9.1**: `--experimental_remote_cache_chunking` (~40% less upload). N/A on 7.7.1.
- **Persist `--repository_cache` on /mnt via a second `actions/cache`** to shave the ~43s repo phase.
- **`--experimental_merged_skyframe_analysis_execution`** (Skymeld) to overlap the ~54s analysis with
  execution — smoke-test first; `rules_docker` is aspect-heavy.
- **Remote *execution* (`--config=remote`)** would keep layer bytes off the runner entirely, but
  requires the cross `_sysroot` toolchains to work under RBE — treat as an experiment.

Sources: Bazel rc precedence & BwoB docs (bazel.build/run/bazelrc, /remote/cache-remote),
BuildBuddy docs, rules_docker issue #282 (blob-existence), Bazel issue #26955 (LTO + remote cache),
go-containerregistry/crane README. Evidence: the run logs analyzed in this repo's CI history.
