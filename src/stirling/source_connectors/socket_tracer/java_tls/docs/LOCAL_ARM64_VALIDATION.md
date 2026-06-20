# Local validation (no cluster) — arm64 / x86_64

How to build, run, and test the arm64-sensitive parts of this work on a single
x86_64 box, using Docker + QEMU user emulation. None of this needs a Kubernetes
cluster or a real Graviton node; the heavier end-to-end (eBPF actually loading on
an arm64 kernel) still needs a real arm64 host, and that limit is called out below.

## Prerequisites (one-time, on an x86_64 host)
```bash
# Docker daemon
dockerd &                     # or: service docker start

# QEMU user-mode emulation for running arm64 binaries/containers via binfmt
docker run --privileged --rm tonistiigi/binfmt --install arm64
docker run --rm --platform linux/arm64 arm64v8/alpine uname -m   # -> aarch64

# clang + libbpf for compiling the eBPF collector
apt-get install -y clang libbpf-dev libelf-dev \
                   zlib1g-dev libzstd-dev libsnappy-dev liblz4-1
```

## 1. JSSE eBPF collector — compile for both arches and verify the uprobe regs
The uprobe reads the arguments of `pixie_jsse_plaintext(fd, dir, buf, len)` out of
`pt_regs`. Those registers are architecture-specific (x86-64: RDI/RSI/RDX/RCX;
arm64: X0–X3 == `regs[0..3]`). Compile the object for each target and disassemble
the argument loads:
```bash
cd collector
clang -O2 -g -target bpf -D__TARGET_ARCH_x86   -I/usr/include/x86_64-linux-gnu \
      -c jsse_collector.bpf.c -o /tmp/x86.o
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I/usr/include/x86_64-linux-gnu \
      -c jsse_collector.bpf.c -o /tmp/arm64.o
llvm-objdump -d /tmp/x86.o   | grep -oE '\(u64 \*\)\(r1 \+ 0x[0-9a-f]+\)'   # 0x70/0x68/0x60/0x58 (di/si/dx/cx)
llvm-objdump -d /tmp/arm64.o | grep -oE '\(u64 \*\)\(r1 \+ 0x[0-9a-f]+\)'   # 0x0/0x8/0x10/0x18  (regs[0..3])
```
Expected: x86 loads the SysV arg registers; arm64 loads `X0..X3`. (Before the fix,
the arm64 build still loaded `0x70/0x68/0x60/0x58`, i.e. X14/X13/X12/X11 — garbage.)

## 2. Full collector build (auto-detects host arch)
```bash
cd collector && ./build.sh        # picks -D__TARGET_ARCH_<arch> + lib paths from `uname -m`
```

## 3. Dynamic-tracer ABI model — run the *real* code on emulated arm64
`obj_tools/abi_model.cc` selects Go/AAPCS64 register tables by `__aarch64__`. To
execute that arm64 branch without a Bazel cross-build, compile the real file inside
a multiarch `gcc` image under QEMU, against a tiny shim for the umbrella header, and
run a harness that mirrors `abi_model_test`:
```bash
# in a scratch dir holding: src/common/base/base.h (shim), the real
# src/stirling/obj_tools/abi_model.{h,cc}, and a test_main.cc oracle
docker run --rm --platform linux/arm64 -v "$PWD":/w -w /w gcc:13 \
  bash -c 'g++ -std=c++17 -I /w /w/src/stirling/obj_tools/abi_model.cc /w/test_main.cc -o /tmp/t && /tmp/t'
# also compile/run natively for the amd64 (#else) branch:
g++ -std=c++17 -I . src/stirling/obj_tools/abi_model.cc test_main.cc -o t && ./t
```
The oracle asserts the exact register/offset/spill results (int args, float args,
return values incl. the SysV hidden-return-pointer) for both architectures.

## 4. pt_regs field reproduction (the original "ctx->ax" failure)
```bash
echo 'int f(struct user_pt_regs*c){unsigned long a[16];for(int i=0;i<16;i++)a[i]=c->regs[i];return a[0];}' \
  | cat <(echo '#include <asm/ptrace.h>') - > /tmp/fix.c
docker run --rm --platform linux/arm64 -v /tmp:/t gcc:13 gcc -c /t/fix.c -o /t/fix.o   # OK on arm64
# the pre-fix `c->ax` instead fails: 'struct user_pt_regs' has no member named 'ax'
```

## 5. Run the published PEM image under QEMU
```bash
IMG=ghcr.io/<fork>/vizier-pem_image:<tag>          # multiarch (amd64 + arm64)
docker manifest inspect "$IMG" | grep architecture # confirm an arm64 entry exists
docker pull --platform linux/arm64 "$IMG"
PEM=/app/src/vizier/services/agent/pem/pem
docker run --rm --platform linux/arm64 --entrypoint "$PEM" "$IMG" --help     # runs under qemu
```
Limitation: QEMU *user* emulation runs the arm64 binary but cannot load eBPF (that
needs a real arm64 kernel). So this confirms the cross-built binary is a working
aarch64 executable; codegen/ABI *correctness* is covered by steps 1–4. Full uprobe
runtime is verified on a real arm64 node (or a qemu-system VM with an arm64 kernel).

## 6. Bazel tests under QEMU (when network/deps are available)
The tree already wires a qemu test runner:
`bazel test --config=aarch64_sysroot //src/stirling/obj_tools:abi_model_test ...`
cross-compiles and runs the test under qemu via `bazel/test_runners/sysroot_chroot`.
This needs the Bazel dependency downloads to succeed (a proxy/CA that the build
trusts); where that is unavailable, steps 1–4 give the same coverage offline.
