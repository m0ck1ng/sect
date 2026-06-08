# SECT — Sched-Ext Concurrency Tester

SECT systematically tests concurrency bugs in the Linux kernel by serializing kernel execution at fine-grained scheduling points injected via an LLVM pass, then controlling thread interleaving through the `sched_ext` (SCX) eBPF framework.

## Repository Layout

```
.
├── instrumentation/       # LLVM pass — injects scheduling points into kernel code
├── scheduler/             # SECT eBPF scheduler (sched_ext)
├── scripts/
│   ├── kernel/            # Kernel setup (setup_kernel.sh, compile.sh, KCONFIG.config)
│   ├── triage/            # Syzbot bug report fetching and caching
│   └── analysis/          # Experiment result plotting
├── benchmarks/            # 10 known kernel concurrency bugs with reproducers
├── configs/               # Example configuration files
├── syzkaller/             # SECT fork of syzkaller (patched for SCHED_EXT)
├── ./build.sh             # Script which fully builds SECT, the target kernel, and all dependencies in a Docker environment
├── ./copy.sh              # Script to copy files from the host system to a live running guest instance VM; useful for quick iteration during development
└── Dockerfile             # Dockerfile for the build environment used by build.sh
```

See [`instrumentation/README.md`](instrumentation/README.md) for LLVM pass build details, and [`benchmarks/README.md`](benchmarks/README.md) for the full bug list.

## Prerequisites

- Docker
- debootsrap (installed via `apt` by `./build.sh`)
- QEMU with KVM support (installed via `apt` by `./build.sh`)


If you want to build SECT outside of the docker environment, you will need:
- Clang/LLVM 16 (`clang-16`, `ld.lld-16`, `llvm-ar-16`, etc.) -- for the SECT LLVM instrumentation pass
- CMake ≥ 3.13 -- for the SECT LLVM instrumentation pass
- Standard kernel build deps — installed automatically by `compile.sh`:
  `build-essential bc flex bison libssl-dev libelf-dev libncurses-dev dwarves pahole`

**Target kernel:** Linux `v6.18` (other versions require manual adaptation of `build.sh`, and can have breaking changes if the kernel version breaks API compatibility)

## Getting Started

```bash
./build.sh
```

This script...
1. Sets up the target kernel and SECT instrumentation (via `scripts/kernel/setup_kernel.sh`)
2. Creates the docker image used for compilation of the target kernel and SECT
3. Compiles the target kernel with SECT instrumentation (via `scripts/kernel/compile.sh`)
4. Creates a disk image on which to run a fuzzing instance (via `tools/syzkaller/create_image.sh`)
5. Compiles the SECT eBPF scheduler
6. Compiles the SECT-syzkaller program used for concurrency fuzzing
7. Fills in templated values to run SECT fuzzing campaigns via `syz-manager`

Of these steps, only steps 2, 4, and 7 are run on the host system. 
All others will be run inside of a docker container via a mounted volume to avoid issues with mismatched dependency versions.


To run SECT, simply do:

```bash
syz-manager -config configs/syzkaller.cfg.example
```

Dashboard available at `http://0.0.0.0:56741`.
