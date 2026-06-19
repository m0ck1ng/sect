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

**Target kernel:** Linux `v6.13-rc4` (other versions require manual adaptation of `build.sh`, and can have breaking changes if the kernel version breaks API compatibility)

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
./syzkaller/bin/syz-manager -config configs/syzkaller.cfg.example
```

Dashboard available at `http://0.0.0.0:56741`.

## Running Individual Programs

To run the SECT scheduler outside of a fuzzing campaign for bug reproduction, first ensure that you have run `./build.sh` as described above.

1. Next, you can stand up a VM running the target kernel with `./run_qemu.sh` (login is `root`)
2. Then, copy all relevant files into the VM with `./copy.sh`
3. Once the files have been copied, *in another terminal window* SSH into the guest with `ssh -p 10021 -i ./bullseye.id_rsa root@localhost`

At this point, you should have two terminal windows open inside the VM

4. In one window, run `./scx_serialise -r 2` to start the SECT scheduler with the random walk algorithm
5. In the *other window* run `./syz-execprog -procs 2 -repeat 1000 ./benchmarks/CVE-2023-31083/repro.prog` to execute the CVE-2023-31083 program 1000 times
6. After running a program, be sure to un-load the scheduler via Ctrl-C in the first window before running on another program

These steps can be repeated with different Syzkaller programs and algorithms. 

### Usage

```
Usage: scx_serialise [-n NUM_THREADS] [-d DEPTH] [-r ALGO]

  -n NUM   Threads expected in each syz-executor cycle (default: 2).
  -d DEPTH PCT search depth (default: 3).
  -r ALGO  Scheduling algorithm:
             1 = Random Priority
             2 = Random Walk
             3 = PCT (default)
             4 = POS
  -h       Display this help and exit.
```

## Benchmark

The benchmark used in the evaluation of the paper is represented as a single patch file which can be applied to `v6.13-rc4` of the Linux kernel.

This patch is *already applied by default* by the build.sh script.
Application of this patch can be disabled by editing the corresponding environment variable to `APPLY_BENCH_PATCH=0`
