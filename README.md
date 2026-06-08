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
<<<<<<< HEAD
./scripts/kernel/setup_kernel.sh $VERSION
```

This patches the kernel source with the instrumentation pass and copies the SCX scheduler into `tools/sched_ext/`.

### 3. Compile the instrumented kernel

```bash
cd v6.18.23
./compile.sh   # adjust -j flag as needed
```

### 4. Create a disk image

```bash
syzkaller/tools/create-image.sh
```

### 5. Configure and run syzkaller

```bash
cp configs/syzkaller.cfg.example configs/syzkaller.cfg
```

Edit `configs/syzkaller.cfg` and update `kernel_obj`, `image`, `sshkey`, `syzkaller`, and `vm.kernel` to match your environment.

The **`scheduler_bin`** field is a SECT-specific extension — set it to the path of the compiled `scx_serialise` binary. syzkaller will deploy and load the scheduler in every VM before fuzzing begins.

```bash
syz-manager -config configs/syzkaller.cfg
||||||| parent of cd1e719 (update README)
./scripts/kernel/setup_kernel.sh $VERSION
```

This patches the kernel source with the instrumentation pass and copies the SCX scheduler into `tools/sched_ext/`.

### 3. Compile the instrumented kernel

```bash
cd v6.13-rc4
./compile.sh   # adjust -j flag as needed
```

### 4. Create a disk image

```bash
syzkaller/tools/create-image.sh
```

### 5. Configure and run syzkaller

```bash
cp configs/syzkaller.cfg.example configs/syzkaller.cfg
```

Edit `configs/syzkaller.cfg` and update `kernel_obj`, `image`, `sshkey`, `syzkaller`, and `vm.kernel` to match your environment.

The **`scheduler_bin`** field is a SECT-specific extension — set it to the path of the compiled `scx_serialise` binary. syzkaller will deploy and load the scheduler in every VM before fuzzing begins.

```bash
syz-manager -config configs/syzkaller.cfg
=======
syz-manager -config configs/syzkaller.cfg.example
>>>>>>> cd1e719 (update README)
```

Dashboard available at `http://0.0.0.0:56741`.
