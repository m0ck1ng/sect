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
└── syzkaller/             # SECT fork of syzkaller (patched for SCHED_EXT)
```

See [`instrumentation/README.md`](instrumentation/README.md) for LLVM pass build details, and [`benchmarks/README.md`](benchmarks/README.md) for the full bug list.

## Prerequisites

- Clang/LLVM 16 (`clang-16`, `ld.lld-16`, `llvm-ar-16`, etc.)
- CMake ≥ 3.13
- QEMU with KVM support
- Standard kernel build deps — installed automatically by `compile.sh`:
  `build-essential bc flex bison libssl-dev libelf-dev libncurses-dev dwarves pahole`

**Target kernel:** Linux `v6.18.23` (other versions require manual adaptation of `setup_kernel.sh`)

## Getting Started

### 1. Build the LLVM pass

```bash
cd instrumentation
cmake -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Debug -B build
cd build && make
cd ../..
```

### 2. Set up the kernel source tree

```bash
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
```

Dashboard available at `http://0.0.0.0:56741`.
