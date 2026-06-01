# SECT — Sched-Ext Concurrency Tester

SECT is a tool for systematically testing concurrency bugs in the Linux kernel. It serializes kernel execution at fine-grained scheduling points injected by an LLVM pass, then drives the resulting deterministic scheduler via the kernel's `sched_ext` (SCX) framework and eBPF. This controlled interleaving enables reproducible triggering of race conditions that are otherwise timing-dependent.

## Repository Layout

```
.
├── instrumentation/       # LLVM pass — injects scheduling points into kernel code
├── scheduler/             # SECT eBPF scheduler (sched_ext)
├── scripts/               # All project scripts
│   ├── kernel/            # Kernel setup and compilation
│   │   ├── setup_kernel.sh    # Patch and configure a kernel source tree
│   │   ├── compile.sh         # Build the instrumented kernel with Clang/LLVM 16
│   │   └── KCONFIG.config     # Kernel .config used for SECT experiments
│   ├── triage/            # Fetch and cache syzbot bug reports
│   └── analysis/          # Plot experiment results
├── benchmarks/            # 10 known kernel concurrency bugs with reproducers
├── configs/               # Example configuration files
│   └── syzkaller.cfg.example  # Sample syzkaller manager config for SECT
└── syzkaller/             # SECT fork of syzkaller (patched for SCHED_EXT)
```

### `instrumentation/`

An LLVM pass (`InjectSchedPoint`) that rewrites kernel bitcode to insert calls to `check_preempt_and_yield()` before every memory access in targeted subsystems (drivers, net, io_uring, fs). This turns ordinary kernel code into a fully cooperative, scheduler-controlled execution model.

- `InjectSchedPoint.pass.cc` — pass implementation
- `func.append` — the `check_preempt_and_yield` function appended to `kernel/sched/core.c`
- `CMakeLists.txt` — pass build configuration

See [`instrumentation/README.md`](instrumentation/README.md) for build details and how to invoke the pass with `opt` or the Clang pipeline.

### `scheduler/`

The userspace + eBPF scheduler loaded into the kernel via `sched_ext`. It intercepts scheduling decisions and implements several interleaving strategies:

| File | Description |
|------|-------------|
| `scx_serialise.bpf.c` | Main eBPF scheduler skeleton |
| `scx_serialise.c` | Userspace loader |
| `scx_algo.bpf.h` | Algorithm dispatch logic |
| `pct.bpf.h` | PCT (Probabilistic Concurrency Testing) |
| `pos.bpf.h` | POS (Partial Order Sampling) |
| `random_priority.bpf.h` | Random-priority interleaving |

### `scripts/`

- **`kernel/setup_kernel.sh`** — clones and patches a Linux kernel tree for use with SECT. Must be run from the project root.
- **`kernel/compile.sh`** — installs build dependencies and compiles the kernel with the full LLVM 16 toolchain. Copied into the kernel root by `setup_kernel.sh`.
- **`kernel/KCONFIG.config`** — the kernel `.config` used for all SECT experiments.
- **`triage/get_data.py`** — queries syzbot and caches results to `current-cache.csv` / `historical.csv` for offline triage.
- **`analysis/plot.py`** — reads experiment CSV output and produces Kaplan-Meier survival curves comparing SECT variants against native execution.

### `benchmarks/`

Ten confirmed concurrency bugs in the Linux kernel, sourced from syzbot and the kernel commit history. Each entry has a fix commit and at least one reproducer (`repro.prog` for syzkaller programs, `repro.c` for standalone C). See [`benchmarks/README.md`](benchmarks/README.md) for the full bug table.

### `configs/`

- **`syzkaller.cfg.example`** — sample syzkaller manager configuration for running SECT. Copy it, adjust the paths to match your environment, and pass it to `syz-manager`:
  ```bash
  cp configs/syzkaller.cfg.example configs/syzkaller.cfg
  # edit configs/syzkaller.cfg
  syz-manager -config configs/syzkaller.cfg
  ```
  Key fields to update: `kernel_obj`, `image`, `sshkey`, `syzkaller`, `scheduler_bin`, and `vm.kernel`.

## Prerequisites

**Host machine**

- Clang/LLVM 16 (`clang-16`, `llvm-ar-16`, `ld.lld-16`, etc.)
- CMake ≥ 3.13
- Standard kernel build dependencies (installed automatically by `compile.sh`):
  `build-essential bc flex bison libssl-dev libelf-dev libncurses-dev dwarves pahole`
- QEMU with KVM support
- Python 3 with `polars`, `lifelines`, `matplotlib`, `seaborn`, `tqdm` (for scripts)

**Target kernel:** Linux `v6.13` (other versions require manual adaptation of `setup_kernel.sh`)

## Getting Started

### 1. Build the LLVM pass

```bash
cd instrumentation
cmake -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Debug -B build
cd build && make
cd ../..
```

The shared library is written to `instrumentation/build/libInjectSchedPoint.so`.

### 2. Set up the kernel source tree

```bash
./scripts/kernel/setup_kernel.sh v6.13
```

This script:
1. Clones the `v6.13` branch of the Linux kernel
2. Copies `KCONFIG.config` as the kernel `.config`
3. Prepends debug and bitcode flags to the top-level `Makefile`
4. Appends the LLVM pass plugin flag to the Makefiles of `fs/`, `io_uring/`, `drivers/`, and `net/`
5. Appends `func.append` to `kernel/sched/core.c`
6. Copies the SCX scheduler sources into `tools/sched_ext/`

To target the latest upstream instead of a tagged branch:

```bash
./scripts/kernel/setup_kernel.sh HEAD
```

### 3. Compile the instrumented kernel

```bash
cd v6.13
./compile.sh
```

`compile.sh` installs build dependencies and invokes `make` with the full LLVM 16 toolchain. Adjust the `-j 10` flag to match your CPU count.

### 4. Create a disk image

Use the helper bundled with the syzkaller fork:

```bash
syzkaller/tools/create-image.sh
```

### 5. Boot the kernel in QEMU

```bash
HOST_PORT=10021
IMAGE_DIR=/path/to/image
LINUX_DIR=/path/to/v6.13

sudo qemu-system-x86_64 \
    -m 8G \
    -smp 6 \
    -kernel $LINUX_DIR/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=$IMAGE_DIR/bookworm.img,format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:$HOST_PORT-:22 \
    -net nic,model=e1000 \
    -snapshot \
    -enable-kvm \
    -nographic
```

### 6. Deploy and load the SECT scheduler

Copy the compiled scheduler binary into the VM:

```bash
scp -P $HOST_PORT -i $IMAGE_DIR/bookworm.id_rsa \
    $LINUX_DIR/tools/sched_ext/scx_serialise \
    root@localhost:/root/scx_serialise
```

Inside the VM, activate the serializing scheduler:

```bash
./scx_serialise
```

### 7. Run a test program

From a second terminal inside the VM, replay a syzkaller reproducer using `syz-execprog` (our patched version defaults to `SCHED_EXT`):

```bash
syz-execprog -executor ./syz-executor benchmarks/CVE-2024-50125/repro.prog
```

## Benchmarks

The `benchmarks/` directory contains reproducers for 10 concurrency bugs spanning networking, filesystems, and VFS. See [`benchmarks/README.md`](benchmarks/README.md) for the full list with fix commits.
