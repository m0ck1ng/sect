# SECT (Sched-Ext Concurrency Tester)
 
This repository contains the artifact for SECT, a tool which serializes OS or application execution using eBPF for testing.

## Layout
The layout of this repo is as follows:

1. `sched_points/` -- the LLVM instrumentation pass for injecting additional scheduling points into the kernel
2. `scripts/` -- scripts used for bug triage and data-analysis of experiments
3. `scx_scheduler/` -- the SECT scheduler eBPF program, including several scheduling algorithm implementations
4. `syzkaller/` -- the SECT fork of syzkaller, with modifications to increase the amount of programs generated during fuzzing which have concurrent behaviors

## Usage


To get started with SECT, you can use the `./setup_kernel.sh <TAG>` script, with the git branch as the <TAG>.
Note that this script may break on kernel versions other than `v6.13`, but it should be relatively easy to manually extrapolate the changes to other kernel versions by reading the script itself.
At a high level, this script:

1. Clones the selected branch of the Linux kernel
2. Copies the KCONFIG we use for SECT into that kernel
3. Adds some CFLAGS to various Makefiles
4. Adds our LLVM instrumentation as a pass for various modules
5. Copies the SECT scheduler eBPF program into the target kernel

Once the target kernel has been set up, it can be compiled via the `./compile.sh` script, which should be copied into the root directory of that kernel. Note that before compiling the target kernel, you should compile the LLVM pass in the `./sched_points` directory, with the following command:

```
cmake -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Debug -B build; cd build; make
```

Once the kernel has been compiled, you can create a disk images with e.g. `syzkaller/tools
/create-image.sh` and run it in QEMU with something like:

```
sudo qemu-system-x86_64 \
    -m 8G \
    -smp 6 \
    -kernel $LINUX_DIR/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=$IMAGE_DIR/bookworm.img,format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:$((10021+$i))-:22 \
    -net nic,model=e1000 \
    -snapshot \
    -enable-kvm \
    -nographic
```

Note that the port forwarding is to allow copying the eBPF program via `scp`:

```
scp -P 10021 -i image/bookworm.id_rsa $LINUX_DIR/tools/sched_ext/scx_serialise root@localhost:/root/scx_serialise
```

Inside the VM, to load the serializer scheduling policy, just run `./scx_serialize`.

From a different terminal inside the VM, you can then execute a syzkaller program with `syz-execprog` in the normal way, which we have patched to use the `SCHED_EXT` scheduling policy by default.
