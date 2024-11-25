# Build Linux kernel into Bitcode

## Make kernel patch

Update additional build flags for kernel Makefile.
```Makefile
# add debug info
KBUILD_CFLAGS += -g
# generate bitcode
KBUILD_CFLAGS += -save-temps=obj
```

Patch the kernel file `kernel\schd\core.c`
```C
void check_preempt_and_yield(void) {
    if (current->policy == SCHED_EXT && 
		get_current_state() == TASK_RUNNING &&
		 !current->non_block_count &&
		!is_idle_task(current) &&
		!current->non_block_count &&
		preempt_count() == 0 &&
		!irqs_disabled() &&
		(rcu_preempt_depth() << MIGHT_RESCHED_RCU_SHIFT) == 0 ) {
        // printk(KERN_EMERG "Preemption is enabled; yielding.\n");
		// DO NOT USE `schedule()` here as it may lead to dangeous sleep state.
        yield();
    }
}
EXPORT_SYMBOL(check_preempt_and_yield);
```

## Compile kernel with LLVM
```bash
make CC=clang defconfig
# customize kernel config here
make CC=clang olddefconfig
make CC=clang \
    LD=ld.lld \
    AR=llvm-ar \
    NM=llvm-nm \
    STRIP=llvm-strip \
    OBJCOPY=llvm-objcopy \
    OBJDUMP=llvm-objdump \
    READELF=llvm-readelf \
    HOSTCC=clang \
    HOSTCXX=clang++ \
    HOSTAR=llvm-ar \
    HOSTLD=ld.lld \
    V=0 \
    -j"$(nproc)"
```

## Link the vmlinux.bc (optional)
This is an optional step. 
```bash
llvm-link-16 -o vmlinux.bc $(find . -type f -name "*.bc")
```

## Compile LLVM passes
```bash
cmake -DLLVM_ENABLE_ASSERTIONS=ON -DCMAKE_BUILD_TYPE=Debug -B build 
```

## Run LLVM passes with opt (debug)
```bash
opt -load-pass-plugin=PATH_TO_PASS -passes=PASS_NAME -disable-output -S target.bc
```

When debugging the pass, use the environment variable `LLVM_DEBUG=1`.

## Run LLVM passes with Clang pipeline
Update additional build flags for kernel Makefile.

This is the legacy style for invoking passes.
```bash
clang -Xclang -load -Xclang "/home/pass/Meminstr/build/libInjectSchedPoint.so"
```

This is the latest style for invoking passes.
```bash
clang -fpass-plugin=/home/pass/Meminstr/build/libInjectSchedPoint.so
```

Patch the makefile of targeted modules (drivers, net, io_uring, fs, ipc).
```Makefile
KBUILD_CFLAGS += -fpass-plugin=/home/pass/Meminstr/build/libInjectSchedPoint.so
```