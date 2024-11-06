# Build Linux kernel into Bitcode

## Modify Makefile

Update additional build flags for kernel Makefile.
```bash
# add debug info
KBUILD_CFLAGS += -g
# generate bitcode
KBUILD_CFLAGS += -save-temps=obj
```

## Compile kernel with LLVM
```
make CC=clang defconfig
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

## Run LLVM passes with opt
```bash
opt -load-pass-plugin=PATH_TO_PASS -passes=PASS_NAME -disable-output -S target.bc
```

    