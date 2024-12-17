# customize kernel config here
V=17
make CC=clang-$V olddefconfig
make CC=clang-$V \
    LD=ld.lld-$V \
    AR=llvm-ar-$V \
    NM=llvm-nm-$V \
    STRIP=llvm-strip-$V \
    OBJCOPY=llvm-objcopy-$V \
    OBJDUMP=llvm-objdump-$V \
    READELF=llvm-readelf-$V \
    HOSTCC=clang-$V \
    HOSTCXX=clang++-$V \
    HOSTAR=llvm-ar-$V \
    HOSTLD=ld.lld-$V \
    V=0 \
    -j 10 2>&1 | tee build_log.txt
