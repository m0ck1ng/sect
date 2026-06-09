#!/bin/bash
set -e

apt install -y \
  build-essential \
  bc \
  flex \
  bison \
  libssl-dev \
  libelf-dev \
  libncurses-dev \
  libudev-dev \
  libpci-dev \
  libiberty-dev \
  python3 \
  rsync \
  zstd



# note clang must be installed manually
V=16
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
    KCFLAGS="-g" \
    V=0 \
    -j 10
