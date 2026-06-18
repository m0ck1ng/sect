#!/bin/bash
set -e

KERNEL_VERSION="v6.13-rc4"
LINUX_DIR=$(pwd)/$KERNEL_VERSION
SYZ_DIR=$(pwd)/syzkaller

ADD_DIR=$(pwd)/to_copy_into_vm
mkdir -p $ADD_DIR

# Rebuild scheduler for active development
docker run -v $LINUX_DIR:/sect/$KERNEL_VERSION sect-kernel-compiler-image bash -c "cd /sect/$KERNEL_VERSION/tools/sched_ext && make"

cp syzkaller/bin/linux_amd64/* $ADD_DIR
cp -r benchmarks/ $ADD_DIR

cp $LINUX_DIR/tools/sched_ext/build/bin/scx_serialise  $ADD_DIR
scp -P 10021 -r -i $(pwd)/bullseye.id_rsa $ADD_DIR/* root@localhost:/root/

