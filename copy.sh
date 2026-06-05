#!/bin/bash
set -e

KERNEL_VERSION="v6.13"
LINUX_DIR=$(pwd)/$KERNEL_VERSION
SYZ_DIR=$(pwd)/syzkaller

ADD_DIR=$(pwd)/to_copy_into_vm

docker run -v $LINUX_DIR:/sect/$KERNEL_VERSION sect-kernel-compiler-image bash -c "cd /sect/$KERNEL_VERSION/tools/sched_ext && make"
docker run -v $(pwd):/sect/mnt sect-kernel-compiler-image bash -c "git config --global --add safe.directory /sect/mnt/syzkaller && cd /sect/mnt/syzkaller && make"

cp syzkaller/bin/linux_amd64/* $ADD_DIR

cp $LINUX_DIR/tools/sched_ext/build/bin/scx_serialise  $ADD_DIR
scp -P 10021 -i $(pwd)/bullseye.id_rsa $ADD_DIR/* root@localhost:/root/

