#!/bin/bash
set -e

KERNEL_VERSION="v6.13-rc4"
DEBIAN_VERSION="bullseye"

LINUX_DIR=$(pwd)/$KERNEL_VERSION

sudo apt install -y debootstrap qemu-system

if [ ! -d "$KERNEL_VERSION" ]; then
	PASS_PATH=/sect/instrumentation/build/libInjectSchedPoint.so ./scripts/kernel/setup_kernel.sh $KERNEL_VERSION
fi

docker build -t sect-kernel-compiler-image .
docker run -v $(pwd)/$KERNEL_VERSION:/sect/$KERNEL_VERSION -w /sect/$KERNEL_VERSION sect-kernel-compiler-image ./compile.sh

if [ ! -f "$DEBIAN_VERSION.img" ]; then
	./syzkaller/tools/create-image.sh
fi

docker run -v $LINUX_DIR:/sect/$KERNEL_VERSION sect-kernel-compiler-image bash -c "cd /sect/$KERNEL_VERSION/tools/sched_ext && make"
docker run -v $(pwd):/sect/mnt sect-kernel-compiler-image bash -c "git config --global --add safe.directory /sect/mnt && cd /sect/mnt/syzkaller && make"


sed -i "s|IMAGE_PATH|./${DEBIAN_VERSION}.img|g" configs/syzkaller.cfg.example
sed -i "s|IMAGE_KEY_PATH|./${DEBIAN_VERSION}.id_rsa|g" configs/syzkaller.cfg.example
sed -i "s|SCHED_BIN_PATH|${LINUX_DIR}/tools/sched_ext/build/bin/scx_serialise|g" configs/syzkaller.cfg.example
sed -i "s|KERNEL_PATH|${LINUX_DIR}/arch/x86_64/boot/bzImage|g" configs/syzkaller.cfg.example
sed -i "s|KERNEL_VER|${KERNEL_VERSION}|g" configs/syzkaller.cfg.example
 
