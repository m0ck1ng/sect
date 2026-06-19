#!/bin/bash
KERNEL_VERSION="v6.13-rc4"
LINUX_DIR=$(pwd)/$KERNEL_VERSION
IMAGE_DIR="."
DEBIAN_VERSION="bullseye"

sudo qemu-system-x86_64 \
    -m 8G \
    -smp 6 \
    -kernel $LINUX_DIR/arch/x86/boot/bzImage \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file=$IMAGE_DIR/$DEBIAN_VERSION.img,format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
    -net nic,model=e1000 \
    -nographic \
    -snapshot \
    -enable-kvm
