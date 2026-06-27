## Segfuzz Setup

### Prerequisite

Command:
```
apt install make gcc g++ flex bison libncurses-dev libelf-dev libssl-dev python3 curl wget bzip2 xz-utils libcapstone-dev build-essential git
git clone https://github.com/casys-kaist/segfuzz.git
```

### Apply patch 

Command in Segfuzz directory:
```
cd segfuzz && git checkout e44fe05 && git apply segfuzz.patch
```

### Build

Command:
```
cd segfuzz/scripts
source envsetup.sh
./install.sh
```

Manually execute commands if LLVM build fails:
```
cd segfuzz/toolchain/llvm
git checkout llvmorg-12.0.1
git am ../../scripts/llvm/patch/*
```

After this, re-run `install.sh`.
