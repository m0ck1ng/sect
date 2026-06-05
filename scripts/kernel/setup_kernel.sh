#!/bin/bash
set -e

PASS_PATH="${PASS_PATH:-$(pwd)/sched_points/build/libInjectSchedPoint.so}"

TAG="${1:-HEAD}"
if [ $TAG = "HEAD" ]; then
	git clone --depth 1 https://github.com/torvalds/linux.git $TAG
	cd $TAG
	COMMIT=$(git rev-parse --short HEAD)
	cd ..
	mv $TAG linux-upstream-$COMMIT
	TAG=linux-upstream-$COMMIT
else
	git clone --branch $TAG --depth 1 https://github.com/torvalds/linux.git $TAG
fi

cd $TAG
git checkout -- .
git clean -f

cp ../scripts/kernel/KCONFIG.config .config
cp ../scripts/kernel/compile.sh .

PREPEND=$(cat <<- DELIM
	# add debug info
	KBUILD_CFLAGS += -g
	# generate bitcode
	KBUILD_CFLAGS += -save-temps=obj
DELIM
)

echo "$PREPEND" > Makefile.tmp
echo "" >> Makefile.tmp
cat Makefile >> Makefile.tmp
mv Makefile.tmp Makefile

echo "KBUILD_CFLAGS += -fpass-plugin=$PASS_PATH" >> fs/Makefile
echo "KBUILD_CFLAGS += -fpass-plugin=$PASS_PATH" >> io_uring/Makefile
echo "KBUILD_CFLAGS += -fpass-plugin=$PASS_PATH" >> drivers/Makefile
echo "KBUILD_CFLAGS += -fpass-plugin=$PASS_PATH" >> net/Makefile

sed -i 's/c-sched-targets = .*/c-sched-targets = scx_serialise/' tools/sched_ext/Makefile 

cat ../instrumentation/func.append >> kernel/sched/core.c
echo "void check_preempt_and_yield(void* addr, bool is_write, u64 id);" >> kernel/sched/sched.h

cp -r ../scheduler/* tools/sched_ext
