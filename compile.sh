

make 3rdparty/clean
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- CC=arm-linux-gnueabi-gcc 3rdparty/compile




make NO_BTF=1 NO_GLOBAL_DATA=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc install


# x86
make 3rdparty/clean
make 3rdparty/compile
make NO_BTF=1 NO_GLOBAL_DATA=1 ARCH=x86 install
make NO_GLOBAL_DATA=1 ARCH=x86 install

# with my own headers from btf
make NO_BTF=1 NO_GLOBAL_DATA=1 BPF_MAKE_HEADERS=1 KERNEL=/home/anlan/Desktop/nettrace_d/src/progs/kheaders/x86 ARCH=x86 install

# with kernel debug
make NO_BTF=1 NO_GLOBAL_DATA=1 BPF_MAKE_HEADERS=1 KERNEL=/home/anlan/Desktop/nettrace_d/src/progs/kheaders/x86 ARCH=x86 BPF_DEBUG=1 install

clang -O2 -S -Wall -fno-asynchronous-unwind-tables		\
    -Wno-incompatible-pointer-types-discards-qualifiers		\
    progs/kprobe.c -emit-llvm -Wno-unknown-attributes -I./ -I/home/anlan/Desktop/nettrace_d/shared/bpf/ -I/home/anlan/Desktop/nettrace_d/3rdparty/install/x86/include -g -DBPF_MAKE_HEADERS -DBPF_NO_GLOBAL_DATA -DNO_BTF -DBPF_DEBUG -D__F_STACK_TRACE -D__F_NFT_NAME_ARRAY -D__KERN_VER=6.8.0 -D__KERN_MAJOR=6 -Wno-unused-function -Wno-compare-distinct-pointer-types -Wuninitialized -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/11/include  -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-frame-address -D__F_SK_PRPTOCOL_LEGACY -Xclang	\
    -disable-llvm-passes -o - | 					\
    opt -O2 -mtriple=bpf-pc-linux | 				\
    llvm-dis |							\
    llc -march=bpf -filetype=obj -o progs/kprobe.o

# compile with -E for define
clang -O2 -E -Wall -fno-asynchronous-unwind-tables		\
    -Wno-incompatible-pointer-types-discards-qualifiers		\
    progs/kprobe.c -emit-llvm -Wno-unknown-attributes -I./ -I/home/anlan/Desktop/nettrace_d/shared/bpf/ -I/home/anlan/Desktop/nettrace_d/3rdparty/install/x86/include -g -DBPF_MAKE_HEADERS -DBPF_NO_GLOBAL_DATA -DNO_BTF -DBPF_DEBUG -D__F_STACK_TRACE -D__F_NFT_NAME_ARRAY -D__KERN_VER=6.8.0 -D__KERN_MAJOR=6 -Wno-unused-function -Wno-compare-distinct-pointer-types -Wuninitialized -D__TARGET_ARCH_x86 -DBPF_NO_PRESERVE_ACCESS_INDEX -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/11/include  -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-frame-address -D__F_SK_PRPTOCOL_LEGACY -Xclang	\
    -disable-llvm-passes -o kprobe.i



# arm64
make 3rdparty/clean
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc 3rdparty/compile

make NO_BTF=1 NO_GLOBAL_DATA=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc KERNEL=/home/anlan/Desktop/perf/linux-6.6.23 install





# kernel
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig

make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- menuconfig

make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-



# build with docker
sudo docker run -d -it --name arm64 --network host -v $(pwd):$(pwd) --platform linux/arm64 arm64_env tail -f /dev/null


###### tools
# bpftool
make check_feat=0 EXTRA_LDFLAGS="-L../../../3rdparty/install/x86/lib --static"

make check_feat=0 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc EXTRA_LDFLAGS="-L../../../3rdparty/install/arm64/lib --static"

make check_feat=0 CROSS_COMPILE=arm-linux-gnueabi- CC=arm-linux-gnueabi-gcc EXTRA_LDFLAGS="-L../../../3rdparty/install/arm/lib --static"

# display bpf_printk message
sudo bpftool prog tracelog


