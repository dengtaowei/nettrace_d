

make 3rdparty/clean
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- CC=arm-linux-gnueabihf-gcc 3rdparty/compile




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

make check_feat=0 CROSS_COMPILE=arm-linux-gnueabihf- CC=arm-linux-gnueabihf-gcc EXTRA_LDFLAGS="-L../../../3rdparty/install/arm/lib --static"

# display bpf_printk message
sudo bpftool prog tracelog


