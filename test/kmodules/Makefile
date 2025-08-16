obj-m := skb_offset.o
KDIR := ../../3rdparty/kheaders/arm/
# KDIR := /lib/modules/6.6.23/build
# KDIR := /home/anlan/Desktop/perf/linux-6.6.23/
PWD := $(shell pwd)

export ARCH = arm
export CROSS_COMPILE = arm-linux-gnueabi-

# CC = arm-linux-gnueabi-gcc

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean