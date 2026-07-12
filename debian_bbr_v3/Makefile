obj-m += tcp_bbr_e.o
tcp_bbr_e-y := tcp_bbr.o

KERNEL_RELEASE ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KERNEL_RELEASE)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load:
	insmod tcp_bbr_e.ko

unload:
	rmmod tcp_bbr_e
