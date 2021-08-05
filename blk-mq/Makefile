CC=gcc
PROJECT_ROOT=/home/suho/oslab
obj-m+=blkdev.o

EXTRA_LDFLAGS := -I$(PROJECT_ROOT)/socket-blk-mq/ksocket
KBUILD_EXTRA_SYMBOLS='$(PROJECT_ROOT)/socket-blk-mq/ksocket/Module.symvers'

all: module

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
