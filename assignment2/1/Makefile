obj-m += hook_read.o

all: sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

sysmap.h: gen-sysmap.sh
	sudo bash gen-sysmap.sh

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f sysmap.h
