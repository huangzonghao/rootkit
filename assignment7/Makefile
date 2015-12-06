obj-m += rudekid.o

all: sysmap.h
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

sysmap.h: gen-sysmap.sh
	sudo bash gen-sysmap.sh

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
