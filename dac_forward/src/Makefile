obj-m	+= dac_forward.o
export PWD :=	$(shell pwd)

.PHONY: modules
modules:
	$(MAKE) -C $(KLIB_BUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KLIB_BUILD) M=$(PWD) clean
