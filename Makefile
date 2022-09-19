# -*-makefile-*-

.PHONY: default
default: modules

.PHONY: modules
modules:
	$(MAKE) -C $(KDIR) M=$$PWD modules

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
