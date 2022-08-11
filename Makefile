# -*-makefile-*-
obj-m += overlay-loader.o

ccflags-y += -I$(src)

#XXX(nitepone) The upstream driver was built in the kernel, and was not a
#              module. This means it was allowed to (and does) call
#              non-exported functions of the of driver.
#
#              For now, I am using `KBUILD_MODPOST_WARN=1` and maintaining a
#              copy of our kernel's `of_private.h` in this repo.
#              This allows us to build a useless module that expects symbols
#              which are not available. (Less we were to export them).
#
#              This is really just for pedantics for the initial commit. So we
#              can track changes made from upstream.
#
#              This nonsense and this comment should be gone before we are
#              trying to use this on target.
all:
	$(MAKE) KBUILD_MODPOST_WARN=1 -C $(KDIR) M=$(PWD)

clean:
	rm -f *.a *.s *.ko *.ko.cmd *.mod.* modules.order Module.symvers
	rm -rf .tmp_versions
	find . -name ".*.o.cmd" -exec rm -f {} \;
	find . -name "*.o" -exec rm -f {} \;
