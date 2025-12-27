CONFIG_MSTAR_CHIP_NAME := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME))
EXTRA_CFLAGS    +=  -Idrivers/mstar2/drv/mzc/
EXTRA_CFLAGS    +=  -Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/mzc/
EXTRA_CFLAGS    +=  -Iarch/$(SRCARCH)/
obj-y +=    ../../hal/$(CONFIG_MSTAR_CHIP_NAME)/mzc/mhal_mzc_hal.o
obj-y +=    mdrv_mzc_drv.o
