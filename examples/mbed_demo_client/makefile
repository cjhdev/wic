# This makefile is used for development
#

DIR_PROJECT_ROOT := $(shell cd ../..;pwd)

# change this to point to your container
DOCKER := docker run --mount type=bind,source=$(DIR_PROJECT_ROOT),destination=/mbed/wic --device=/dev/ttyACM0:/dev/ttyACM0 -ti --rm --user 1000:1000 -v $(shell pwd):/mbed:cached my-mbed-cli

# special MBED name for target
DEVICE ?= NUCLEO_F429ZI
#DEVICE ?= DISCO_L072CZ_LRWAN1

# special JLINK name for the target
JLINK_DEVICE ?= STM32F429ZI

# need to slow it down?
JLINK_SPEED ?= 4000

# location of toolchain in container
PREFIX := $(DOCKER) /opt/gcc-arm/bin/arm-none-eabi

# location of the toolchain (can't seem to get GDB to work inside the container)
LOCAL_TOOLCHAIN := /opt/arm/gcc-arm-none-eabi-9-2020-q2-update/bin

# toolchain commands
GXX        := $(PREFIX)-g++
CC         := $(PREFIX)-gcc
AR         := $(PREFIX)-ar
OBJCOPY    := $(PREFIX)-objcopy
OBJDUMP    := $(PREFIX)-objdump
SIZE       := $(PREFIX)-size
GDB        := $(LOCAL_TOOLCHAIN)/arm-none-eabi-gdb
MBED	   := $(DOCKER) mbed
GDB_SERVER := JLinkGDBServer
JLINK 	   := JLinkExe

DIR_BUILD := BUILD/$(DEVICE)/GCC_ARM-DEBUG

compile: $(DIR_BUILD)/mbed.elf

$(DIR_BUILD)/mbed.elf:
	$(MBED) compile -m $(DEVICE) -t GCC_ARM --profile debug

$(DIR_BUILD)/mbed.hex: $(DIR_BUILD)/mbed.elf
	$(OBJCOPY) -O ihex $< $@

flash: upload_flash.jlink $(DIR_BUILD)/mbed.hex
	$(JLINK) -device $(JLINK_DEVICE) -if swd  -speed $(JLINK_SPEED) -CommanderScript $<

gdb: $(DIR_BUILD)/mbed.elf .gdbinit flash
	$(GDB) --command=.gdbinit -tui -q $<
	
gdb_server:
	$(GDB_SERVER) -if swd -device $(JLINK_DEVICE) -vd -speed $(JLINK_SPEED) -endian little 

size: $(DIR_BUILD)/mbed.elf
	$(SIZE) $<

upload_flash.jlink: 
	@ rm -f $@
	@ touch $@
	@ echo r                          >> $@
	@ echo h                          >> $@
	@ echo loadfile $(DIR_BUILD)/mbed.hex >> $@
	@ echo r                          >> $@
	@ echo g                          >> $@
	@ echo q                          >> $@

.gdbinit:
	@ rm -f $@
	@ touch $@
	@ echo target remote localhost:2331  >> $@
	@ echo dir $(DIR_PROJECT_ROOT)/src  >> $@
	@ echo dir $(DIR_PROJECT_ROOT)/include  >> $@
	@ echo dir $(DIR_PROJECT_ROOT)/port/mbed  >> $@
	#@ echo monitor flash download = 1    >> $@ 
	#@ echo load                 >> $@
	@ echo monitor reset                 >> $@
	@ echo focus cmd                     >> $@

clean:
	rm .gdbinit upload_flash.jlink
	rm -rf $(DIR_BUILD)	

.PHONY: clean gdb_server $(DIR_BUILD)/mbed.elf upload_flash.jlink .gdbinit config

config:
	$(MBED) compile --config -v
