DIR_ROOT := ../..

CC := gcc

VPATH += $(DIR_ROOT)/src
VPATH += $(DIR_ROOT)/examples/transport

INCLUDES += -I$(DIR_ROOT)/include
INCLUDES += -I$(DIR_ROOT)/examples/transport
INCLUDES += -I.

CFLAGS += -DVERSION=\"$(shell cat $(DIR_ROOT)/version)\"

CFLAGS := -O0 -Wall -ggdb $(INCLUDES)

CFLAGS += -D'WSC_PORT_INCLUDE="port.h"'

SRC := $(notdir $(wildcard $(DIR_ROOT)/src/*.c)) transport.c
OBJ := $(SRC:.c=.o)

all: $(addprefix bin/, demo_client)

bin/demo_client: $(addprefix build/,$(OBJ) demo_client.o)
	$(CC) $(LDFLAGS) $^ -o $@

build/%.o: %.c
	@ echo building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/*

sqeaky_clean: clean
	rm -f bin/*

.PHONY: clean sqeaky_clean all
