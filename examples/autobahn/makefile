DIR_ROOT := ../..

CC := gcc

VPATH += $(DIR_ROOT)/src
VPATH += $(DIR_ROOT)/examples/transport

INCLUDES += -I$(DIR_ROOT)/include
INCLUDES += -I.
INCLUDES += -I$(DIR_ROOT)/examples/transport

CFLAGS += -DVERSION=\"$(shell cat $(DIR_ROOT)/version)\"

CFLAGS := -O0 -Wall -ggdb $(INCLUDES)

CFLAGS += -D'WSC_PORT_INCLUDE="port.h"'

SRC := $(notdir $(wildcard $(DIR_ROOT)/src/*.c)) transport.c
OBJ := $(SRC:.c=.o)

all: $(addprefix bin/, client server)

bin/client: $(addprefix build/,$(OBJ) client.o)
	$(CC) $(LDFLAGS) $^ -o $@

bin/server: $(addprefix build/,$(OBJ) server.o)
	$(CC) $(LDFLAGS) $^ -o $@

build/%.o: %.c
	@ echo building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/*

sqeaky_clean: clean
	rm -f bin/*

.PHONY: clean sqeaky_clean all

check: CC := clang
check: CFLAGS += --analyze -Xanalyzer -analyzer-output=text
check: $(addprefix build/, $(OBJ))
