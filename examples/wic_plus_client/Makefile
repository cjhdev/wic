DIR_ROOT := $(shell cd ../..; pwd)

CC := gcc

VPATH += $(DIR_ROOT)/src
VPATH += $(DIR_ROOT)/wrapper/wic_plus

INCLUDES += -I$(DIR_ROOT)/include
INCLUDES += -I$(DIR_ROOT)/wrapper/wic_plus
INCLUDES += -I.

CFLAGS += -DVERSION=\"$(shell cat $(DIR_ROOT)/version)\"

CFLAGS := -O0 -Wall -ggdb $(INCLUDES)

LDFLAGS := -lpthread -lstdc++ -lm

SRC := $(notdir $(wildcard $(DIR_ROOT)/src/*.c)) $(notdir $(wildcard $(DIR_ROOT)/wrapper/wic_plus/*.cpp))

OBJ_INTER := $(SRC:.c=.o)
OBJ := $(OBJ_INTER:.cpp=.o)

all: $(addprefix bin/, wic_plus_client)

bin/wic_plus_client: $(addprefix build/,$(OBJ) main.o)
	@ mkdir -p bin
	$(CC) $(LDFLAGS) $^ -o $@

build/%.o: %.cpp
	@ echo building $@
	@ mkdir -p build
	@ $(CC) $(CFLAGS) -c $< -o $@

build/%.o: %.c
	@ echo building $@
	@ mkdir -p build
	@ $(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f build/*

sqeaky_clean: clean
	rm -f bin/*

.PHONY: clean sqeaky_clean all
