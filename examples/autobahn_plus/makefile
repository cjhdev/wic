DIR_ROOT := $(shell cd ../..; pwd)

CC := gcc

VPATH += $(DIR_ROOT)

INCLUDES += -I$(DIR_ROOT)/include
INCLUDES += -I.
INCLUDES += -I$(DIR_ROOT)/wrapper/wic_plus

CFLAGS += -DVERSION=\"$(shell cat $(DIR_ROOT)/version)\"

CFLAGS := -O0 -Wall -Wextra -ggdb -pthread $(INCLUDES)

LDFLAGS := -ggdb -lpthread -lstdc++ -lm

SRC += $(subst $(DIR_ROOT)/,,$(wildcard $(DIR_ROOT)/src/*.c))
SRC += $(subst $(DIR_ROOT)/,,$(wildcard $(DIR_ROOT)/wrapper/wic_plus/*.cpp))

OBJ2 += $(SRC:.c=.o)
OBJ3 += $(OBJ2:.cpp=.o)

OBJ := $(addprefix build/,$(OBJ3))

all: $(addprefix bin/, client)

bin/client: $(OBJ) build/examples/autobahn_plus/main.o
	@ mkdir -p bin
	@ $(CC) $^ -o $@ $(LDFLAGS)

build/%.o: %.c
	@ echo building $@ from $<
	@ mkdir -p $(dir $@)
	@ $(CC) $(CFLAGS) -c $< -o $@

build/%.o: %.cpp
	@ echo building $@ from $<
	@ mkdir -p $(dir $@)
	@ $(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build/*

sqeaky_clean: clean
	rm -rf bin/*

.PHONY: clean sqeaky_clean all

check: CC := clang
check: CFLAGS += --analyze -Xanalyzer -analyzer-output=text
check: $(addprefix build/, $(OBJ))
