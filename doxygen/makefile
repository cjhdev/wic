DIR_ROOT := ../
SPACE :=
SPACE +=

CORE_VERSION := $(shell cat $(DIR_ROOT)/version)

VERSION := $(CORE_VERSION)

ifdef BUILD_NUMBER
VERSION += +$(BUILD_NUMBER)
endif

VERSION := $(subst $(SPACE),,$(VERSION))

all: clean
	VERSION=$(VERSION) doxygen
	rm html/index.html
	ln --symbolic group__wic.html html/index.html
	rm -f html/*.js

clean: 
	rm -rf html/*

.PHONY: all clean deploy
