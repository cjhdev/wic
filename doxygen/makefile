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

deploy: all
	rm -rf deploy
	mkdir deploy
	git clone git@github.com:cjhdev/wic_api.git deploy
	rm -rf deploy/docs
	mkdir deploy/docs
	cp -r html/* deploy/docs/
	git -C deploy add -A
	git -C deploy commit -m "update"
	git -C deploy push origin master

.PHONY: all clean deploy
