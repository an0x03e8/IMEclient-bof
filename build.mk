# build.mk - shared build configuration for IMEclient-bof.

ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

CC_X64 := x86_64-w64-mingw32-gcc

CFLAGS_X64 := -nostdlib -Os -fno-builtin -Wall -Wextra \
              -D__USE_MINGW_ANSI_STDIO=0

# COFF linker, expected on PATH. Override on the command line:
# make BOFLINK=/path/to/boflink
BOFLINK ?= boflink

BUILD := $(ROOT)/build
OBJ   := $(BUILD)/obj
