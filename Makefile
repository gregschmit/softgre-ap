VERSION = $(shell git describe --dirty 2>/dev/null)
LIBS_USR = -lbpf -lelf -lz -lzstd
OLEVEL ?= 3
BPF_DEBUG ?= 0
CFLAGS_COMMON = -g -Wall -DVERSION=\"$(VERSION)\" -DBPF_DEBUG=$(BPF_DEBUG)

# Since we have to use clang for BPF, use it for everything.
CC = clang

# This probably shouldn't ever change, since it uses host endianness which is typically little, and
# that's also the endianness for most target architectures, but this could be set to `bpfel` or
# `bpfeb` if we need to target a different endianness from the host.
TARGET_BPF ?= bpf

TARGET_USR ?=

CFLAGS_BPF = $(CFLAGS_COMMON) -target $(TARGET_BPF)
CFLAGS_BPF += -I/usr/include/x86_64-linux-gnu

CFLAGS_USR = $(CFLAGS_COMMON) $(if $(TARGET_USR),-target $(TARGET_USR),)
CFLAGS_USR += -I/usr/include/x86_64-linux-gnu
CFLAGS_USR += -I/usr/include/aarch64-linux-gnu

OBJFILES_USR = \
	src/dtuninit/main.o \
	src/shared.o \
	src/dtuninit/bpf_state.o \
	src/dtuninit/list.o \
	src/dtuninit/log.o \
	src/dtuninit/watch.o

ifeq ($(STATIC),1)
	LIBS_USR += -static
endif

.PHONY: all
all: dtuninit_bpf.o dtuninit

dtuninit_bpf.o: src/dtuninit_bpf/main.c
	$(CC) $(CFLAGS_BPF) -O$(OLEVEL) $(TARGET_BPF_FLAG) -c $^ -o $@

dtuninit: $(OBJFILES_USR)
	$(CC) $(CFLAGS_USR) -O$(OLEVEL) $(TARGET_USR_FLAG) $^ -o $@ $(LIBS_USR)

$(OBJFILES_USR): %.o : %.c
	$(CC) $(CFLAGS_USR) -O$(OLEVEL) $(TARGET_USR_FLAG) -c $< -o $@

dev: dtuninit_bpf.o dtuninit
	@echo "Running dev configuration..."
	sudo ./dtuninit -df -m ./dtuninit_clients

.PHONY: static
static:
	$(MAKE) all STATIC=1

.PHONY: cross
cross:
	# Assume aarch64 for now.
	$(MAKE) all TARGET_USR=aarch64-linux-gnu

.PHONY: docker_build
docker_build:
	@echo "Building Docker image..."
	docker build -t dtuninit .

.PHONY: build
build: docker_build
	@echo "Building in Docker container..."
	docker run -it --rm -v .:/app dtuninit make -B

.PHONY: build_static
build_static: docker_build
	@echo "Building static in Docker container..."
	docker run -it --rm -v .:/app dtuninit make -B static

# TODO: Get clang-tidy working.
# .PHONY: tidy
# tidy:
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit_bpf/main.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit/main.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f dtuninit_bpf.o dtuninit **/*.o
