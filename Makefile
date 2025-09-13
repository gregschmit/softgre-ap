VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS_COMMON = -g -Wall -DVERSION=\"$(VERSION)\"
LIBS = -lbpf -lelf -lz -lzstd

# Since we have to use clang for BPF, use it for everything.
CC = clang

# This probably shouldn't ever change, since it uses host endianness which is typically little, and
# that's also the endianness for most target architectures, but this could be set to `bpfel` or
# `bpfeb` if we need to target a different endianness from the host.
TARGET_BPF ?= bpf
TARGET_BPF_FLAG = -target $(TARGET_BPF)

# TODO: Figure out TARGET_USR_FLAG and what other options are needed for cross-compiling.
TARGET_USR ?=
TARGET_USR_FLAG = $(if $(TARGET_USR),-target $(TARGET_USR),)

CFLAGS_BPF = $(CFLAGS_COMMON) -D__BPF__

CFLAGS_USR = $(CFLAGS_COMMON)

OBJFILES_USR = src/softgre_apd.o src/bpf_state.o src/list.o src/log.o src/shared.o src/watch.o

ifeq ($(STATIC),1)
	LIBS += -static
endif

.PHONY: all
all: softgre_ap_bpf.o softgre_apd

softgre_ap_bpf.o: src/softgre_ap_bpf.c
	$(CC) $(CFLAGS_BPF) -O2 $(TARGET_BPF_FLAG) -c $^ -o $@

softgre_apd: $(OBJFILES_USR)
	$(CC) $(CFLAGS_USR) -O0 $(TARGET_USR_FLAG) $^ -o $@ $(LIBS)

$(OBJFILES_USR): %.o : %.c
	$(CC) $(CFLAGS_USR) -O0 $(TARGET_USR_FLAG) -c $< -o $@

dev: softgre_ap_bpf.o softgre_apd
	@echo "Running dev configuration..."
	sudo ./softgre_apd -df -m ./softgre_ap_map.conf

.PHONY: static
static:
	$(MAKE) all STATIC=1

.PHONY: docker_build
docker_build:
	@echo "Building Docker image..."
	docker build -t softgre-ap .

.PHONY: build
build: docker_build
	@echo "Building in Docker container..."
	docker run -it --rm -v .:/app softgre-ap make -B

.PHONY: build_static
build_static: docker_build
	@echo "Building static in Docker container..."
	docker run -it --rm -v .:/app softgre-ap make -B static

# TODO: Get clang-tidy working.
# .PHONY: tidy
# tidy:
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_ap_bpf.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_apd.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f softgre_ap_bpf.o softgre_apd **/*.o
