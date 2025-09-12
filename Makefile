VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS = -g -Wall -DVERSION=\"$(VERSION)\"
LIBS = -lbpf -lelf -lz -lzstd

# Since we have to use clang for BPF, use it for everything.
CC = clang

# This probably shouldn't ever change, since it uses host endianness which is typically little, and
# that's also the endianness for most target architectures, but this could be set to `bpfel` or
# `bpfeb` if we need to target a different endianness from the host.
XDP_TARGET ?= bpf
XDP_TARGET_FLAG = -target $(XDP_TARGET)

# TODO: Figure out APD_TARGET_FLAG and what other options are needed for cross-compiling.
APD_TARGET ?=
APD_TARGET_FLAG = $(if $(APD_TARGET),-target $(APD_TARGET),)

ifeq ($(STATIC),1)
	LIBS += -static
endif

.PHONY: all
all: softgre_ap_xdp.o softgre_apd

softgre_ap_xdp.o: src/softgre_ap_xdp.c
	$(CC) $(CFLAGS) -O2 $(XDP_TARGET_FLAG) -c src/softgre_ap_xdp.c -o $@

softgre_apd: src/softgre_apd.o src/list.o src/log.o src/shared.o src/watch.o src/xdp_state.o
	$(CC) $(CFLAGS) -O0 $(APD_TARGET_FLAG) $^ -o $@ $(LIBS)

dev: softgre_ap_xdp.o softgre_apd
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
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_ap_xdp.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_apd.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f softgre_ap_xdp.o softgre_apd
