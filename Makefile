VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS = -g -Wall -DVERSION=\"$(VERSION)\"
LIBS = -lbpf -lelf -lz -lzstd

# Since we have to use clang for BPF, use it for everything.
CC = clang

ifeq ($(STATIC),1)
	LIBS += -static
endif

.PHONY: all
all: softgre_ap_xdp.o softgre_apd

.PHONY: static
static:
	$(MAKE) STATIC=1 all

softgre_ap_xdp.o: src/softgre_ap_xdp.c
	$(CC) $(CFLAGS) -O2 -target bpf -c src/softgre_ap_xdp.c -o $@

softgre_apd: src/softgre_apd.o src/list.o src/log.o src/shared.o src/watch.o src/xdp_state.o
	$(CC) $(CFLAGS) -O0 $(LDFLAGS) $^ -o $@ $(LIBS)

dev: softgre_ap_xdp.o softgre_apd
	@echo "Running dev configuration..."
	sudo ./softgre_apd -df -m ./softgre_ap_map.conf

.PHONY: docker_build
docker_build:
	@echo "Building Docker image..."
	docker build -t softgre-ap .

.PHONY: build
build: docker_build
	@echo "Building in Docker container..."
	docker run -it --rm softgre-ap make -B

.PHONY: build_static
build_static: docker_build
	@echo "Building static in Docker container..."
	docker run -it --rm softgre-ap make -B static

# TODO: Get clang-tidy working.
# .PHONY: tidy
# tidy:
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_ap_xdp.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/softgre_apd.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f softgre_ap_xdp.o softgre_apd
