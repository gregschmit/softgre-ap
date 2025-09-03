VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS ?= -Wall -DVERSION=\"$(VERSION)\"

.PHONY: all
all: softgre_ap_xdp.o softgre_apd test

softgre_ap_xdp.o: src/softgre_ap_xdp.c
	clang -Wall -O2 -target bpf -c src/softgre_ap_xdp.c -o softgre_ap_xdp.o

softgre_apd: src/softgre_apd.c
	cc -Wall -g -O0 src/softgre_apd.c -o softgre_apd

.PHONY: clean
clean:
	rm -f softgre_ap_xdp.o softgre_apd
