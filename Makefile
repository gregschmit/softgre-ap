VERSION = $(shell git describe --tags --long --always)$(shell git diff-index --quiet HEAD -- || echo '-changed')
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
