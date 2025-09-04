VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS = -Wall -DVERSION=\"$(VERSION)\"

.PHONY: all
all: softgre_ap_xdp.o softgre_apd

softgre_ap_xdp.o: src/softgre_ap_xdp.c
	clang $(CFLAGS) -O2 -target bpf -c src/softgre_ap_xdp.c -o $@

softgre_apd: src/softgre_apd.o src/watch.o src/dbg.o
	cc $(CFLAGS) -g -O0 $^ -o $@

dev: softgre_ap_xdp.o softgre_apd
	@echo "Running dev configuration..."
	./softgre_apd -df -m ./softgre_ap_map.conf

.PHONY: clean
clean:
	rm -f softgre_ap_xdp.o softgre_apd
