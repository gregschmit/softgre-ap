VERSION = $(shell git describe --dirty 2>/dev/null)
CFLAGS = -g -Wall -DVERSION=\"$(VERSION)\"

.PHONY: all
all: softgre_ap_xdp.o softgre_apd

softgre_ap_xdp.o: src/softgre_ap_xdp.c
	clang $(CFLAGS) -O2 -target bpf -c src/softgre_ap_xdp.c -o $@

softgre_apd: src/softgre_apd.o src/list.o src/log.o src/shared.o src/watch.o src/xdp_state.o
	cc $(CFLAGS) -O0 $^ -o $@ -lbpf

dev: softgre_ap_xdp.o softgre_apd
	@echo "Running dev configuration..."
	sudo ./softgre_apd -df -m ./softgre_ap_map.conf wlx54c9ff02cfb5

.PHONY: tidy
tidy:
	clang-tidy -checks='misc-include-cleaner' src/softgre_ap_xdp.c -- -target bpf $(CFLAGS)
	clang-tidy -checks='misc-include-cleaner' src/softgre_apd.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f softgre_ap_xdp.o softgre_apd
