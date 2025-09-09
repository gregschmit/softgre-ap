#ifndef XDP_STATE_H
#define XDP_STATE_H

#include <stdbool.h>

#include <bpf/libbpf.h>

struct XDPState {
    struct bpf_object *obj;

    int num_ifs;
    int *ifindexes;
    struct bpf_link **links;
};

void xdp_state__close(struct XDPState *state);
struct XDPState *xdp_state__open(char *xdp_path, int num_ifs, char **ifs);

struct bpf_map *xdp_state__get_mac_map(struct XDPState *state);
struct bpf_map *xdp_state__get_ip_set(struct XDPState *state);
void clear_bpf_map(struct bpf_map *map, unsigned int key_size);

#endif  // XDP_STATE_H
