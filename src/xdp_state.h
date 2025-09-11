#ifndef XDP_STATE_H
#define XDP_STATE_H

#include <stdbool.h>

#include <bpf/libbpf.h>

struct XDPState {
    struct bpf_object *obj;

    unsigned num_ifs;
    unsigned *ifindexes;
    struct bpf_link **links;

    uint8_t cycle;  // For removing stale map entries.
};

void xdp_state__close(struct XDPState *state);
struct XDPState *xdp_state__open(char *xdp_path, unsigned num_ifs, char **ifs);

struct bpf_map *xdp_state__get_device_map(struct XDPState *state);
struct bpf_map *xdp_state__get_ip_config_map(struct XDPState *state);
void xdp_state__clear_device_map(struct XDPState *state);
void xdp_state__clear_ip_config_map(struct XDPState *state);
void xdp_state__remove_stale_devices(struct XDPState *state, List *devices);
void xdp_state__remove_stale_ip_configs(struct XDPState *state, List *ip_configs);
unsigned xdp_state__get_num_devices(struct XDPState *state);
unsigned xdp_state__get_num_ip_configs(struct XDPState *state);

#endif  // XDP_STATE_H
