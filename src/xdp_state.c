#include <stdlib.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>

#include "log.h"

#include "xdp_state.h"

void xdp_state__close(struct XDPState *state) {
    if (!state) { return; }

    if (state->ifindexes) {
        free(state->ifindexes);
    }

    if (state->links) {
        for (int i = 0; i < state->num_ifs; i++) {
            if (state->links[i]) {
                int res = bpf_link__destroy(state->links[i]);
                if (res) {
                    log_error("Failed to destroy XDP link (%d).", res);
                }
            }
        }
        free(state->links);
    }

    if (state->obj) {
        bpf_object__close(state->obj);
    }

    free(state);
}

struct XDPState *xdp_state__open(char *xdp_path, int num_ifs, char **ifs) {
    struct XDPState *state = calloc(1, sizeof(struct XDPState));
    if (!state) {
        log_error("Failed to allocate memory for XDP state.");
        return NULL;
    }

    state->num_ifs = num_ifs;

    // Allocate memory for interface indexes.
    state->ifindexes = calloc(num_ifs, sizeof(int));
    if (!state->ifindexes) {
        log_error("Failed to allocate memory for interface indexes.");
        xdp_state__close(state);
        return NULL;
    }

    // Allocate memory for links.
    state->links = calloc(num_ifs, sizeof(struct bpf_link *));
    if (!state->links) {
        log_error("Failed to allocate memory for links.");
        xdp_state__close(state);
        return NULL;
    }

    // Open and load the XDP object file.
    state->obj = bpf_object__open(xdp_path);
    if (!state->obj) {
        log_errno("bpf_object__open");
        log_error("Failed to open XDP object file: %s", xdp_path);
        xdp_state__close(state);
        return NULL;
    }

    // Load the BPF object into the kernel.
    if (bpf_object__load(state->obj)) {
        log_errno("bpf_object__load");
        log_error("Failed to load BPF object.");
        xdp_state__close(state);
        return NULL;
    }

    // Find the XDP program.
    struct bpf_program *prog = bpf_object__find_program_by_name(state->obj, "xdp_softgre_ap");
    if (!prog) {
        log_error("Failed to find XDP program.");
        xdp_state__close(state);
        return NULL;
    }

    // Find the MAC map and clear it.
    struct bpf_map *mac_map = bpf_object__find_map_by_name(state->obj, "mac_map");
    if (!mac_map) {
        log_error("Failed to find MAC BPF map.");
        xdp_state__close(state);
        return NULL;
    }
    clear_bpf_map(mac_map, ETH_ALEN);

    // Find the IP set and clear it.
    // struct bpf_map *ip_set = bpf_object__find_map_by_name(state.obj, "ip_set");
    // if (!ip_set) {
    //     log_error("Failed to find IP BPF map.");
    //     return close_xdp_state(state);
    // }
    // clear_bpf_map(ip_set, sizeof(struct in_addr));

    // Attach the XDP program to each interface.
    int successful_attachments = 0;
    for (int i = 0; i < num_ifs; i++) {
        state->ifindexes[i] = if_nametoindex(ifs[i]);
        if (state->ifindexes[i] == 0) {
            log_errno("if_nametoindex");
            log_error("Failed to find interface %s.", ifs[i]);
            continue;
        }

        state->links[i] = bpf_program__attach_xdp(prog, state->ifindexes[i]);
        if (state->links[i]) {
            log_info("Attached to interface %s (ifindex %d)", ifs[i], state->ifindexes[i]);
            successful_attachments++;
        } else {
            log_errno("bpf_program__attach_xdp");
            log_error("Failed to attach XDP program to interface %s.", ifs[i]);
            continue;
        }
    }

    if (successful_attachments == 0) {
        log_error("Failed to attach XDP program to any interface.");
        xdp_state__close(state);
        return NULL;
    }

    return state;
}

struct bpf_map *xdp_state__get_mac_map(struct XDPState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "mac_map");
}

void clear_bpf_map(struct bpf_map *map, unsigned int key_size) {
    if (!map) { return; }

    void *cur_key = NULL;
    void *next_key = NULL;
    while (bpf_map__get_next_key(map, cur_key, next_key, key_size) == 0) {
        bpf_map__delete_elem(map, next_key, key_size, BPF_ANY);
        cur_key = next_key;
    }
}
