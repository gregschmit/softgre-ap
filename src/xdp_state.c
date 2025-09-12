#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>

#include <bpf/libbpf.h>

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

struct XDPState *xdp_state__open(char *xdp_path, unsigned num_ifs, char **ifs) {
    struct XDPState *state = calloc(1, sizeof(struct XDPState));
    if (!state) {
        log_error("Failed to allocate memory for XDP state.");
        return NULL;
    }

    state->num_ifs = num_ifs;

    // Allocate memory for interface indexes.
    state->ifindexes = calloc(num_ifs, sizeof(*state->ifindexes));
    if (!state->ifindexes) {
        log_error("Failed to allocate memory for interface indexes.");
        xdp_state__close(state);
        return NULL;
    }

    // Allocate memory for links.
    state->links = calloc(num_ifs, sizeof(*state->links));
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

    // Find the Device map and clear it.
    struct bpf_map *device_map = bpf_object__find_map_by_name(state->obj, "device_map");
    if (!device_map) {
        log_error("Failed to find Device BPF map.");
        xdp_state__close(state);
        return NULL;
    }
    xdp_state__clear_device_map(state);

    // Find the IP Config map and clear it.
    struct bpf_map *ip_cfg_map = bpf_object__find_map_by_name(state->obj, "ip_cfg_map");
    if (!ip_cfg_map) {
        log_error("Failed to find IP Config BPF map.");
        xdp_state__close(state);
        return NULL;
    }
    xdp_state__clear_ip_cfg_map(state);

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
            log_info("Attached to interface %s (ifindex %d).", ifs[i], state->ifindexes[i]);
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

struct bpf_map *xdp_state__get_device_map(struct XDPState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "device_map");
}

struct bpf_map *xdp_state__get_ip_cfg_map(struct XDPState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "ip_cfg_map");
}

void xdp_state__clear_device_map(struct XDPState *state) {
    struct bpf_map *device_map = xdp_state__get_device_map(state);
    if (!device_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(device_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from Device map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(device_map, key, next_key, ETH_ALEN);

        // Delete the current key.
        if (bpf_map__delete_elem(device_map, key, ETH_ALEN, BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from Device map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from Device map.");
    }
}

void xdp_state__clear_ip_cfg_map(struct XDPState *state) {
    struct bpf_map *ip_cfg_map = xdp_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) { return; }

    struct in_addr key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from IP Config map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));

        // Delete the current key.
        if (bpf_map__delete_elem(ip_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from IP Config map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from IP Config map.");
    }
}

void xdp_state__remove_stale_devices(struct XDPState *state, List *devices) {
    if (!state || !devices) { return; }

    struct bpf_map *device_map = xdp_state__get_device_map(state);
    if (!device_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(device_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from MAC map (%d).", res);
        }

        return;
    }

    while (!res) {
        // Get the next key before possibly deleting the current key.
        res = bpf_map__get_next_key(device_map, key, next_key, ETH_ALEN);

        // Look up the device to check its cycle.
        struct Device device;
        if (bpf_map__lookup_elem(device_map, key, ETH_ALEN, &device, sizeof(device), 0)) {
            log_error("Failed to look up device in Device map.");
            return;
        } else {
            if (device.cycle != state->cycle) {
                // Cycle doesn't match, so remove this stale entry.
                if (bpf_map__delete_elem(device_map, key, ETH_ALEN, BPF_ANY) != 0) {
                    log_error("Failed to delete stale key from Device map.");
                    return;
                }
            }
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from Device map.");
    }
}

void xdp_state__remove_stale_ip_cfgs(struct XDPState *state, List *ip_cfgs) {
    if (!state || !ip_cfgs) { return; }

    struct bpf_map *ip_cfg_map = xdp_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) { return; }

    struct in_addr key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from IP Config map (%d).", res);
        }

        return;
    }

    while (!res) {
        // Get the next key before possibly deleting the current key.
        res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));

        // Look up the IP config to check its cycle.
        struct IPCfg ip_cfg;
        if (bpf_map__lookup_elem(ip_cfg_map, &key, sizeof(key), &ip_cfg, sizeof(ip_cfg), 0)) {
            log_error("Failed to look up IP config in IP Config map.");
            return;
        } else {
            if (ip_cfg.cycle != state->cycle) {
                // Cycle doesn't match, so remove this stale entry.
                if (bpf_map__delete_elem(ip_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
                    log_error("Failed to delete stale key from IP Config map.");
                    return;
                }
            }
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from IP Config map.");
    }
}

unsigned xdp_state__get_num_devices(struct XDPState *state) {
    if (!state) { return 0; }

    struct bpf_map *device_map = xdp_state__get_device_map(state);
    if (!device_map) { return 0; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];
    unsigned count = 0;
    int res = bpf_map__get_next_key(device_map, NULL, key, ETH_ALEN);
    while (res == 0) {
        count++;
        res = bpf_map__get_next_key(device_map, key, next_key, ETH_ALEN);
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    return count;
}

unsigned xdp_state__get_num_ip_cfgs(struct XDPState *state) {
    if (!state) { return 0; }

    struct bpf_map *ip_cfg_map = xdp_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) { return 0; }

    struct in_addr key, next_key;
    unsigned count = 0;
    int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
    while (res == 0) {
        count++;
        res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));
        if (res == 0) {
            key = next_key;
        }
    }

    return count;
}
