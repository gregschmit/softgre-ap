#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include <linux/if_packet.h>

#include <bpf/libbpf.h>

#include "../shared.h"
#include "log.h"

#include "bpf_state.h"

void bpf_state__close(BPFState *state) {
    if (!state) { return; }

    if (state->ifindexes) {
        free(state->ifindexes);
    }

    if (state->links) {
        int res = 0;
        for (unsigned i = 0; i < state->num_ifs * 2; i++) {
            if (state->links[i]) {
                if ((res = bpf_link__destroy(state->links[i]))) {
                    log_error("Failed to destroy BPF link (%d).", res);
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

BPFState *bpf_state__open(char *bpf_path, char **specified_ifs) {
    BPFState *state = calloc(1, sizeof(BPFState));
    if (!state) {
        log_errno("calloc");
        log_error("Failed to allocate memory for BPF state.");
        return NULL;
    }

    char **ifs = NULL;
    unsigned num_ifs = 0;
    struct ifaddrs *ifaddr = NULL;
    if (specified_ifs) {
        while (num_ifs < MAX_INTERFACES && specified_ifs[num_ifs]) { num_ifs++; }
        ifs = specified_ifs;
    } else {
        if (!(ifs = malloc(MAX_INTERFACES * sizeof(*ifs)))) {
            log_errno("malloc");
            log_error("Failed to allocate memory for interface names.");
            goto failure;
        }

        if (getifaddrs(&ifaddr) == -1) {
            log_errno("getifaddrs");
            ifaddr = NULL;  // Just to be safe.
        } else {
            for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (num_ifs >= MAX_INTERFACES) { break; }
                if (ifa->ifa_addr == NULL) { continue; }

                // Only consider L2 interfaces.
                if (ifa->ifa_addr->sa_family != AF_PACKET) { continue; }

                // Cast to sockaddr_ll to access hardware type.
                struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;

                // Skip loopback and non-ethernet interfaces.
                if (sll->sll_hatype != ARPHRD_ETHER) { continue; }

                // Check if we already have this interface.
                bool found = false;
                for (unsigned i = 0; i < num_ifs; i++) {
                    if (strcmp(ifs[i], ifa->ifa_name) == 0) {
                        found = true;
                        break;
                    }
                }
                if (found) { continue; }

                // Add this interface name to the list.
                ifs[num_ifs] = ifa->ifa_name;
                num_ifs++;
            }
        }
    }

    // If no interfaces found, cleanup. While an error condition, this is not a failure condition,
    // because we may just be waiting for interfaces to appear.
    if (!num_ifs) {
        log_error("No Ethernet interfaces available to attach to.");
        goto cleanup;
    }

    state->num_ifs = num_ifs;

    // Allocate memory for interface indexes.
    if (!(state->ifindexes = calloc(num_ifs, sizeof(*state->ifindexes)))) {
        log_errno("calloc");
        log_error("Failed to allocate memory for interface indexes.");
        goto failure;
    }

    // Allocate memory for links (number of ifs * number of programs).
    if (!(state->links = calloc(num_ifs * 2, sizeof(*state->links)))) {
        log_errno("calloc");
        log_error("Failed to allocate memory for links.");
        goto failure;
    }

    // Open and load the BPF object file.
    if (!(state->obj = bpf_object__open(bpf_path))) {
        log_errno("bpf_object__open");
        log_error("Failed to open BPF object file: %s", bpf_path);
        goto failure;
    }

    // Load the BPF object into the kernel.
    if (bpf_object__load(state->obj)) {
        log_errno("bpf_object__load");
        log_error("Failed to load BPF object.");
        goto failure;
    }

    // Find the BPF programs.
    struct bpf_program *prog_xdp = bpf_object__find_program_by_name(state->obj, "dtuninit_xdp");
    if (!prog_xdp) {
        log_error("Failed to find dtuninit_xdp.");
        goto failure;
    }
    struct bpf_program *prog_tci = bpf_object__find_program_by_name(state->obj, "dtuninit_tci");
    if (!prog_tci) {
        log_error("Failed to find dtuninit_tci.");
        goto failure;
    }

    // Find the Client map and clear it.
    struct bpf_map *client_map = bpf_state__get_client_map(state);
    if (!client_map) {
        log_error("Failed to find Client BPF map.");
        goto failure;
    }
    bpf_state__clear_client_map(state);

    // Find the IP Config map and clear it.
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) {
        log_error("Failed to find IP Config BPF map.");
        goto failure;
    }
    bpf_state__clear_ip_cfg_map(state);

    // Find the VLAN Config map and clear it.
    struct bpf_map *vlan_cfg_map = bpf_state__get_vlan_cfg_map(state);
    if (!vlan_cfg_map) {
        log_error("Failed to find VLAN Config BPF map.");
        goto failure;
    }
    bpf_state__clear_vlan_cfg_map(state);

    // Attach the BPF programs to each interface.
    unsigned successful_attachments = 0;
    for (unsigned i = 0; i < num_ifs; i++) {
        state->ifindexes[i] = if_nametoindex(ifs[i]);
        if (state->ifindexes[i] == 0) {
            log_errno("if_nametoindex");
            log_error("Failed to find interface %s.", ifs[i]);
            continue;
        }

        unsigned xdp_i = i;
        state->links[xdp_i] = bpf_program__attach_xdp(prog_xdp, state->ifindexes[i]);
        if (state->links[xdp_i]) {
            log_info("Attached XDP to interface %s (ifindex %d).", ifs[i], state->ifindexes[i]);
            successful_attachments++;
        } else {
            log_errno("bpf_program__attach_xdp");
            log_error("Failed to attach XDP to interface %s.", ifs[i]);
            continue;
        }

        unsigned tci_i = num_ifs + i;
        state->links[tci_i] = bpf_program__attach_tcx(prog_tci, state->ifindexes[i], NULL);
        if (state->links[tci_i]) {
            log_info("Attached TCI to interface %s (ifindex %d).", ifs[i], state->ifindexes[i]);
            successful_attachments++;
        } else {
            log_errno("bpf_program__attach_tcx");
            log_error("Failed to attach TCI to interface %s.", ifs[i]);
            continue;
        }
    }

    if (successful_attachments == 0) {
        // If we failed to attach to any interface, then just log a message. While this is an error
        // condition, this is not a failure condition, because we may just be waiting for the proper
        // interfaces to appear or be put into a state where they can have BPF programs attached.
        log_info("Failed to attach BPF programs to any interface.");
    }

    // Success, cleanup.
    goto cleanup;

    // Failure, ensure state is closed and NULL, then fall through to cleanup.
    failure:
    bpf_state__close(state);
    state = NULL;

    // Always cleanup and return state.
    cleanup:
    if (ifs && !specified_ifs) { free(ifs); }
    if (ifaddr) { freeifaddrs(ifaddr); }
    return state;
}

struct bpf_map *bpf_state__get_client_map(BPFState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "client_map");
}

struct bpf_map *bpf_state__get_ip_cfg_map(BPFState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "ip_cfg_map");
}

struct bpf_map *bpf_state__get_vlan_cfg_map(BPFState *state) {
    if (!state || !state->obj) { return NULL; }
    return bpf_object__find_map_by_name(state->obj, "vlan_cfg_map");
}

void bpf_state__clear_client_map(BPFState *state) {
    struct bpf_map *client_map = bpf_state__get_client_map(state);
    if (!client_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from Client map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);

        // Delete the current key.
        if (bpf_map__delete_elem(client_map, key, ETH_ALEN, BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from Client map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from Client map.");
    }
}

void bpf_state__clear_ip_cfg_map(BPFState *state) {
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
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

void bpf_state__clear_vlan_cfg_map(BPFState *state) {
    struct bpf_map *vlan_cfg_map = bpf_state__get_vlan_cfg_map(state);
    if (!vlan_cfg_map) { return; }

    uint16_t key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(vlan_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from VLAN Config map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(vlan_cfg_map, &key, &next_key, sizeof(next_key));

        // Delete the current key.
        if (bpf_map__delete_elem(vlan_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from VLAN Config map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from VLAN Config map.");
    }
}

void bpf_state__remove_stale_clients(BPFState *state, List *clients) {
    if (!state || !clients) { return; }

    struct bpf_map *client_map = bpf_state__get_client_map(state);
    if (!client_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from MAC map (%d).", res);
        }

        return;
    }

    while (!res) {
        // Get the next key before possibly deleting the current key.
        res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);

        // Look up the client to check its cycle.
        Client client;
        if (bpf_map__lookup_elem(client_map, key, ETH_ALEN, &client, sizeof(client), 0)) {
            log_error("Failed to look up client in Client map.");
            return;
        } else {
            if (client.cycle != state->cycle) {
                // Cycle doesn't match, so remove this stale entry.
                if (bpf_map__delete_elem(client_map, key, ETH_ALEN, BPF_ANY) != 0) {
                    log_error("Failed to delete stale key from Client map.");
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
        log_error("Failed to get next key from Client map.");
    }
}

void bpf_state__remove_stale_ip_cfgs(BPFState *state, List *ip_cfgs) {
    if (!state || !ip_cfgs) { return; }

    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
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
        IPCfg ip_cfg;
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

unsigned bpf_state__get_num_clients(BPFState *state) {
    if (!state) { return 0; }

    struct bpf_map *client_map = bpf_state__get_client_map(state);
    if (!client_map) { return 0; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];
    unsigned count = 0;
    int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
    while (res == 0) {
        count++;
        res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    return count;
}

unsigned bpf_state__get_num_ip_cfgs(BPFState *state) {
    if (!state) { return 0; }

    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
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
