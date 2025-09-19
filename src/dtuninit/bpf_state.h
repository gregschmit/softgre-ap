#ifndef BPF_STATE_H
#define BPF_STATE_H

#include <stdbool.h>

#include <bpf/libbpf.h>

#include "list.h"

typedef struct {
    struct bpf_object *obj;

    unsigned num_ifs;
    unsigned *ifindexes;
    struct bpf_link **links;

    uint8_t cycle;  // For removing stale map entries.
} BPFState;

void bpf_state__close(BPFState *state);
BPFState *bpf_state__open(char *bpf_path, char **ifs);

struct bpf_map *bpf_state__get_client_map(BPFState *state);
struct bpf_map *bpf_state__get_ip_cfg_map(BPFState *state);
struct bpf_map *bpf_state__get_vlan_cfg_map(BPFState *state);
void bpf_state__clear_client_map(BPFState *state);
void bpf_state__clear_ip_cfg_map(BPFState *state);
void bpf_state__clear_vlan_cfg_map(BPFState *state);
void bpf_state__remove_stale_clients(BPFState *state, List *clients);
void bpf_state__remove_stale_ip_cfgs(BPFState *state, List *ip_cfgs);
unsigned bpf_state__get_num_clients(BPFState *state);
unsigned bpf_state__get_num_ip_cfgs(BPFState *state);

#endif  // BPF_STATE_H
