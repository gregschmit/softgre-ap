/*
 * Shared definitions for the BPF program and the userspace daemon.
 *
 * WARNING: Since these definitions are shared between kernel and userspace, they must only use
 * features available in both contexts.
 */

#ifndef SHARED_H
#define SHARED_H

// Detect BPF compilation context.
#ifdef __BPF__
// BPF program: use kernel headers.
#include <linux/if_ether.h>
#include <linux/in.h>

typedef __u8 uint8_t;
typedef __u16 uint16_t;
#else
// Userspace daemon: use standard library headers.
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#endif  // __BPF__

#define MAX_DEVICES 1024

extern int DEBUG;

struct Device {
    uint8_t mac[ETH_ALEN];  // Key
    struct in_addr gre_ip;
    uint16_t vlan;
    uint8_t cycle;  // For removing stale entries.
};

struct IPCfg {
    struct in_addr gre_ip;  // Key
    struct in_addr src_ip;
    // Might need these. Currently trying to use bpf_redirect_neigh to hopefully be able to just
    // let the kernel handle the ethhdr.
    // uint8_t dst_mac[ETH_ALEN];
    // uint8_t src_mac[ETH_ALEN];
    unsigned ifindex;
    uint8_t cycle;  // For removing stale entries.
};

#ifndef __BPF__
bool device__key_eq(const uint8_t *key1, const uint8_t *key2);
bool ip_cfg__key_eq(const struct in_addr *key1, const struct in_addr *key2);
bool ip_cfg__is_valid(const struct IPCfg *ip_cfg);
#endif  // __BPF__

#endif  // SHARED_H
