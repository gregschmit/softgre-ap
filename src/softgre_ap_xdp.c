/*
 * SoftGRE Access Point XDP Program
 *
 * This program handles encapsulation/decapsulation of Dynamic SoftGRE traffic.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "device.h"

#define ETH_P_8021Q 0x8100
#define ETH_P_IPV4 0x0800
#define ETH_BCAST_MAC {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Shared map for MAC to Device mappings.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, sizeof(struct Device));
} mac_map SEC(".maps");

// Shared set of endpoint IPs (needed for Ethernet Broadcast Frames).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);  // Would never be larger than the amount of devices.
    __uint(key_size, sizeof(struct in_addr));
    __uint(value_size, 1);
} ip_set SEC(".maps");

static inline int mac_eq(const __u8 *mac1, const __u8 *mac2) {
    for (int i = 0; i < ETH_ALEN; i++) {
        if (mac1[i] != mac2[i]) { return 0; }
    }
    return 1;
}

SEC("xdp")
int xdp_softgre_ap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check we can get a valid Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { return XDP_PASS; }

    // Check (untagged) IP EtherType.
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { return XDP_PASS; }

    // Check we can get a valid IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) { return XDP_PASS; }

    // Verify it's actually an IPv4 packet.
    if (ip->version != 4) { return XDP_PASS; }

    // Check if source MAC matches a map entry.
    struct Device *d = bpf_map_lookup_elem(&mac_map, &eth->h_source);
    if (d) {
        bpf_printk("gns: found packet!");
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Proprietary";
