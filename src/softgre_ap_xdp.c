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
#include <linux/gre.h>

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
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_DEVICES);  // Would never be larger than the amount of devices.
//     __type(key, struct in_addr);
//     __type(value, bool);
// } ip_set SEC(".maps");

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

    // Encapsulation:
    // If the source MAC is in the MAC map, then it's coming from a client, so we should encapsulate
    // the frame in an IP/GRE header and pass it up the stack.
    struct Device *d = bpf_map_lookup_elem(&mac_map, &eth->h_source);
    if (d) {
        bpf_printk("softgre_apd: encapsulate");

        // First, expand packet to cover both GRE header and IP header.
        int expand_size = sizeof(struct gre_base_hdr) + sizeof(struct iphdr);
        if (bpf_xdp_adjust_head(ctx, -expand_size)) {
            bpf_printk("softgre_apd: bpf_xdp_adjust_head failed");
            return XDP_ABORTED;
        }

        // Write IP Header at start of new head.
        struct iphdr *ip = (struct iphdr *)data;
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = bpf_htons(sizeof(struct iphdr));
        ip->protocol = IPPROTO_GRE;
        ip->check = 0;
        ip->saddr = d->src_ip.s_addr;
        ip->daddr = d->dst_ip.s_addr;

        // Write GRE Header after IP header.
        struct gre_base_hdr *gre = (struct gre_base_hdr *)(ip + 1);
        gre->flags = 0;
        gre->protocol = 0;

        return XDP_PASS;
    }

    // Decapsulation:
    // Otherwise, if the data is a SoftGRE packet, then we should check the source IP is in the IP
    // set, and if so, decapsulate it. Then we need to check the inner destination MAC, and if it's
    // either in the MAC map or a broadcast, then we should modify the packet bounds to finalize the
    // decapsulation and pass it up the stack. If that's not the case, then we should forward it
    // unmodified up the stack to ensure we don't interfere with another perhaps static GRE tunnel.

    // TODO: Check IP version is IPPROTO_GRE to determine if GRE Header is present.

    // // Check (untagged) IP EtherType.
    // if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { return XDP_PASS; }

    // // Check we can get a valid IP header.
    // struct iphdr *ip = (struct iphdr *)(eth + 1);
    // if ((void *)(ip + 1) > data_end) { return XDP_PASS; }

    // // Verify it's actually an IPv4 packet.
    // if (ip->version != 4) { return XDP_PASS; }

    // // Get the IP packet payload, up to the end of the data.
    // void *ip_payload = (void *)ip + (ip->ihl * 4);
    // if (ip_payload > data_end) { return XDP_PASS; }

    // // Check if source MAC matches a map entry.
    // struct Device *d = bpf_map_lookup_elem(&mac_map, &eth->h_source);
    // if (d) {
    //     bpf_printk("gns: found device for mac");
    // }

    return XDP_PASS;
}

char _license[] SEC("license") = "Proprietary";
