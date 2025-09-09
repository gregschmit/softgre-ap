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

#define ETH_BCAST_MAC {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
};

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
    __type(key, struct in_addr);
    __type(value, __u8);
} ip_set SEC(".maps");

static inline __u8 mac_eq(const __u8 *mac1, const __u8 *mac2) {
    for (int i = 0; i < ETH_ALEN; i++) {
        if (mac1[i] != mac2[i]) { return false; }
    }
    return true;
}

SEC("xdp")
int xdp_softgre_ap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check for valid Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { return XDP_PASS; }

    // Encapsulation:
    // If the source MAC is in the MAC map, then it's coming from a client, so we should encapsulate
    // the frame in an IP/GRE header and pass it up the stack.
    struct Device *src_device = bpf_map_lookup_elem(&mac_map, &eth->h_source);
    if (src_device) {
        bpf_printk("softgre_apd: encapsulate");
        unsigned short inner_size = data_end - data;

        // First, expand packet to cover both GRE header and IP header.
        // NOTE: Assumes we only need space for minimal (ihl=5) IP header.
        unsigned short outer_size = sizeof(struct gre_base_hdr) + sizeof(struct iphdr);
        if (bpf_xdp_adjust_head(ctx, -outer_size)) {
            bpf_printk("softgre_apd: bpf_xdp_adjust_head failed");
            return XDP_ABORTED;
        }

        // Must recalculate data pointers after bpf_xdp_adjust_head.
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        // Write IP Header at start of new head.
        // NOTE: This is a minimal IPv4 header (ihl=5).
        struct iphdr *ip = (struct iphdr *)data;
        __builtin_memset(ip, 0, sizeof(struct iphdr));
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = bpf_htons(outer_size + inner_size);
        ip->ttl = 64;  // Common default TTL.
        ip->protocol = IPPROTO_GRE;
        ip->check = 0;  // TODO: Calculate proper checksum.
        ip->saddr = src_device->src_ip.s_addr;
        ip->daddr = src_device->dst_ip.s_addr;

        // Write GRE Header after IP header.
        struct gre_base_hdr *gre = (struct gre_base_hdr *)(ip + 1);
        gre->flags = 0;
        gre->protocol = bpf_htons(ETH_P_TEB);  // Transparent Ethernet Bridging

        return XDP_PASS;
    }

    // Decapsulation:
    // Otherwise, if the data is a SoftGRE packet, then we should check the source IP is in the IP
    // set, and if so, decapsulate it. Then we need to check the inner destination MAC, and if it's
    // either in the MAC map or a broadcast, then we should modify the packet bounds to finalize the
    // decapsulation and pass it up the stack. If that's not the case, then we should forward it
    // unmodified up the stack to ensure we don't interfere with another perhaps static GRE tunnel.

    // Check (untagged) IP EtherType.
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { return XDP_PASS; }

    // Check for valid IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) { return XDP_PASS; }

    // Verify it's a minimal IPv4 GRE packet.
    // TODO: Need to verify that all softgre packets will be minimal?
    if (ip->version != 4) { return XDP_PASS; }
    if (ip->ihl != 5) { return XDP_PASS; }
    if (ip->protocol != IPPROTO_GRE) { return XDP_PASS; }

    // Check for valid simple GRE header with no flags and protocol TEB.
    struct gre_base_hdr *gre = (void *)ip + (ip->ihl * 4);
    if ((void *)(gre + 1) > data_end) { return XDP_PASS; }
    if (gre->flags != 0 || gre->protocol != bpf_htons(ETH_P_TEB)) { return XDP_PASS; }

    // Check source IP is in the IP set.
    if (!bpf_map_lookup_elem(&ip_set, &ip->saddr)) {
        bpf_printk("softgre_apd: source IP not in set");
        return XDP_PASS;
    }

    // Get the IP packet payload, up to the end of the data.
    void *inner_frame = (void *)(gre + 1);
    if (inner_frame >= data_end) { return XDP_PASS; }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = inner_frame;
    if ((void *)(inner_eth + 1) > data_end) { return XDP_PASS; }

    struct Device *dst_device = bpf_map_lookup_elem(&mac_map, &inner_eth->h_dest);
    __u8 bcast = mac_eq(inner_eth->h_dest, (const __u8 [])ETH_BCAST_MAC);
    if (dst_device || bcast) {
        bpf_printk("softgre_apd: decapsulate");

        // Shrink packet to remove GRE and IP headers.
        unsigned short shrink_size = sizeof(struct gre_base_hdr) + (ip->ihl * 4);
        if (bpf_xdp_adjust_head(ctx, shrink_size)) {
            bpf_printk("softgre_apd: bpf_xdp_adjust_head failed");
            return XDP_ABORTED;
        }

        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
