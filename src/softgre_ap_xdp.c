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

#include "shared.h"

#define ETH_BCAST_MAC {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define DEBUGTEST 0

struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
};

// Shared map (MAC -> Device).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, sizeof(struct Device));
} device_map SEC(".maps");

// Shared map (GRE IP -> IPCfg).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);  // Would never be larger than the amount of devices.
    __type(key, struct in_addr);
    __type(value, struct IPCfg);
} ip_cfg_map SEC(".maps");

static inline __u8 mac_eq(const __u8 *mac1, const __u8 *mac2) {
    for (__u8 i = 0; i < ETH_ALEN; i++) {
        if (mac1[i] != mac2[i]) { return 0; }
    }
    return 1;
}

static inline __u16 ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;

    // Sum all 16-bit words in the IP header.
    __u16 *ptr = (__u16 *)ip;
    for (int i = 0; i < (ip->ihl * 4) / 2; i++) {
        csum += ptr[i];
    }

    // Fold carry bits.
    while (csum >> 16) {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }

    // Return one's complement.
    return ~csum;
}

SEC("xdp")
int xdp_softgre_ap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check for valid Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { return XDP_PASS; }

    if (DEBUGTEST) {
        struct Device *d = bpf_map_lookup_elem(&device_map, &eth->h_source);
        if (d) {
            bpf_printk(
                "softgre_apd: packet from %02x:%02x:%02x:%02x:%02x:%02x (gre_ip: %pI4 vlan: %d)",
                eth->h_source[0],
                eth->h_source[1],
                eth->h_source[2],
                eth->h_source[3],
                eth->h_source[4],
                eth->h_source[5],
                &d->gre_ip,
                d->vlan
            );
        }
        return XDP_PASS;
    }

    // Encapsulation:
    // If the source MAC is in the Device map, then it's coming from a client, so we should
    // encapsulate the frame in an IP/GRE header and pass it up the stack.
    struct Device *src_device = bpf_map_lookup_elem(&device_map, &eth->h_source);
    if (src_device) {
        bpf_printk("softgre_apd: encapsulate");

        // Get the IP config for this device.
        struct IPCfg *ip_cfg = bpf_map_lookup_elem(&ip_cfg_map, &src_device->gre_ip);
        if (!ip_cfg) {
            bpf_printk("softgre_apd: no IP config for gre_ip %pI4", &src_device->gre_ip);
            return XDP_PASS;
        }

        // Expand packet to cover both GRE header and IP header.
        // NOTE: Assumes we only need space for minimal (ihl=5) IP header.
        unsigned short inner_size = data_end - data;
        struct ethhdr *outer_eth = NULL;
        struct iphdr *outer_ip = NULL;
        struct gre_base_hdr *gre = NULL;
        unsigned short outer_size = sizeof(*gre) + sizeof(*outer_ip) + sizeof(*outer_eth);
        if (bpf_xdp_adjust_head(ctx, -outer_size)) {
            bpf_printk("softgre_apd: bpf_xdp_adjust_head failed");
            return XDP_ABORTED;
        }

        // Must recalculate data pointers after adjusting head.
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        // Write Ethernet Header. Zero out the src/dst and we will use `bpf_redirect_neigh` to let
        // the kernel fill them in.
        outer_eth = data;
        if ((void *)(outer_eth + 1) > data_end) {
            bpf_printk("softgre_apd: outer ethhdr out of bounds");
            return XDP_ABORTED;
        }
        __builtin_memset(outer_eth, 0, sizeof(*outer_eth));
        outer_eth->h_proto = bpf_htons(ETH_P_IP);

        // Write IP Header.
        // NOTE: This is a minimal IPv4 header (ihl=5).
        outer_ip = (struct iphdr *)(outer_eth + 1);
        if ((void *)(outer_ip + 1) > data_end) {
            bpf_printk("softgre_apd: outer iphdr out of bounds");
            return XDP_ABORTED;
        }
        __builtin_memset(outer_ip, 0, sizeof(*outer_ip));
        outer_ip->version = 4;
        outer_ip->ihl = 5;
        outer_ip->tot_len = bpf_htons(outer_size + inner_size);
        outer_ip->ttl = 64;  // Common default TTL.
        outer_ip->protocol = IPPROTO_GRE;
        outer_ip->saddr = ip_cfg->src_ip.s_addr;
        outer_ip->daddr = ip_cfg->gre_ip.s_addr;
        outer_ip->check = ip_checksum(outer_ip);

        // Write GRE Header after IP header.
        gre = (struct gre_base_hdr *)(outer_ip + 1);
        if ((void *)(gre + 1) > data_end) {
            bpf_printk("softgre_apd: gre header out of bounds");
            return XDP_ABORTED;
        }
        gre->flags = 0;
        gre->protocol = bpf_htons(ETH_P_TEB);  // Transparent Ethernet Bridging

        return bpf_redirect_neigh(ip_cfg->ifindex, NULL, 0, 0);
    }

    // Decapsulation:
    // Otherwise, if the data is a SoftGRE packet, then we should check the source IP is in the IP
    // set, and if so, decapsulate it. Then we need to check the inner destination MAC, and if it's
    // either in the Device map or a broadcast, then we should modify the packet bounds to finalize
    // the decapsulation and pass it up the stack. If that's not the case, then we should forward it
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

    // Check source IP is in the IP map.
    if (!bpf_map_lookup_elem(&ip_cfg_map, &ip->saddr)) {
        bpf_printk("softgre_apd: source IP not in IP map");
        return XDP_PASS;
    }

    // Get the IP packet payload, up to the end of the data.
    void *inner_frame = (void *)(gre + 1);
    if (inner_frame >= data_end) { return XDP_PASS; }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = inner_frame;
    if ((void *)(inner_eth + 1) > data_end) { return XDP_PASS; }

    struct Device *dst_device = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
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
