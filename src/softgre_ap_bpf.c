/*
 * SoftGRE Access Point BPF Program
 *
 * This program handles encapsulation/decapsulation of Dynamic SoftGRE traffic.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

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

static inline __sum16 csum_fold(__wsum csum) {
    __u32 sum = (__u32)csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

SEC("tc/ingress")
int bpf_softgre_ap(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Check for valid Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) { return TC_ACT_OK; }

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
        return TC_ACT_OK;
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
            return TC_ACT_OK;
        }

        // Expand packet to cover both GRE header and IP header.
        // NOTE: Assumes we only need space for minimal (ihl=5) IP header.
        unsigned short inner_size = data_end - data;
        struct ethhdr *inner_eth = NULL;
        struct ethhdr *outer_eth = NULL;
        struct iphdr *outer_ip = NULL;
        struct gre_base_hdr *gre = NULL;
        unsigned short outer_size = sizeof(*gre) + sizeof(*outer_ip) + sizeof(*outer_eth);
        if (bpf_skb_adjust_room(skb, outer_size, BPF_ADJ_ROOM_MAC, 0)) {
            bpf_printk("softgre_apd: bpf_skb_adjust_room on encap failed");
            return TC_ACT_SHOT;
        }

        // Must recalculate data pointers after adjusting head.
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        // Get location of outer Ethernet header.
        outer_eth = data;
        if ((void *)(outer_eth + 1) > data_end) {
            bpf_printk("softgre_apd: outer ethhdr out of bounds after adjust");
            return TC_ACT_SHOT;
        }

        // Get location of outer IP header.
        outer_ip = (struct iphdr *)(outer_eth + 1);
        if ((void *)(outer_ip + 1) > data_end) {
            bpf_printk("softgre_apd: outer iphdr out of bounds after adjust");
            return TC_ACT_SHOT;
        }

        // Get location of outer GRE header.
        gre = (struct gre_base_hdr *)(outer_ip + 1);
        if ((void *)(gre + 1) > data_end) {
            bpf_printk("softgre_apd: gre header out of bounds after adjust");
            return TC_ACT_SHOT;
        }

        // Get location of inner Ethernet header.
        inner_eth = (struct ethhdr *)(gre + 1);
        if ((void *)(inner_eth + 1) > data_end) {
            bpf_printk("softgre_apd: inner ethhdr out of bounds after adjust");
            return TC_ACT_SHOT;
        }

        // Outer Ethernet header contains inner Ethernet header data; copy to inner Ethernet
        // header location.
        __builtin_memmove(inner_eth, outer_eth, sizeof(*outer_eth));

        // Write outer Ethernet header. Zero out the src/dst and we will use `bpf_redirect_neigh` to
        // let the kernel fill them in.
        __builtin_memset(outer_eth, 0, sizeof(*outer_eth));
        outer_eth->h_proto = bpf_htons(ETH_P_IP);

        // Write outer IP header.
        // NOTE: This is a minimal IPv4 header (ihl=5).
        __builtin_memset(outer_ip, 0, sizeof(*outer_ip));
        outer_ip->version = 4;
        outer_ip->ihl = 5;
        outer_ip->tot_len = bpf_htons(inner_size + sizeof(*gre) + sizeof(*outer_ip));
        outer_ip->ttl = 64;  // Common default TTL.
        outer_ip->protocol = IPPROTO_GRE;
        outer_ip->saddr = ip_cfg->src_ip.s_addr;
        outer_ip->daddr = ip_cfg->gre_ip.s_addr;
        // outer_ip->check = ip_checksum(outer_ip, data_end);
        __wsum csum = bpf_csum_diff(0, 0, (__be32 *)outer_ip, sizeof(*outer_ip), 0);
        outer_ip->check = csum_fold(csum);

        // Write outer GRE header.
        gre->flags = 0;
        gre->protocol = bpf_htons(ETH_P_TEB);  // Transparent Ethernet Bridging

        return bpf_redirect_neigh(ip_cfg->ifindex, NULL, 0, 0);
    }

    // Decapsulation:
    // Otherwise, if the data is a GRE packet, then we should check the source IP is in the IP
    // config map, and if so, decapsulate it. Then we need to check the inner destination MAC, and
    // if it's either in the Device map or a broadcast, then we should modify the packet bounds to
    // finalize the decapsulation and pass it up the stack. If that's not the case, then we should
    // forward it unmodified up the stack to ensure we don't interfere with another perhaps static
    // GRE tunnel.

    // Check (untagged) IP EtherType.
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { return TC_ACT_OK; }

    // Check for valid IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) { return TC_ACT_OK; }

    // Verify it's a minimal IPv4 GRE packet.
    // TODO: Need to verify that all softgre packets will be minimal?
    if (ip->version != 4) { return TC_ACT_OK; }
    if (ip->ihl != 5) { return TC_ACT_OK; }
    if (ip->protocol != IPPROTO_GRE) { return TC_ACT_OK; }

    // Check for valid simple GRE header with no flags and protocol TEB.
    struct gre_base_hdr *gre = (void *)ip + (ip->ihl * 4);
    if ((void *)(gre + 1) > data_end) { return TC_ACT_OK; }
    if (gre->flags != 0 || gre->protocol != bpf_htons(ETH_P_TEB)) { return TC_ACT_OK; }

    // Check source IP is in the IP config map.
    if (!bpf_map_lookup_elem(&ip_cfg_map, &ip->saddr)) {
        bpf_printk("softgre_apd: source IP not in IP config map");
        return TC_ACT_OK;
    }

    // Get the IP packet payload, up to the end of the data.
    void *inner_frame = (void *)(gre + 1);
    if (inner_frame >= data_end) { return TC_ACT_OK; }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = inner_frame;
    if ((void *)(inner_eth + 1) > data_end) { return TC_ACT_OK; }

    struct Device *dst_device = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
    __u8 bcast = mac_eq(inner_eth->h_dest, (const __u8 [])ETH_BCAST_MAC);
    if (dst_device || bcast) {
        bpf_printk("softgre_apd: decapsulate");

        // Shrink packet to remove GRE and IP headers.
        unsigned short shrink_size = sizeof(struct gre_base_hdr) + (ip->ihl * 4);
        if (bpf_skb_adjust_room(skb, -shrink_size, BPF_ADJ_ROOM_MAC, 0)) {
            bpf_printk("softgre_apd: bpf_skb_adjust_room on decap failed");
            return TC_ACT_SHOT;
        }

        return TC_ACT_OK;
    }

    // All other cases, pass the packet up the stack unmodified.
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
