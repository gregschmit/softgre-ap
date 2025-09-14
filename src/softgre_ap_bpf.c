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

// Debug level 0 is the default to turn off printk entirely to avoid the performance hit, and to
// satisfy kernels that don't allow use of printk from BPF programs.
//
// DBG is primarily for error conditions that should never happen in normal operation.
// DBGV is for more verbose and detailed information.
#if BPF_DEBUG > 1
#define BPF_DBGV(fmt, ...) bpf_printk("softgre_ap: " fmt, ##__VA_ARGS__)
#else
#define BPF_DBGV(fmt, ...) do { } while (0)
#endif
#if BPF_DEBUG > 0
#define BPF_DBG(fmt, ...) bpf_printk("softgre_ap: " fmt, ##__VA_ARGS__)
#else
#define BPF_DBG(fmt, ...) do { } while (0)
#endif

struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, sizeof(Device));
} device_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);  // Would never be larger than the amount of devices.
    __type(key, struct in_addr);
    __type(value, IPCfg);
} ip_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __type(key, uint16_t);
    __type(value, VLANCfg);
} vlan_cfg_map SEC(".maps");

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
        Device *d = bpf_map_lookup_elem(&device_map, &eth->h_source);
        if (d) {
            BPF_DBGV(
                "Frame from %02x:%02x:%02x:%02x:%02x:%02x (gre_ip: %pI4 vlan: %d).",
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
    Device *src_device = bpf_map_lookup_elem(&device_map, &eth->h_source);
    if (src_device) {
        BPF_DBGV("Encapsulating.");

        // Annotate the Device's ifindex if not already set.
        if (!src_device->ifindex) {
            src_device->ifindex = skb->ifindex;
            if (bpf_map_update_elem(&device_map, &eth->h_source, src_device, BPF_EXIST)) {
                BPF_DBG("Failed to update device ifindex.");
                return TC_ACT_SHOT;
            }

            // Also create/update a VLANCfg entry for this VLAN, if it doesn't already exist.
            __u16 vlan_id = 0;
            VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &vlan_id);
            if (vlan_cfg) {
                // Ensure src_device->ifindex is in the ifindexes array.
                __u8 found = 0;
                __u8 inserted = 0;
                for (unsigned i = 0; i < MAX_INTERFACES; i++) {
                    if (vlan_cfg->ifindexes[i] == src_device->ifindex) {
                        // Already present, so nothing to do.
                        found = 1;
                        break;
                    } else if (vlan_cfg->ifindexes[i] == 0) {
                        // Found an empty slot, so add it here.
                        vlan_cfg->ifindexes[i] = src_device->ifindex;
                        inserted = 1;
                        break;
                    }
                }

                if (inserted) {
                    if (bpf_map_update_elem(&vlan_cfg_map, &vlan_id, vlan_cfg, BPF_EXIST)) {
                        BPF_DBG("Failed to update VLAN config.");
                        return TC_ACT_SHOT;
                    }
                }

                if (!found && !inserted) {
                    BPF_DBG("VLAN cfg ifindexes full, cannot add ifindex %d.", src_device->ifindex);
                    return TC_ACT_SHOT;
                }
             } else {
                // Create a new VLAN cfg.
                VLANCfg new_vlan_cfg = {.vlan = vlan_id, .ifindexes = {0}};
                new_vlan_cfg.ifindexes[0] = src_device->ifindex;
                if (bpf_map_update_elem(&vlan_cfg_map, &vlan_id, &new_vlan_cfg, BPF_NOEXIST)) {
                    BPF_DBG("Failed to create VLAN config.");
                    return TC_ACT_SHOT;
                }
            }
        }

        // Get the IP config for this device.
        IPCfg *ip_cfg = bpf_map_lookup_elem(&ip_cfg_map, &src_device->gre_ip);
        if (!ip_cfg) {
            BPF_DBG("No IP config for gre_ip %pI4.", &src_device->gre_ip);
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
            BPF_DBG("Failed to expand frame (`bpf_skb_adjust_room`).");
            return TC_ACT_SHOT;
        }

        // Must recalculate data pointers after adjusting head.
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        // Get location of outer Ethernet header.
        outer_eth = data;
        if ((void *)(outer_eth + 1) > data_end) {
            BPF_DBG("Outer Ethernet header out of bounds after adjust.");
            return TC_ACT_SHOT;
        }

        // Get location of outer IP header.
        outer_ip = (struct iphdr *)(outer_eth + 1);
        if ((void *)(outer_ip + 1) > data_end) {
            BPF_DBG("Outer IP header out of bounds after adjust.");
            return TC_ACT_SHOT;
        }

        // Get location of outer GRE header.
        gre = (struct gre_base_hdr *)(outer_ip + 1);
        if ((void *)(gre + 1) > data_end) {
            BPF_DBG("GRE header out of bounds after adjust.");
            return TC_ACT_SHOT;
        }

        // Get location of inner Ethernet header.
        inner_eth = (struct ethhdr *)(gre + 1);
        if ((void *)(inner_eth + 1) > data_end) {
            BPF_DBG("Inner Ethernet header out of bounds after adjust.");
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
    if (gre->flags || gre->protocol != bpf_htons(ETH_P_TEB)) { return TC_ACT_OK; }

    // Check source IP is in the IP config map.
    if (!bpf_map_lookup_elem(&ip_cfg_map, &ip->saddr)) {
        BPF_DBGV("Source IP not in IP cfg map.");
        return TC_ACT_OK;
    }

    // Get the IP packet payload, up to the end of the data.
    void *inner_frame = (void *)(gre + 1);
    if (inner_frame >= data_end) { return TC_ACT_OK; }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = inner_frame;
    if ((void *)(inner_eth + 1) > data_end) { return TC_ACT_OK; }

    Device *dst_device = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
    __u8 bcast = mac_eq(inner_eth->h_dest, (const __u8 [])ETH_BCAST_MAC);
    if (dst_device || bcast) {
        BPF_DBGV("Decapsulating.");

        // Shrink packet to remove GRE and IP headers.
        unsigned short shrink_size = sizeof(struct gre_base_hdr) + (ip->ihl * 4);
        if (bpf_skb_adjust_room(skb, -shrink_size, BPF_ADJ_ROOM_MAC, 0)) {
            BPF_DBG("Failed to shrink frame (`bpf_skb_adjust_room`).");
            return TC_ACT_SHOT;
        }
    }

    if (dst_device) {
        // Check that this Device has an ifindex.
        if (!dst_device->ifindex) {
            BPF_DBG("No ifindex for dst device.");
            return TC_ACT_SHOT;
        }

        // Redirect to the device's ifindex.
        return bpf_redirect(dst_device->ifindex, 0);
    } else if (bcast) {
        // Redirect to all interfaces hosting native devices.
        __u16 vlan_id = 0;
        VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &vlan_id);
        if (vlan_cfg) {
            for (unsigned i = 0; i < MAX_INTERFACES && vlan_cfg->ifindexes[i]; i++) {
                bpf_clone_redirect(skb, vlan_cfg->ifindexes[i], 0);
            }
        }

        // Lose the original packet.
        return TC_ACT_SHOT;
    }

    // All other cases, pass the packet up the stack unmodified.
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
