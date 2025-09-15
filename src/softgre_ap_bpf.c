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

// Kernel definitions that are missing from kernel headers due to BPF context restrictions. I have
// no idea why things like `ethhdr` and `iphdr` are available but not `gre_base_hdr`.
#define VLAN_VID_MASK 0x0fff
struct gre_base_hdr {
    __be16 flags;
    __be16 protocol;
};
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
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

static inline bool mac_eq(const uint8_t *mac1, const uint8_t *mac2) {
    for (uint8_t i = 0; i < ETH_ALEN; i++) {
        if (mac1[i] != mac2[i]) { return false; }
    }

    return true;
}

static inline __sum16 csum_fold(__wsum csum) {
    uint32_t sum = (uint32_t)csum;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__sum16)~sum;
}

// May modify skb, so pointers must be recalculated.
static inline bool enforce_vlan(struct __sk_buff *skb, Device *device) {
    if (device->vlan) {
        // Ensure the VLAN tag is present and correct.
        if (bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), device->vlan)) {
            BPF_DBG("Failed to push VLAN tag.");
            return false;
        }
    } else {
        // Remove VLAN tag, if present.
        if (skb->vlan_present && bpf_skb_vlan_pop(skb)) {
            BPF_DBG("Failed to remove VLAN tag.");
            return false;
        }
    }

    return true;
}

SEC("tc/ingress")
int bpf_softgre_ap(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Check for valid Ethernet header.
    struct ethhdr *outer_eth = data;
    if ((void *)(outer_eth + 1) > data_end) { return TC_ACT_OK; }

    if (DEBUGTEST) {
        Device *d = bpf_map_lookup_elem(&device_map, &outer_eth->h_source);
        if (d) {
            BPF_DBGV(
                "Frame from %02x:%02x:%02x:%02x:%02x:%02x (gre_ip: %pI4 vlan: %d).",
                outer_eth->h_source[0],
                outer_eth->h_source[1],
                outer_eth->h_source[2],
                outer_eth->h_source[3],
                outer_eth->h_source[4],
                outer_eth->h_source[5],
                &d->gre_ip,
                d->vlan
            );
        }
        return TC_ACT_OK;
    }

    // Encapsulation:
    // If the source MAC is in the Device map, then it's coming from a client, so we should
    // encapsulate the frame in an IP/GRE header and pass it up the stack.
    Device *src_dev = bpf_map_lookup_elem(&device_map, &outer_eth->h_source);
    if (src_dev) {
        BPF_DBGV("Encapsulating.");

        // Annotate the Device's ifindex if not already set.
        if (!src_dev->ifindex) {
            src_dev->ifindex = skb->ifindex;
            if (bpf_map_update_elem(&device_map, &outer_eth->h_source, src_dev, BPF_EXIST)) {
                BPF_DBG("Failed to update device ifindex.");
                return TC_ACT_SHOT;
            }

            // Also create/update a VLANCfg entry for this VLAN, if it doesn't already exist.
            VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &src_dev->vlan);
            if (vlan_cfg) {
                // Ensure src_dev->ifindex is in the ifindexes array.
                bool found = false;
                bool inserted = false;
                for (unsigned i = 0; i < MAX_INTERFACES; i++) {
                    if (vlan_cfg->ifindexes[i] == src_dev->ifindex) {
                        // Already present, so nothing to do.
                        found = true;
                        break;
                    } else if (vlan_cfg->ifindexes[i] == 0) {
                        // Found an empty slot, so add it here.
                        vlan_cfg->ifindexes[i] = src_dev->ifindex;
                        inserted = true;
                        break;
                    }
                }

                if (inserted) {
                    if (bpf_map_update_elem(&vlan_cfg_map, &src_dev->vlan, vlan_cfg, BPF_EXIST)) {
                        BPF_DBG("Failed to update VLAN config.");
                        return TC_ACT_SHOT;
                    }
                }

                if (!found && !inserted) {
                    BPF_DBG("VLAN cfg ifindexes full, cannot add ifindex %d.", src_dev->ifindex);
                    return TC_ACT_SHOT;
                }
             } else {
                // Create a new VLAN cfg.
                VLANCfg new_cfg = {.vlan = src_dev->vlan, .ifindexes = {0}};
                new_cfg.ifindexes[0] = src_dev->ifindex;
                if (bpf_map_update_elem(&vlan_cfg_map, &src_dev->vlan, &new_cfg, BPF_NOEXIST)) {
                    BPF_DBG("Failed to create VLAN config.");
                    return TC_ACT_SHOT;
                }
            }
        }

        // Get the IP config for this device.
        IPCfg *ip_cfg = bpf_map_lookup_elem(&ip_cfg_map, &src_dev->gre_ip);
        if (!ip_cfg) {
            BPF_DBG("No IP config for gre_ip %pI4.", &src_dev->gre_ip);
            return TC_ACT_OK;
        }

        // Enforce VLAN from Device entry, and update data pointers.
        if (!enforce_vlan(skb, src_dev)) {
            BPF_DBG("Failed to enforce VLAN.");
            return TC_ACT_SHOT;
        }
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        // Expand packet to cover outer Ethernet/GRE/IP header.
        // NOTE: Assumes we only need space for minimal (ihl=5) IP header.
        unsigned short inner_size = data_end - data;
        struct iphdr *ip = NULL;
        struct gre_base_hdr *gre = NULL;
        struct ethhdr *inner_eth = NULL;
        unsigned short outer_size = sizeof(*outer_eth) + sizeof(*ip) + sizeof(*gre);
        if (bpf_skb_adjust_room(skb, outer_size, BPF_ADJ_ROOM_MAC, 0)) {
            BPF_DBG("Failed to expand frame (`bpf_skb_adjust_room`).");
            return TC_ACT_SHOT;
        }

        // Update data pointers after expanding frame.
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        // Get location of outer Ethernet header.
        outer_eth = data;
        if ((void *)(outer_eth + 1) > data_end) {
            BPF_DBG("Outer Ethernet header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of outer IP header.
        ip = (struct iphdr *)(outer_eth + 1);
        if ((void *)(ip + 1) > data_end) {
            BPF_DBG("Outer IP header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of outer GRE header.
        gre = (struct gre_base_hdr *)(ip + 1);
        if ((void *)(gre + 1) > data_end) {
            BPF_DBG("GRE header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of inner Ethernet header.
        inner_eth = (struct ethhdr *)(gre + 1);
        if ((void *)(inner_eth + 1) > data_end) {
            BPF_DBG("Inner Ethernet header out of bounds after expand.");
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
        __builtin_memset(ip, 0, sizeof(*ip));
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = bpf_htons(inner_size + sizeof(*gre) + sizeof(*ip));
        ip->ttl = 64;  // Common default TTL.
        ip->protocol = IPPROTO_GRE;
        ip->saddr = ip_cfg->src_ip.s_addr;
        ip->daddr = ip_cfg->gre_ip.s_addr;
        __wsum csum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);
        ip->check = csum_fold(csum);

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
    if (bpf_ntohs(outer_eth->h_proto) != ETH_P_IP) { return TC_ACT_OK; }

    // Check for valid IP header.
    struct iphdr *ip = (struct iphdr *)(outer_eth + 1);
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

    Device *dst_dev = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
    bool bcast = mac_eq(inner_eth->h_dest, (const uint8_t[])ETH_BCAST_MAC);
    if (dst_dev || bcast) {
        BPF_DBGV("Decapsulating.");

        // Shrink packet to remove outer Ethernet/IP/GRE headers.
        unsigned short shrink_size = sizeof(*outer_eth) + (ip->ihl * 4) + sizeof(*gre);
        if (bpf_skb_adjust_room(skb, -shrink_size, BPF_ADJ_ROOM_MAC, 0)) {
            BPF_DBG("Failed to shrink frame (`bpf_skb_adjust_room`).");
            return TC_ACT_SHOT;
        }

        // Update data pointers after shrinking frame.
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        // "Inner" Ethernet header is now at the start of the packet.
        inner_eth = data;
        if ((void *)(inner_eth + 1) > data_end) {
            BPF_DBG("Inner Ethernet header out of bounds after shrink.");
            return TC_ACT_SHOT;
        }

        if (bcast) {
            // Extract VLAN ID from inner Ethernet header, if present.
            uint16_t vlan_id = 0;
            if (inner_eth->h_proto == bpf_htons(ETH_P_8021Q)) {
                struct vlan_hdr *vlan = (void *)(inner_eth + 1);
                if ((void *)(vlan + 1) > data_end) {
                    BPF_DBG("VLAN header out of bounds.");
                    return TC_ACT_SHOT;
                }
                vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
            }

            // Redirect to all interfaces hosting this VLAN, if any.
            VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &vlan_id);
            if (vlan_cfg) {
                for (unsigned i = 0; i < MAX_INTERFACES && vlan_cfg->ifindexes[i]; i++) {
                    bpf_clone_redirect(skb, vlan_cfg->ifindexes[i], 0);
                }
            }

            // Lose the original packet.
            return TC_ACT_SHOT;
        } else if (dst_dev) {
            // Check that this Device has an ifindex.
            if (!dst_dev->ifindex) {
                BPF_DBG("No ifindex for dst device.");
                return TC_ACT_SHOT;
            }

            // Redirect to the device's ifindex.
            return bpf_redirect(dst_dev->ifindex, 0);
        }
    }

    // All other cases, pass the packet up the stack unmodified.
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
