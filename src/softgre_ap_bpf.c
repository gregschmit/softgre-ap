/*
 * SoftGRE Access Point BPF Program
 *
 * This program handles encapsulation/decapsulation of Dynamic SoftGRE traffic.
 */

#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "shared.h"

#define ETH_BCAST_MAC {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
#define IP_MIN_IHL 5
#define DEFAULT_IP_TTL 64  // Reasonable default TTL.

#define DEBUGTEST 0

// Debug levels:
// 0: No debug output (default for performance, satisfy kernels that disallow printk).
// 1: Error conditions only (BPF_DBG).
// 2: Verbose debugging including normal operations (BPF_DBGV).
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
    __uint(max_entries, 4096);  // VLAN IDs are 12 bits.
    __type(key, uint16_t);
    __type(value, VLANCfg);
} vlan_cfg_map SEC(".maps");

// Compare two MAC addresses for equality.
static inline bool mac_eq(const uint8_t *mac1, const uint8_t *mac2) {
    return __builtin_memcmp(mac1, mac2, ETH_ALEN) == 0;
}

// Fold a 32-bit checksum into a 16-bit value.
static inline __sum16 csum_fold(__wsum csum) {
    uint32_t sum = (uint32_t)csum;

    // Add lower and upper 16-bit halves.
    sum = (sum & 0xffff) + (sum >> 16);

    // Add any carry from the previous addition.
    sum = (sum & 0xffff) + (sum >> 16);

    // Return one's complement of the result.
    return (__sum16)~sum;
}

// Validate header does not exceed packet bounds.
static inline bool validate_header_bounds(void *header, void *data_end, int32_t header_size) {
    // TODO: Remove cast?
    return (void *)header + header_size <= data_end;
}

// Update data pointers after skb modification.
static inline void update_data_pointers(struct __sk_buff *skb, void **data, void **data_end) {
    *data = (void *)(long)skb->data;
    *data_end = (void *)(long)skb->data_end;
}

SEC("tcx/ingress")
int bpf_softgre_ap(struct __sk_buff *skb) {
    long r;  // Return value of BPF helper functions.
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Check for valid Ethernet header.
    struct ethhdr *outer_eth = data;
    if (!validate_header_bounds(outer_eth, data_end, sizeof(*outer_eth))) { return TC_ACT_OK; }

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

    // Encapsulation path:
    // If the source MAC is in the device map, this is a frame from a known client. We encapsulate
    // it in Eth/IP/GRE headers and forward it to the appropriate interface.
    Device *src_dev = bpf_map_lookup_elem(&device_map, &outer_eth->h_source);
    if (src_dev) {
        BPF_DBGV("Encapsulating.");

        // Ensure Ethernet frame is not VLAN-tagged.
        if (
            outer_eth->h_proto == bpf_htons(ETH_P_8021Q) ||
            outer_eth->h_proto == bpf_htons(ETH_P_8021AD)
        ) {
            BPF_DBGV("DROP; VLAN tagged frame received; not supported.");
            return TC_ACT_SHOT;
        }

        // Annotate the Device's ifindex if not already set.
        if (!src_dev->ifindex) {
            src_dev->ifindex = skb->ifindex;
            if ((r = bpf_map_update_elem(&device_map, &outer_eth->h_source, src_dev, BPF_EXIST))) {
                BPF_DBG("DROP; Failed to update device ifindex (%ld).", r);
                return TC_ACT_SHOT;
            }
        }

        // Ensure we have a VLAN config entry; update if necessary.
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
                if ((r = bpf_map_update_elem(&vlan_cfg_map, &src_dev->vlan, vlan_cfg, BPF_EXIST))) {
                    BPF_DBG("DROP; Failed to update VLAN config (%ld).", r);
                    return TC_ACT_SHOT;
                }
            }

            if (!found && !inserted) {
                BPF_DBG("DROP; VLAN cfg ifindexes full, cannot add ifindex %d.", src_dev->ifindex);
                return TC_ACT_SHOT;
            }
        } else {
            // Create a new VLAN cfg.
            VLANCfg new_cfg = {.vlan = src_dev->vlan, .ifindexes = {0}};
            new_cfg.ifindexes[0] = src_dev->ifindex;
            if ((r = bpf_map_update_elem(&vlan_cfg_map, &src_dev->vlan, &new_cfg, BPF_NOEXIST))) {
                BPF_DBG("DROP; Failed to create VLAN config (%ld).", r);
                return TC_ACT_SHOT;
            }
        }

        // Get the IP config for this device.
        IPCfg *ip_cfg = bpf_map_lookup_elem(&ip_cfg_map, &src_dev->gre_ip);
        if (!ip_cfg) {
            BPF_DBG("DROP; No IP config for gre_ip %pI4.", &src_dev->gre_ip);
            return TC_ACT_SHOT;
        }

        // Get outer Ethernet header.
        outer_eth = data;
        if (!validate_header_bounds(outer_eth, data_end, sizeof(*outer_eth))) {
            BPF_DBG("DROP; Outer Ethernet header out of bounds after VLAN pop.");
            return TC_ACT_SHOT;
        }

        // Expand packet to cover outer Ethernet/GRE/IP header, and inner VLAN header, if needed.
        // NOTE: Assumes we only need space for minimal (ihl=5) IP header.
        struct iphdr *ip = NULL;
        struct gre_base_hdr *gre = NULL;
        struct ethhdr *inner_eth = NULL;
        struct vlan_hdr *inner_vlan = NULL;
        uint32_t expand_size = sizeof(*outer_eth) + sizeof(*ip) + sizeof(*gre);
        if (src_dev->vlan) {
            expand_size += sizeof(*inner_vlan);
        }
        // Useful when debugging when expanding fails.
        // BPF_DBGV("About to expand frame by %ld bytes.", expand_size);
        // BPF_DBGV(
        //     "Packet pkt_type: %d protocol: 0x%04x vlan_present: %d",
        //     skb->pkt_type,
        //     bpf_ntohs(skb->protocol),
        //     skb->vlan_present
        // );
        // Have to use `bpf_skb_change_head otherwise it will error for e.g. ARP packets.
        if ((r = bpf_skb_change_head(skb, expand_size, 0))) {
            BPF_DBG("DROP; Failed to expand frame (%ld).", r);
            return TC_ACT_SHOT;
        }
        // TODO: Consider re-enabling to prevent VLAN spoofing or accidental Q-in-Q.
        // if ((r = bpf_skb_vlan_pop(skb))) {
        //     BPF_DBG("DROP; Failed to remove existing VLAN tag (%ld).", r);
        //     return TC_ACT_SHOT;
        // }
        update_data_pointers(skb, &data, &data_end);

        // Get location of outer Ethernet header.
        outer_eth = data;
        if (!validate_header_bounds(outer_eth, data_end, sizeof(*outer_eth))) {
            BPF_DBG("DROP; Outer Ethernet header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of IP header.
        ip = (struct iphdr *)(outer_eth + 1);
        if (!validate_header_bounds(ip, data_end, sizeof(*ip))) {
            BPF_DBG("DROP; IP header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of GRE header.
        gre = (struct gre_base_hdr *)(ip + 1);
        if (!validate_header_bounds(gre, data_end, sizeof(*gre))) {
            BPF_DBG("DROP; GRE header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Get location of inner Ethernet header.
        inner_eth = (struct ethhdr *)(gre + 1);
        if (!validate_header_bounds(inner_eth, data_end, sizeof(*inner_eth))) {
            BPF_DBG("DROP; Inner Ethernet header out of bounds after expand.");
            return TC_ACT_SHOT;
        }

        // Write inner VLAN header, if needed.
        if (src_dev->vlan) {
            inner_vlan = (struct vlan_hdr *)(inner_eth + 1);
            if (!validate_header_bounds(inner_vlan, data_end, sizeof(*inner_vlan))) {
                BPF_DBG("DROP; Inner VLAN header out of bounds after expand.");
                return TC_ACT_SHOT;
            }

            // First, after expand, the inner Ethernet header is actually positioned after the GRE
            // header plus the size of a VLAN header. We need to move it back to the proper location
            // so we have room to write the VLAN header.
            // NOTE: We have to use memmove here instead of memcpy because the regions overlap.
            struct ethhdr *true_inner_eth = (void *)(gre + 1) + sizeof(*inner_vlan);
            if (!validate_header_bounds(true_inner_eth, data_end, sizeof(*true_inner_eth))) {
                BPF_DBG("DROP; True inner Ethernet header out of bounds after expand.");
                return TC_ACT_SHOT;
            }
            __builtin_memmove(inner_eth, true_inner_eth, sizeof(*inner_eth));

            // Now we can write the inner VLAN header, and update the inner Ethernet header's proto.
            inner_vlan->h_vlan_TCI = bpf_htons(src_dev->vlan);
            inner_vlan->h_vlan_encapsulated_proto = inner_eth->h_proto;
            inner_eth->h_proto = bpf_htons(ETH_P_8021Q);
        }

        // Write outer Ethernet header with zeroed src/dst MAC addresses; bpf_redirect_neigh() will
        // populate these fields automatically.
        __builtin_memset(outer_eth, 0, sizeof(*outer_eth));
        outer_eth->h_proto = bpf_htons(ETH_P_IP);

        // Write outer IP header (minimal ihl=5 without options).
        __builtin_memset(ip, 0, sizeof(*ip));
        ip->version = 4;
        ip->ihl = IP_MIN_IHL;
        ip->tot_len = bpf_htons((void *)data_end - (void *)ip);
        ip->ttl = DEFAULT_IP_TTL;
        ip->protocol = IPPROTO_GRE;
        ip->saddr = ip_cfg->src_ip.s_addr;
        ip->daddr = ip_cfg->gre_ip.s_addr;
        __wsum csum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);
        ip->check = csum_fold(csum);

        // Write outer GRE header.
        gre->flags = 0;
        gre->protocol = bpf_htons(ETH_P_TEB);

        // Fix packet type for broadcast packets (like ARP) to try to make them go out. Right now
        // they seem to be silently dropped...
        bpf_skb_change_type(skb, PACKET_OUTGOING);

        BPF_DBGV(
            "Redirecting pkt_type: %d protocol: 0x%04x", skb->pkt_type, bpf_ntohs(skb->protocol)
        );

        return bpf_redirect_neigh(ip_cfg->ifindex, NULL, 0, 0);
    }

    // Decapsulation path:
    // For GRE packets from authorized sources, we decapsulate and forward based on the inner
    // destination MAC:
    // - If destination is in device map: forward to specific device.
    // - If destination is broadcast: clone to all devices on the VLAN.
    // - Otherwise: pass through unmodified to avoid interfering with other tunnels.

    // Check (untagged) IP EtherType.
    if (bpf_ntohs(outer_eth->h_proto) != ETH_P_IP) { return TC_ACT_OK; }

    // Check for valid IP header.
    struct iphdr *ip = (struct iphdr *)(outer_eth + 1);
    if (!validate_header_bounds(ip, data_end, sizeof(*ip))) {
        return TC_ACT_OK;
    }

    // Verify it's a minimal IPv4 GRE packet.
    if (ip->version != 4) { return TC_ACT_OK; }
    if (ip->ihl != IP_MIN_IHL) { return TC_ACT_OK; }
    if (ip->protocol != IPPROTO_GRE) { return TC_ACT_OK; }

    // Check for valid simple GRE header with no flags and protocol TEB.
    struct gre_base_hdr *gre = (void *)ip + (ip->ihl * 4);
    if (!validate_header_bounds(gre, data_end, sizeof(*gre))) {
        return TC_ACT_OK;
    }
    if (gre->flags || gre->protocol != bpf_htons(ETH_P_TEB)) { return TC_ACT_OK; }

    // Check source IP is in the IP config map.
    if (!bpf_map_lookup_elem(&ip_cfg_map, &ip->saddr)) {
        BPF_DBGV("PASS; Source IP not in IP cfg map.");
        return TC_ACT_OK;
    }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = (void *)(gre + 1);
    if (!validate_header_bounds(inner_eth, data_end, sizeof(*inner_eth))) {
        return TC_ACT_OK;
    }

    Device *dst_dev = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
    bool bcast = mac_eq(inner_eth->h_dest, (const uint8_t[])ETH_BCAST_MAC);
    if (dst_dev || bcast) {
        BPF_DBGV("Decapsulating.");

        // Save inner Ethernet/VLAN headers before shrinking.
        struct ethhdr saved_inner_eth;
        struct vlan_hdr saved_inner_vlan;
        uint16_t vlan_id = 0;
        __builtin_memcpy(&saved_inner_eth, inner_eth, sizeof(saved_inner_eth));
        if (inner_eth->h_proto == bpf_htons(ETH_P_8021Q)) {
            struct vlan_hdr *inner_vlan = (void *)(inner_eth + 1);
            if (!validate_header_bounds(inner_vlan, data_end, sizeof(*inner_vlan))) {
                BPF_DBG("DROP; Inner VLAN header out of bounds.");
                return TC_ACT_SHOT;
            }
            __builtin_memcpy(&saved_inner_vlan, inner_vlan, sizeof(saved_inner_vlan));
            vlan_id = bpf_ntohs(inner_vlan->h_vlan_TCI) & VLAN_VID_MASK;
        }

        // Shrink packet to remove outer Ethernet/IP/GRE headers and remove any VLAN metadata.
        int32_t shrink_size = sizeof(*outer_eth) + (ip->ihl * 4) + sizeof(*gre);
        if ((r = bpf_skb_adjust_room(skb, -shrink_size, BPF_ADJ_ROOM_MAC, 0))) {
            BPF_DBG("DROP; Failed to shrink frame (%ld).", r);
            return TC_ACT_SHOT;
        }
        if ((r = bpf_skb_vlan_pop(skb))) {
            BPF_DBG("DROP; Failed to remove VLAN metadata (%ld).", r);
            return TC_ACT_SHOT;
        }
        update_data_pointers(skb, &data, &data_end);

        // Copy saved inner Ethernet header to the start of the packet.
        inner_eth = data;
        if (!validate_header_bounds(inner_eth, data_end, sizeof(*inner_eth))) {
            BPF_DBG("DROP; Ethernet header out of bounds after shrink.");
            return TC_ACT_SHOT;
        }
        __builtin_memcpy(inner_eth, &saved_inner_eth, sizeof(saved_inner_eth));

        // Copy saved inner VLAN header, if present.
        if (vlan_id) {
            struct vlan_hdr *inner_vlan = (void *)(inner_eth + 1);
            if (!validate_header_bounds(inner_vlan, data_end, sizeof(*inner_vlan))) {
                BPF_DBG("DROP; VLAN header out of bounds after shrink.");
                return TC_ACT_SHOT;
            }
            __builtin_memcpy(inner_vlan, &saved_inner_vlan, sizeof(saved_inner_vlan));
        }

        if (bcast) {
            // Redirect to all interfaces hosting this VLAN, if any.
            BPF_DBGV("Decap broadcasting on VLAN %d.", vlan_id);
            VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &vlan_id);
            if (vlan_cfg) {
                for (unsigned i = 0; i < MAX_INTERFACES && vlan_cfg->ifindexes[i]; i++) {
                    BPF_DBGV("CLONE; Decap broadcasting to ifindex %d.", vlan_cfg->ifindexes[i]);
                    bpf_clone_redirect(skb, vlan_cfg->ifindexes[i], 0);
                }
            }

            // Lose the original packet.
            return TC_ACT_SHOT;
        } else if (dst_dev) {
            // Check that this Device has an ifindex.
            if (!dst_dev->ifindex) {
                BPF_DBG("DROP; No ifindex for dst device.");
                return TC_ACT_SHOT;
            }

            // Redirect to the device's ifindex.
            BPF_DBGV("REDIR; Decap redirecting on VLAN %d to ifindex %d.", vlan_id, dst_dev->ifindex);
            return bpf_redirect(dst_dev->ifindex, 0);
        }
    }

    // All other cases, pass the packet up the stack unmodified.
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
