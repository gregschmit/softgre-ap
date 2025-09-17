/*
 * SoftGRE Access Point BPF Programs
 *
 * This file consists of two BPF programs, an XDP component and a TC component.
 *
 * The XDP component is responsible for ensuring packets originating from clients are untagged,
 * doing the encapsulation and decapsulation. The TC component is responsible for using helpers to
 * fill in L2 headers and redirecting/duplicating packets as needed.
 *
 * This separation is necessary because:
 * - The XDP component's packet modifications are respected by the rest of the network stack. If it
 *   encapsulates an ARP packet, it will be recognized as an IPv4 packet by the rest of the stack.
 *   This is not true in the TC component, where modifying the skb->protocol is not allowed, and
 *   helpers like `bpf_skb_change_proto` are only allowed to convert between IPv4 and IPv6.
 * - The TC component can duplicate packets and has access to `bpf_redirect_neigh`, which can let
 *   the kernel neighboring subsystem fill in the L2 header for us, which avoids us having to manage
 *   ARP data ourselves.
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

// Metadata macros and structs.
#define METADATA_SIG 0xd700b1f0  // Arbitrary signature to identify our metadata.
typedef struct {
    unsigned ifindex;
} MetadataEncap;
typedef struct {
    unsigned ifindex;
    uint16_t vlan;
} MetadataDecap;
enum MetadataType {
    METADATA_ENCAP,
    METADATA_DECAP,
};
typedef struct {
    uint32_t signature;
    enum MetadataType type;
    union {
        MetadataEncap encap;
        MetadataDecap decap;
    } data;
} Metadata;

#define DEBUGTEST 0

// Debug levels:
// 0: No debug output (default for performance, satisfy kernels that disallow printk).
// 1: Error conditions only (XDP_DBG/TCI_DBG/BPF_DBG).
// 2: Verbose debugging including normal operations (XDP_DBGV/TCI_DBGV/BPF_DBGV).
#if BPF_DEBUG > 1
#define XDP_DBGV(fmt, ...) bpf_printk("dtuninit_xdp: " fmt, ##__VA_ARGS__)
#define TCX_DBGV(fmt, ...) bpf_printk("dtuninit_tci: " fmt, ##__VA_ARGS__)
#define BPF_DBGV(fmt, ...) bpf_printk("dtuninit: " fmt, ##__VA_ARGS__)
#else
#define XDP_DBGV(fmt, ...) do { } while (0)
#define TCX_DBGV(fmt, ...) do { } while (0)
#define BPF_DBGV(fmt, ...) do { } while (0)
#endif
#if BPF_DEBUG > 0
#define XDP_DBG(fmt, ...) bpf_printk("dtuninit_xdp: " fmt, ##__VA_ARGS__)
#define TCX_DBG(fmt, ...) bpf_printk("dtuninit_tci: " fmt, ##__VA_ARGS__)
#define BPF_DBG(fmt, ...) bpf_printk("dtuninit: " fmt, ##__VA_ARGS__)
#else
#define XDP_DBG(fmt, ...) do { } while (0)
#define TCX_DBG(fmt, ...) do { } while (0)
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

static inline bool validate_header_bounds(void *header, void *end, int32_t header_size) {
    // TODO: Remove cast?
    return (void *)header + header_size <= end;
}

// static inline void skb_update_data_ptrs(struct __sk_buff *skb, void **data, void **data_end) {
//     *data = (void *)(long)skb->data;
//     *data_end = (void *)(long)skb->data_end;
// }

static inline void xdp_update_data_ptrs(struct xdp_md *ctx, void **data, void **data_end) {
    *data = (void *)(long)ctx->data;
    *data_end = (void *)(long)ctx->data_end;
}

static inline void debug_test(struct ethhdr *eth) {
    Device *d = bpf_map_lookup_elem(&device_map, &eth->h_source);
    if (d) {
        BPF_DBG(
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
}

// Encapsulate a packet in outer Eth/IP/GRE headers and return an XDP action code. This is only
// possible in XDP, as TC cannot modify the packet protocol.
static inline int xdp_encapsulate(struct xdp_md *ctx, Device *device) {
    XDP_DBGV("Encapsulating.");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    long r;  // Return code for BPF helpers.

    // Get Ethernet header.
    struct ethhdr *eth = data;
    if (!validate_header_bounds(eth, data_end, sizeof(*eth))) {
        XDP_DBG("DROP; Ethernet header out of bounds.");
        return XDP_DROP;
    }

    // Ensure Ethernet frame is not VLAN-tagged.
    if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
        XDP_DBGV("DROP; VLAN tagged frame received; not supported.");
        return XDP_DROP;
    }

    // Annotate the Device's ifindex if not already set.
    if (!device->ifindex) {
        device->ifindex = ctx->ingress_ifindex;
        if ((r = bpf_map_update_elem(&device_map, &eth->h_source, device, BPF_EXIST))) {
            XDP_DBG("DROP; Failed to update device ifindex (%ld).", r);
            return XDP_DROP;
        }
    }

    // Ensure we have a VLAN config entry; update if necessary.
    VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &device->vlan);
    if (vlan_cfg) {
        // Ensure device->ifindex is in the ifindexes array.
        bool found = false;
        bool inserted = false;
        for (unsigned i = 0; i < MAX_INTERFACES; i++) {
            if (vlan_cfg->ifindexes[i] == device->ifindex) {
                // Already present, so nothing to do.
                found = true;
                break;
            } else if (vlan_cfg->ifindexes[i] == 0) {
                // Found an empty slot, so add it here.
                vlan_cfg->ifindexes[i] = device->ifindex;
                inserted = true;
                break;
            }
        }

        if (inserted) {
            if ((r = bpf_map_update_elem(&vlan_cfg_map, &device->vlan, vlan_cfg, BPF_EXIST))) {
                XDP_DBG("DROP; Failed to update VLAN config (%ld).", r);
                return XDP_DROP;
            }
        }

        if (!found && !inserted) {
            XDP_DBG("DROP; VLAN cfg ifindexes full, cannot add ifindex %d.", device->ifindex);
            return XDP_DROP;
        }
    } else {
        // Create a new VLAN cfg.
        VLANCfg new_cfg = {.vlan = device->vlan, .ifindexes = {0}};
        new_cfg.ifindexes[0] = device->ifindex;
        if ((r = bpf_map_update_elem(&vlan_cfg_map, &device->vlan, &new_cfg, BPF_NOEXIST))) {
            XDP_DBG("DROP; Failed to create VLAN config (%ld).", r);
            return XDP_DROP;
        }
    }

    // Get the IP config for this device.
    IPCfg *ip_cfg = bpf_map_lookup_elem(&ip_cfg_map, &device->gre_ip);
    if (!ip_cfg) {
        XDP_DBG("DROP; No IP config for gre_ip %pI4.", &device->gre_ip);
        return XDP_DROP;
    }

    // Expand packet to cover outer Ethernet/GRE/IP header, and inner VLAN header, if needed.
    // NOTE: Assumes we only need space for minimal IP header.
    int expand_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct gre_base_hdr);
    if (device->vlan) {
        expand_size += sizeof(struct vlan_hdr);
    }
    if ((r = bpf_xdp_adjust_head(ctx, -expand_size))) {
        XDP_DBG("DROP; Failed to expand frame (%ld).", r);
        return XDP_DROP;
    }
    xdp_update_data_ptrs(ctx, &data, &data_end);

    // Write outer Ethernet header. Zero the src/dst MAC addresses as the TCI component will
    // complete them.
    struct ethhdr *outer_eth = (struct ethhdr *)data;
    if (!validate_header_bounds(outer_eth, data_end, sizeof(*outer_eth))) {
        XDP_DBG("DROP; Outer Ethernet header out of bounds after expand.");
        return XDP_DROP;
    }
    __builtin_memset(outer_eth, 0, sizeof(*outer_eth));
    outer_eth->h_proto = bpf_htons(ETH_P_IP);

    // Write minimal IP header.
    struct iphdr *ip = (struct iphdr *)(outer_eth + 1);
    if (!validate_header_bounds(ip, data_end, sizeof(*ip))) {
        XDP_DBG("DROP; IP header out of bounds after expand.");
        return XDP_DROP;
    }
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

    // Write GRE header.
    struct gre_base_hdr *gre = (struct gre_base_hdr *)(ip + 1);
    if (!validate_header_bounds(gre, data_end, sizeof(*gre))) {
        XDP_DBG("DROP; GRE header out of bounds after expand.");
        return XDP_DROP;
    }
    gre->flags = 0;
    gre->protocol = bpf_htons(ETH_P_TEB);

    // Get location of inner Ethernet header.
    struct ethhdr *inner_eth = (struct ethhdr *)(gre + 1);
    if (!validate_header_bounds(inner_eth, data_end, sizeof(*inner_eth))) {
        XDP_DBG("DROP; Inner Ethernet header out of bounds after expand.");
        return XDP_DROP;
    }

    // Write inner VLAN header, if needed.
    if (device->vlan) {
        struct vlan_hdr *inner_vlan = (struct vlan_hdr *)(inner_eth + 1);
        if (!validate_header_bounds(inner_vlan, data_end, sizeof(*inner_vlan))) {
            XDP_DBG("DROP; Inner VLAN header out of bounds after expand.");
            return XDP_DROP;
        }

        // If we need a VLAN header, when when we expanded the packet, the inner Ethernet header
        // ends up actually positioned after the GRE header plus the size of a VLAN header. We
        // need to move it back to the proper location so we have room to write the VLAN header.
        // NOTE: Use memmove, as the regions overlap.
        struct ethhdr *true_inner_eth = (void *)(gre + 1) + sizeof(*inner_vlan);
        if (!validate_header_bounds(true_inner_eth, data_end, sizeof(*true_inner_eth))) {
            XDP_DBG("DROP; True inner Ethernet header out of bounds after expand.");
            return XDP_DROP;
        }
        __builtin_memmove(inner_eth, true_inner_eth, sizeof(*inner_eth));

        // Now we can write the inner VLAN header, and update the inner Ethernet header's proto.
        inner_vlan->h_vlan_TCI = bpf_htons(device->vlan);
        inner_vlan->h_vlan_encapsulated_proto = inner_eth->h_proto;
        inner_eth->h_proto = bpf_htons(ETH_P_8021Q);
    }

    // Annotate that we have encapsulated.
    if ((r = bpf_xdp_adjust_meta(ctx, -(int)sizeof(Metadata)))) {
        XDP_DBG("DROP; Failed to adjust meta (%ld).", r);
        return XDP_DROP;
    }
    xdp_update_data_ptrs(ctx, &data, &data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    Metadata *md = (Metadata *)data_meta;
    if (!validate_header_bounds(md, data, sizeof(*md))) {
        XDP_DBG("DROP; Metadata out of bounds after adjust.");
        return XDP_DROP;
    }
    md->signature = METADATA_SIG;
    md->type = METADATA_ENCAP;
    md->data.encap.ifindex = ip_cfg->ifindex;

    return XDP_PASS;
}

static inline int xdp_decapsulate(
    struct xdp_md *ctx, uint8_t ihl, Device *device, uint16_t vlan, struct ethhdr *untagged_eth
) {
    XDP_DBGV("Decapsulating.");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    long r;  // Return code for BPF helpers.

    // Shrink packet to remove outer Ethernet/IP/GRE and inner VLAN headers.
    int32_t shrink_size = sizeof(struct ethhdr) + (ihl * 4) + sizeof(struct gre_base_hdr);
    if (vlan) {
        shrink_size += sizeof(struct vlan_hdr);
    }
    if ((r = bpf_xdp_adjust_head(ctx, shrink_size))) {
        XDP_DBG("DROP; Failed to shrink frame (%ld).", r);
        return XDP_DROP;
    }

    // Write untagged Ethernet header, if needed.
    if (vlan) {
        xdp_update_data_ptrs(ctx, &data, &data_end);
        struct ethhdr *eth = data;
        if (!validate_header_bounds(eth, data_end, sizeof(*eth))) {
            XDP_DBG("DROP; Ethernet header out of bounds after shrink.");
            return XDP_DROP;
        }
        *eth = *untagged_eth;
    }

    // Annotate that we have decapsulated.
    if ((r = bpf_xdp_adjust_meta(ctx, -(int)sizeof(Metadata)))) {
        XDP_DBG("DROP; Failed to adjust meta (%ld).", r);
        return XDP_DROP;
    }
    xdp_update_data_ptrs(ctx, &data, &data_end);
    void *data_meta = (void *)(long)ctx->data_meta;
    Metadata *md = (Metadata *)data_meta;
    if (!validate_header_bounds(md, data, sizeof(*md))) {
        XDP_DBG("DROP; Metadata out of bounds after adjust.");
        return XDP_DROP;
    }
    md->signature = METADATA_SIG;
    md->type = METADATA_DECAP;
    md->data.decap.vlan = vlan;
    md->data.decap.ifindex = device ? device->ifindex : 0;

    return XDP_PASS;
}

SEC("xdp")
int dtuninit_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check for Ethernet header.
    struct ethhdr *eth = data;
    if (!validate_header_bounds(eth, data_end, sizeof(*eth))) { return XDP_PASS; }

    if (DEBUGTEST) {
        debug_test(eth);
        return XDP_PASS;
    }

    // ENCAPSULATION:
    // If source MAC is a known client, encapsulate and pass to TC for processing.
    Device *src_dev = bpf_map_lookup_elem(&device_map, &eth->h_source);
    if (src_dev) {
        return xdp_encapsulate(ctx, src_dev);
    }

    // DECAPSULATION:
    // If this is a GRE packet from a known GRE IP, decapsulate and pass to TC for processing.

    // Check (untagged) IP EtherType.
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { return XDP_PASS; }

    // Check for valid IP header.
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_header_bounds(ip, data_end, sizeof(*ip))) { return XDP_PASS; }

    // Verify it's a minimal IPv4 GRE packet.
    if (ip->version != 4) { return XDP_PASS; }
    if (ip->ihl != IP_MIN_IHL) { return XDP_PASS; }
    if (ip->protocol != IPPROTO_GRE) { return XDP_PASS; }

    // Check for valid simple GRE header with no flags and protocol TEB.
    struct gre_base_hdr *gre = (void *)ip + (ip->ihl * 4);
    if (!validate_header_bounds(gre, data_end, sizeof(*gre))) { return XDP_PASS; }
    if (gre->flags || gre->protocol != bpf_htons(ETH_P_TEB)) { return XDP_PASS; }

    // Check source IP is in the IP config map.
    if (!bpf_map_lookup_elem(&ip_cfg_map, &ip->saddr)) { return XDP_PASS; }

    // Get the inner Ethernet header.
    struct ethhdr *inner_eth = (void *)(gre + 1);
    if (!validate_header_bounds(inner_eth, data_end, sizeof(*inner_eth))) { return XDP_PASS; }

    // Get VLAN, if present.
    uint16_t vlan_id = 0;
    struct ethhdr untagged_eth = *inner_eth;
    if (inner_eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)(inner_eth + 1);
        if (!validate_header_bounds(vlan, data_end, sizeof(*vlan))) { return XDP_PASS; }
        vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
        untagged_eth.h_proto = vlan->h_vlan_encapsulated_proto;
    }

    bool bcast = mac_eq(inner_eth->h_dest, (const uint8_t[])ETH_BCAST_MAC);
    Device *dst_dev = bpf_map_lookup_elem(&device_map, &inner_eth->h_dest);
    if (bcast || dst_dev) {
        return xdp_decapsulate(ctx, ip->ihl, dst_dev, vlan_id, &untagged_eth);
    }

    return XDP_PASS;
}

SEC("tcx/ingress")
int dtuninit_tci(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_meta = (void *)(long)skb->data_meta;
    Metadata *md = (Metadata *)data_meta;

    // Pass packets without our metadata.
    if (!validate_header_bounds(md, data, sizeof(*md))) { return TC_ACT_OK; }
    if (md->signature != METADATA_SIG) { return TC_ACT_OK; }

    // ENCAPSULATION:
    // If the XDP program encapsulated, handle L2 data and redirect to ifindex.
    if (md->type == METADATA_ENCAP) {
        TCX_DBGV("NEIGH; Encap to ifindex %d.", md->data.encap.ifindex);
        return bpf_redirect_neigh(md->data.encap.ifindex, NULL, 0, 0);
    }

    // DECAPSULATION:
    // If the XDP program decapsulated, then forward based on the destination MAC.
    if (md->type == METADATA_DECAP) {
        if (md->data.decap.ifindex) {
            // Unicast to specific interface.
            TCX_DBGV(
                "REDIR; Decap on VLAN %d to ifindex %d.",
                md->data.decap.vlan,
                md->data.decap.ifindex
            );
            return bpf_redirect(md->data.decap.ifindex, 0);
        } else {
            // Get VLAN config.
            VLANCfg *vlan_cfg = bpf_map_lookup_elem(&vlan_cfg_map, &md->data.decap.vlan);
            if (!vlan_cfg) {
                TCX_DBG("No VLAN config for VLAN %d.", md->data.decap.vlan);
                return TC_ACT_SHOT;
            }

            // Broadcast to all interfaces in the VLAN config.
            TCX_DBGV("Decap broadcast on VLAN %d.", md->data.decap.vlan);
            for (unsigned i = 0; i < MAX_INTERFACES && vlan_cfg->ifindexes[i]; i++) {
                TCX_DBGV("CLONE; Decap to ifindex %d.", vlan_cfg->ifindexes[i]);
                bpf_clone_redirect(skb, vlan_cfg->ifindexes[i], 0);
            }

            // Lose the original packet.
            return TC_ACT_SHOT;
        }
    }

    // All other cases, pass the packet up the stack unmodified.
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
