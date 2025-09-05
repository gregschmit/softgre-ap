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

// static const unsigned char target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const unsigned char target_mac[6] = {0xe2, 0x0b, 0x11, 0x8c, 0x75, 0x4b};

// Shared map for MAC to Device mappings.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, MAC_SIZE);
    __uint(value_size, sizeof(struct Device));
    __uint(max_entries, MAX_DEVICES);
} mac_map SEC(".maps");

#define VLAN_ID 99
#define ETH_P_8021Q 0x8100

SEC("xdp")
int xdp_softgre_ap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check if we have enough data for ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check if source MAC matches our target
    if (__builtin_memcmp(eth->h_source, target_mac, 6) == 0) {
        bpf_printk("gns: found packet!");

        // Test map access by looking up the first sample MAC address
        unsigned char test_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        struct Device *d = bpf_map_lookup_elem(&mac_map, &test_mac);
        if (d) {
            bpf_printk(
                "gns: Found MAC: %02x:%02x:%02x:%02x:%02x:%02x, IP: %pI4, VLAN: %u",
                d->mac[0],
                d->mac[1],
                d->mac[2],
                d->mac[3],
                d->mac[4],
                d->mac[5],
                &d->ip.s_addr,
                d->vlan
            );
        } else {
            bpf_printk("gns: MAC not found");
        }

        // Note: FCS recalculation is typically handled by the network hardware
        // when the packet is transmitted. XDP programs don't usually need to
        // manually recalculate FCS as it's handled at the driver/hardware level.
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Proprietary";
