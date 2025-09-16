/*
 * Shared definitions for the BPF program and the userspace daemon.
 *
 * WARNING: Since these definitions are shared between kernel and userspace, they must only use
 * features available in both contexts, or conditionally use equivalent features based on the
 * compilation context.
 */

#ifndef SHARED_H
#define SHARED_H

// Detect BPF compilation context. Indented for readability.
#ifdef __BPF__

// BPF program: use kernel headers.
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/types.h>

// NOTE: I am choosing not to use the BPF CO-RE method of building a `vmlinux.h` file and including
// it, because that resulting file excludes kernel macros (such as `ETH_*`), and then you cannot
// include linux kernel headers to get those missing macros, because then there will be conflicts
// with the `vmlinux.h` file. I have found it better to use the kernel headers, and then define any
// missing types (that seem to be omitted in BPF context) here.

// Define types that are not available in BPF context. I have no idea why including `linux/types.h`
// doesn't define these. This is another weird spot where I would expect to be able to use `u32`,
// for example, and I could with BPF CO-RE, but that has other disadvantages as mentioned above, so
// I'm sticking to just defining the types I want to use here.
typedef __s32 int32_t;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef _Bool bool;
#define true 1
#define false 0

#else

// Userspace daemon: use standard library headers.
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#endif  // __BPF__

#define MAX_DEVICES 1024
#define MAX_INTERFACES 32

extern bool DEBUG;

typedef struct {
    uint8_t mac[ETH_ALEN];  // Key
    struct in_addr gre_ip;
    uint16_t vlan;

    unsigned ifindex;
    uint8_t cycle;  // For removing stale entries.
} Device;

typedef struct {
    struct in_addr gre_ip;  // Key
    struct in_addr src_ip;
    // Might need these. Currently trying to use bpf_redirect_neigh to hopefully be able to just
    // let the kernel handle the ethhdr.
    // uint8_t dst_mac[ETH_ALEN];
    // uint8_t src_mac[ETH_ALEN];
    unsigned ifindex;
    uint8_t cycle;  // For removing stale entries.
} IPCfg;

typedef struct {
    uint16_t vlan;
    unsigned ifindexes[MAX_INTERFACES];
} VLANCfg;

#ifndef __BPF__
bool device__key_eq(const uint8_t *key1, const uint8_t *key2);
bool ip_cfg__key_eq(const struct in_addr *key1, const struct in_addr *key2);
bool ip_cfg__is_valid(const IPCfg *ip_cfg);
#endif  // __BPF__

#endif  // SHARED_H
