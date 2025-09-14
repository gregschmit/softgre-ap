/*
 * Code for shared definitions.
 *
 * NOTE: While the definitions are shared between kernel and userspace, the functions here are only
 * for the userspace daemon. Therefore, use of standard library is allowed.
 */

#include <string.h>

#include "shared.h"

int DEBUG = 0;

bool device__key_eq(const uint8_t *key1, const uint8_t *key2) {
    return memcmp(key1, key2, ETH_ALEN) == 0;
}

bool ip_cfg__key_eq(const struct in_addr *key1, const struct in_addr *key2) {
    return key1->s_addr == key2->s_addr;
}

// Use the src_ip to determine validity. In the program logic, if there is a problem populating part
// of the config, then the src_ip should be set to 0.
bool ip_cfg__is_valid(const IPCfg *ip_cfg) {
    if (!ip_cfg) { return false; }
    if (ip_cfg->src_ip.s_addr == 0) { return false; }

    return true;
}
