/*
 * SoftGRE Access Point Daemon
 *
 * This daemon loads/unload the BPF program and monitors the mapping file to keep the BPF maps
 * updated.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/socket.h>
#include <ifaddrs.h>
#include <linux/bpf.h>
#include <linux/if_packet.h>

#include "list.h"
#include "log.h"
#include "shared.h"
#include "watch.h"
#include "bpf_state.h"

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_BPF "softgre_ap_bpf.o"

// Must fit the largest map entry; e.g. `FF:FF:FF:FF:FF:FF 255.255.255.255 4095\0`.
#define MAX_LINE_SIZE 39

volatile bool INTERRUPT = false;

// Static storage to hold all interface names, if needed.
#define ALL_IFS_MAX_STRLEN 256
static char ALL_IFS[MAX_INTERFACES][ALL_IFS_MAX_STRLEN] = {0};
static char *ALL_IFS_PTRS[MAX_INTERFACES] = {0};

void interrupt_handler(int _signum) {
    INTERRUPT = true;
}

bool populate_ip_cfg_src_ip(IPCfg *ip_cfg) {
    // Create UDP socket.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errno("socket");
        return false;
    }

    // Set up dst address.
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(53);  // DNS port, but any port works.
    dst_addr.sin_addr = ip_cfg->gre_ip;

    // Connect to destination (this doesn't actually send packets for UDP).
    if (connect(sockfd, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
        log_errno("connect");
        close(sockfd);
        return false;
    }

    // Get the local address the kernel assigned.
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    if (getsockname(sockfd, (struct sockaddr*)&src_addr, &src_addr_len) < 0) {
        log_errno("getsockname");
        close(sockfd);
        return false;
    }

    // Copy the src IP.
    ip_cfg->src_ip = src_addr.sin_addr;

    close(sockfd);

    return true;
}

bool populate_ip_cfg_ifindex(IPCfg *ip_cfg) {
    if (!ip_cfg) { return false; }

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        log_errno("getifaddrs");
        return false;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) { continue; }

        // If this is an IPv4 address and it matches, set ifindex and break.
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;

            if (sin->sin_addr.s_addr == ip_cfg->src_ip.s_addr) {
                ip_cfg->ifindex = if_nametoindex(ifa->ifa_name);
                break;
            }

            // NOTE: If needed in future, could also get netmask here with ifa->ifa_netmask.
        }
    }

    // NOTE: If needed in future, could also get L2 data here by:
    //   - Checking `ifa->ifa_addr->sa_family == AF_PACKET`.
    //   - Casting to `struct sockaddr_ll *` and copying `sll_addr` to `ip_cfg->src_mac`.
    //   - Inspecting `sll_ifindex`.
    // This would probably have to be done in a separate loop after the above loop, because
    // `AF_PACKET` is not guaranteed to come after `AF_INET` and in my experience it typically comes
    // before. But we would want to match the IP addr first.

    freeifaddrs(ifaddr);
    return ip_cfg->ifindex != 0;
}

// Ensure `src_ip` is set to 0 if any of the population steps fail.
bool populate_ip_cfg(IPCfg *ip_cfg) {
    if (!ip_cfg || !ip_cfg->gre_ip.s_addr) { return false; }

    // Determine src IP for this GRE IP.
    if (!populate_ip_cfg_src_ip(ip_cfg)) {
        log_error("Failed to determine src IP for GRE IP: %s", inet_ntoa(ip_cfg->gre_ip));
        ip_cfg->src_ip.s_addr = 0;
        return false;
    }

    // Determine ifindex.
    if (!populate_ip_cfg_ifindex(ip_cfg)) {
        log_error("Failed to determine ifindex for src IP: %s", inet_ntoa(ip_cfg->src_ip));
        ip_cfg->src_ip.s_addr = 0;
        return false;
    }

    return true;
}

void parse_map_file(const char *path, List *devices, List *ip_cfgs, uint8_t cycle) {
    if (!devices || !ip_cfgs) { return; }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) {
            // It's actually a normal condition for the file to not exist.
            dbg_errno("fopen");
        } else {
            // Other errors should be logged.
            log_errno("fopen");
            log_error("Failed to open map file.");
        }
        return;
    }

    // Read file line by line into the device list.
    char linebuf[MAX_LINE_SIZE] = "";
    while (fgets(linebuf, sizeof(linebuf), fp)) {
        // Ignore comments.
        if (linebuf[0] == '#') { continue; }

        // Parse the line, logging but otherwise disregarding any errors.
        Device device = {.cycle = cycle};
        char gre_ip[16] = "";
        int res = sscanf(
            linebuf,
            "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %15s %hu",
            &device.mac[0],
            &device.mac[1],
            &device.mac[2],
            &device.mac[3],
            &device.mac[4],
            &device.mac[5],
            gre_ip,
            &device.vlan
        );

        if (res != 8) {
            log_error("Failed to parse line: `%s`", linebuf);
            continue;
        }

        if (!inet_pton(AF_INET, gre_ip, &device.gre_ip)) {
            log_error("Failed to parse GRE IP: `%s`", gre_ip);
            continue;
        }

        // See if we already have an IP Config.
        IPCfg *ip_cfg = list__find(ip_cfgs, &device.gre_ip);
        if (ip_cfg) {
            // If the config is not valid, then we previously failed to populate it, so skip this
            // device.
            if (!ip_cfg__is_valid(ip_cfg)) {
                continue;
            }
        } else {
            // We haven't seen this GRE IP before, so populate a new IP config and add it to the
            // list. If we fail to populate it fully, then skip this device. But add the IP config
            // regardless so we don't try again for subsequent devices with the same GRE IP.
            IPCfg ip_cfg = {.gre_ip = device.gre_ip, .cycle = cycle};
            if (!populate_ip_cfg(&ip_cfg)) {
                log_error("Failed to populate IP config for IP: %s", gre_ip);
                continue;
            }

            if (!list__add(ip_cfgs, &ip_cfg)) {
                log_error("Failed to add IP config for IP: %s", gre_ip);
                continue;
            }
        }

        if (!list__add(devices, &device)) {
            log_error("Failed to add device for MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                device.mac[0],
                device.mac[1],
                device.mac[2],
                device.mac[3],
                device.mac[4],
                device.mac[5]
            );
        }
    }

    fclose(fp);
}

void update_bpf_map(BPFState *state, const char *map_path) {
    if (!state) {
        log_error("BPF state is NULL.");
        return;
    }

    if (!state->obj) {
        log_error("BPF state obj doesn't exist.");
        return;
    }

    // Get the map objects.
    struct bpf_map *device_map = bpf_state__get_device_map(state);
    if (!device_map) {
        log_error("Failed to get Device map.");
        return;
    }
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) {
        log_error("Failed to get IP Config map.");
        return;
    }

    // Create device and IP config lists.
    List *devices = list__new(
        sizeof(Device), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)device__key_eq
    );
    if (!devices) { return; }
    List *ip_cfgs = list__new(
        sizeof(IPCfg), sizeof(struct in_addr), (list__key_eq_t)ip_cfg__key_eq
    );
    if (!ip_cfgs) {
        list__free(devices);
        return;
    }

    // Bump the state cycle.
    state->cycle++;

    // Parse map file to populate the lists.
    parse_map_file(map_path, devices, ip_cfgs, state->cycle);
    if (!devices->length) {
        list__free(devices);
        list__free(ip_cfgs);
        return;
    }
    if (!ip_cfgs->length) {
        list__free(devices);
        list__free(ip_cfgs);
        return;
    }

    // Update the IP config map.
    for (size_t i = 0; i < ip_cfgs->length; i++) {
        IPCfg ip_cfg = ((IPCfg *)ip_cfgs->items)[i];

        if (bpf_map__update_elem(
            ip_cfg_map,
            &ip_cfg.gre_ip,
            sizeof(ip_cfg.gre_ip),
            &ip_cfg,
            sizeof(ip_cfg),
            BPF_ANY
        )) {
            log_error("Failed to update IP map for GRE IP: %s", inet_ntoa(ip_cfg.gre_ip));
            continue;
        }
    }

    // Update the device map.
    for (size_t i = 0; i < devices->length; i++) {
        Device device = ((Device *)devices->items)[i];
        if (bpf_map__update_elem(
            device_map,
            &device.mac,
            sizeof(device.mac),
            &device,
            sizeof(device),
            BPF_ANY
        )) {
            log_error("Failed to update Device map for MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                device.mac[0],
                device.mac[1],
                device.mac[2],
                device.mac[3],
                device.mac[4],
                device.mac[5]
            );
            continue;
        }
    }

    // Remove stale entries.
    bpf_state__remove_stale_devices(state, devices);
    bpf_state__remove_stale_ip_cfgs(state, ip_cfgs);

    list__free(devices);
    list__free(ip_cfgs);
}

unsigned populate_all_ifs() {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        log_errno("getifaddrs");
        return 0;
    }

    unsigned count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (count >= MAX_INTERFACES) { break; }
        if (ifa->ifa_addr == NULL) { continue; }

        // Only consider L2 interfaces.
        if (ifa->ifa_addr->sa_family != AF_PACKET) { continue; }

        // Cast to sockaddr_ll to access hardware type.
        struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;

        // Skip loopback and non-ethernet interfaces.
        if (sll->sll_hatype != ARPHRD_ETHER) { continue; }

        // Check if we already have this interface.
        bool found = false;
        for (unsigned i = 0; i < count; i++) {
            if (strcmp(ALL_IFS[i], ifa->ifa_name) == 0) {
                found = true;
                break;
            }
        }
        if (found) { continue; }

        // Add the interface name to the list.
        strncpy(ALL_IFS[count], ifa->ifa_name, ALL_IFS_MAX_STRLEN - 1);
        ALL_IFS[count][ALL_IFS_MAX_STRLEN - 1] = '\0';
        count++;
    }

    freeifaddrs(ifaddr);
    return count;
}

int main(int argc, char *argv[]) {
    int clear_existing = 0;
    int foreground = 0;
    char bpf_path[PATH_MAX + 1] = "";
    char map_path[PATH_MAX + 1] = DEFAULT_MAP;

    // If this program was invoked with a path, then assume the BPF program is in the same
    // directory.
    char *last_slash = strrchr(argv[0], '/');
    if (last_slash != NULL) {
        int len = last_slash - argv[0];
        snprintf(bpf_path, sizeof(bpf_path), "%.*s/" DEFAULT_BPF, len, argv[0]);

        // Check if that file DOESN'T exist, and if so, clear the `bpf_path`.
        FILE *fp = fopen(bpf_path, "r");
        if (fp == NULL) {
            bpf_path[0] = '\0';
        } else {
            fclose(fp);
        }
    }

    // If that file doesn't exist, try to find using PATH.
    char *path_env = getenv("PATH");
    char *path_env_copy = strdup(path_env);
    if (path_env_copy == NULL) {
        log_errno("strdup");
        log_error("Failed to duplicate PATH environment variable.");
        return 1;
    }
    if (bpf_path[0] == '\0' && path_env != NULL) {
        char *path = strtok(path_env_copy, ":");
        while (path != NULL) {
            snprintf(bpf_path, sizeof(bpf_path), "%s/" DEFAULT_BPF, path);
            FILE *fp = fopen(bpf_path, "r");
            if (fp != NULL) {
                fclose(fp);
                break;
            }
            bpf_path[0] = '\0';
            path = strtok(NULL, ":");
        }
    }
    free(path_env_copy);
    path_env_copy = NULL;

    int ch;
    char version[256] = "softgre_apd " VERSION;
    char usage[1024] = "softgre_apd " VERSION "\n\n"
        "Usage: softgre_apd [-dfVh] [interface(s)...]\n"
        "Options:\n"
        "  -c         Clear existing BPF programs on interfaces.\n"
        "  -d         Enable debug logging.\n"
        "  -f         Foreground mode (no daemonization).\n"
        "  -m FILE    Map file (default: " DEFAULT_MAP ").\n"
        "  -x FILE    BPF program file (default: neighbor " DEFAULT_BPF " or PATH\n"
        "             " DEFAULT_BPF ").\n"
        "  -V         Show version.\n"
        "  -h -?      Show usage.\n";
    while ((ch = getopt(argc, argv, "cdfm:x:Vh?")) != -1) {
        switch (ch) {
            case 'c': {
                clear_existing = 1;
                // TODO: Implement.
                break;
            }
            case 'd': {
                DEBUG = 1;
                break;
            }
            case 'f': {
                foreground = 1;
                // TODO: Implement.
                break;
            }
            case 'm': {
                int map_length = strlen(optarg);
                if (map_length <= 0) {
                    log_error("Invalid map file.");
                    return 1;
                } else if (map_length > PATH_MAX) {
                    log_error("Map file path is too long.");
                    return 1;
                } else {
                    strcpy(map_path, optarg);
                }
                break;
            }
            case 'x': {
                int bpf_length = strlen(optarg);
                if (bpf_length <= 0) {
                    log_error("Invalid BPF program file.");
                    return 1;
                } else if (bpf_length > PATH_MAX) {
                    log_error("BPF program file path is too long.");
                    return 1;
                } else {
                    strcpy(bpf_path, optarg);
                }

                FILE *fp = fopen(bpf_path, "r");
                if (fp == NULL) {
                    log_errno("fopen");
                    log_error("BPF program file could not be opened.");
                    return 1;
                } else {
                    fclose(fp);
                }
                break;
            }
            case 'V': {
                printf("%s\n", version);
                exit(0);
                break;
            }
            case 'h':
            case '?': {
                printf("%s\n", usage);
                exit(0);
                break;
            }
            default: {
                fprintf(stderr, "%s\n", usage);
                exit(1);
                break;
            }
        }
    }

    // Check that we have an BPF program.
    if (bpf_path[0] == '\0') {
        log_error("No BPF program found.");
        return 1;
    }

    // Check if BPF program can be read.
    FILE *fp = fopen(bpf_path, "r");
    if (fp == NULL) {
        log_errno("fopen");
        log_error("BPF program file could not be opened.");
        return 1;
    } else {
        fclose(fp);
    }

    // Register signal handlers.
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    // Organize interface list.
    unsigned num_ifs = 0;
    char **ifs = NULL;
    if (optind >= argc) {
        log_info("No interfaces specified; defaulting to all Ethernet interfaces.");
        num_ifs = populate_all_ifs();

        // Create array of pointers to each interface string.
        for (unsigned i = 0; i < MAX_INTERFACES && i < num_ifs; i++) {
            ALL_IFS_PTRS[i] = ALL_IFS[i];
        }
        ifs = ALL_IFS_PTRS;
    } else {
        num_ifs = argc - optind;
        ifs = argv + optind;

        // Enforce max interfaces.
        if (num_ifs > MAX_INTERFACES) {
            log_info("Max interfaces is %d; truncating list.", MAX_INTERFACES);
            num_ifs = MAX_INTERFACES;
        }
    }

    if (num_ifs == 0) {
        log_error("No interfaces available.");
        return 1;
    } else {
        log_info("Will attempt to bind to %d interface(s):", num_ifs);
        for (unsigned i = 0; i < num_ifs; i++) {
            log_info("  - %s", ifs[i]);
        }
    }

    // Load the BPF program onto selected interfaces.
    log_info("Loading BPF program (bpf: %s, map: %s).", bpf_path, map_path);
    BPFState *state = bpf_state__open(bpf_path, num_ifs, ifs);
    if (!state) {
        log_error("Failed to load BPF program.");
        exit(1);
    }

    // Initial map load.
    update_bpf_map(state, map_path);

    // Watch the map file for changes.
    bool watch_success = watch(map_path, &update_bpf_map, state);

    log_info("Unloading BPF program.");
    bpf_state__close(state);

    return watch_success ? 0 : 1;
}
