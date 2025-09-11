/*
 * SoftGRE Access Point Daemon
 *
 * This daemon loads/unload the XDP program and monitors the mapping file to keep the BPF maps
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

#include "debug.h"
#include "list.h"
#include "log.h"
#include "shared.h"
#include "watch.h"
#include "xdp_state.h"

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_XDP "softgre_ap_xdp.o"

// Must fit the largest map entry; e.g. `FF:FF:FF:FF:FF:FF 255.255.255.255 4095\0`.
#define MAX_LINE_SIZE 39

volatile bool INTERRUPT = false;

// Static storage to hold all interface names, if needed.
static unsigned ALL_IFS_MAX = 20;
static unsigned ALL_IFS_MAX_STRLEN = 256;
static char ALL_IFS[ALL_IFS_MAX][ALL_IFS_MAX_STRLEN] = {0};

void interrupt_handler(int _signum) {
    INTERRUPT = true;
}

bool populate_ip_config_src_ip(struct IPConfig *ip_config) {
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
    dst_addr.sin_addr = ip_config->gre_ip;

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
    ip_config->src_ip = src_addr.sin_addr;

    close(sockfd);

    return true;
}

bool populate_ip_config_ifindex(struct IPConfig *ip_config) {
    if (!ip_config) { return false; }

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

            if (sin->sin_addr.s_addr == ip_config->src_ip.s_addr) {
                ip_config->ifindex = if_nametoindex(ifa->ifa_name);
                break;
            }

            // NOTE: If needed in future, could also get netmask here with ifa->ifa_netmask.
        }
    }

    // NOTE: If needed in future, could also get L2 data here by:
    //   - Checking `ifa->ifa_addr->sa_family == AF_PACKET`.
    //   - Casting to `struct sockaddr_ll *` and copying `sll_addr` to `ip_config->src_mac`.
    //   - Inspecting `sll_ifindex`.
    // This would probably have to be done in a separate loop after the above loop, because
    // `AF_PACKET` is not guaranteed to come after `AF_INET` and in my experience it typically comes
    // before. But we would want to match the IP addr first.

    freeifaddrs(ifaddr);
    return ip_config->ifindex != 0;
}

// Ensure `src_ip` is set to 0 if any of the population steps fail.
bool populate_ip_config(struct IPConfig *ip_config) {
    if (!ip_config || !ip_config->gre_ip) { return false; }

    // Determine src IP for this GRE IP.
    if (!populate_ip_config_src_ip(ip_config)) {
        log_error("Failed to determine src IP for GRE IP: %s", inet_ntoa(ip_config->gre_ip));
        ip_config->src_ip.s_addr = 0;
        return false;
    }

    // Determine ifindex.
    if (!populate_ip_config_ifindex(ip_config)) {
        log_error("Failed to determine ifindex for src IP: %s", inet_ntoa(ip_config->src_ip));
        ip_config->src_ip.s_addr = 0;
        return false;
    }

    return true;
}

void parse_map_file(const char *path, List *devices, List *ip_configs, uint8_t cycle) {
    if (!devices || !ip_configs) { return; }

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
        struct Device device = {.cycle = cycle};
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
        struct IPConfig *ip_config = list__find(ip_configs, &device.gre_ip);
        if (ip_config) {
            // If the config is not valid, then we previously failed to populate it, so skip this
            // device.
            if (!ip_config__is_valid(ip_config)) {
                continue;
            }
        } else {
            // We haven't seen this GRE IP before, so populate a new IP config and add it to the
            // list. If we fail to populate it fully, then skip this device. But add the IP config
            // regardless so we don't try again for subsequent devices with the same GRE IP.
            struct IPConfig ip_config = {.gre_ip = device.gre_ip, .cycle = cycle};
            if (!populate_ip_config(&ip_config)) {
                log_error("Failed to populate IP config for IP: %s", gre_ip);
                continue;
            }

            if (!list__add(ip_configs, &ip_config)) {
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

void update_bpf_map(struct XDPState *state, const char *map_path) {
    if (!state) {
        log_error("XDP state is NULL.");
        return;
    }

    if (!state->obj) {
        log_error("XDP state obj doesn't exist.");
        return;
    }

    // Get the map objects.
    struct bpf_map *device_map = xdp_state__get_device_map(state);
    if (!device_map) {
        log_error("Failed to get Device map.");
        return;
    }
    struct bpf_map *ip_config_map = xdp_state__get_ip_config_map(state);
    if (!ip_config_map) {
        log_error("Failed to get IP Config map.");
        return;
    }

    // Create device and IP config lists.
    List *devices = list__new(
        sizeof(struct Device), sizeof(uint8_t) * ETH_ALEN, device__key_eq
    );
    if (!devices) { return; }
    List *ip_configs = list__new(
        sizeof(struct IPConfig), sizeof(struct in_addr), ip_config__key_eq
    );
    if (!ip_configs) {
        list__free(devices);
        return;
    }

    // Bump the state cycle.
    state->cycle++;

    // Parse map file to populate the lists.
    parse_map_file(map_path, devices, ip_configs, state->cycle);
    if (!devices->length) {
        list__free(devices);
        list__free(ip_configs);
        return;
    }
    if (!ip_configs->length) {
        list__free(devices);
        list__free(ip_configs);
        return;
    }

    // Update the IP config map.
    for (size_t i = 0; i < ip_configs->length; i++) {
        struct IPConfig ip_config = ip_configs->items[i];

        if (bpf_map__update_elem(
            ip_config_map,
            &ip_config.gre_ip,
            sizeof(ip_config.gre_ip),
            &ip_config,
            sizeof(ip_config),
            BPF_ANY
        )) {
            log_error("Failed to update IP map for GRE IP: %s", inet_ntoa(ip_config.gre_ip));
            continue;
        }
    }

    // Update the device map.
    for (size_t i = 0; i < devices->length; i++) {
        struct Device device = devices->items[i];
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
    xdp_state__remove_stale_devices(state, devices);
    xdp_state__remove_stale_ip_configs(state, ip_configs);

    list__free(devices);
    list__free(ip_configs);
}

unsigned populate_all_ifs() {
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        log_errno("getifaddrs");
        return 0;
    }
    struct ifaddrs *ifa = ifaddr;

    unsigned count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (count >= ALL_IFS_MAX) { break; }
        if (ifa->ifa_addr == NULL) { continue; }

        // Only consider L2 interfaces.
        if (ifa->ifa_addr->sa_family != AF_PACKET) { continue; }

        // Check if we already have this interface.
        bool found = false;
        for (unsigned i = 0; i < count; i++) {
            if (strncmp(ALL_IFS[i], ifa->ifa_name, ALL_IFS_MAX_STRLEN) == 0) {
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
    char xdp_path[PATH_MAX + 1] = "";
    char map_path[PATH_MAX + 1] = DEFAULT_MAP;

    // If this program was invoked with a path, then assume the XDP program is in the same
    // directory.
    char *last_slash = strrchr(argv[0], '/');
    if (last_slash != NULL) {
        int len = last_slash - argv[0];
        snprintf(xdp_path, sizeof(xdp_path), "%.*s/" DEFAULT_XDP, len, argv[0]);

        // Check if that file DOESN'T exist, and if so, clear the `xdp_path`.
        FILE *fp = fopen(xdp_path, "r");
        if (fp == NULL) {
            xdp_path[0] = '\0';
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
    if (xdp_path[0] == '\0' && path_env != NULL) {
        char *path = strtok(path_env_copy, ":");
        while (path != NULL) {
            snprintf(xdp_path, sizeof(xdp_path), "%s/" DEFAULT_XDP, path);
            FILE *fp = fopen(xdp_path, "r");
            if (fp != NULL) {
                fclose(fp);
                break;
            }
            xdp_path[0] = '\0';
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
        "  -c         Clear existing XDP programs on interfaces.\n"
        "  -d         Enable debug logging.\n"
        "  -f         Foreground mode (no daemonization).\n"
        "  -m FILE    Map file (default: " DEFAULT_MAP ").\n"
        "  -x FILE    XDP program file (default: neighbor " DEFAULT_XDP " or PATH\n"
        "             " DEFAULT_XDP ").\n"
        "  -V         Show version.\n"
        "  -h -?      Show usage.\n";
    int i = 0;
    while ((ch = getopt(argc, argv, "cdfm:x:Vh?")) != -1) {
        i++;
        switch (ch) {
        case 'c':
            clear_existing = 1;
            // TODO: Implement.
            break;
        case 'd':
            DEBUG = true;
            break;
        case 'f':
            foreground = 1;
            // TODO: Implement.
            break;
        case 'm':
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
        case 'x':
            int xdp_length = strlen(optarg);
            if (xdp_length <= 0) {
                log_error("Invalid XDP program file.");
                return 1;
            } else if (xdp_length > PATH_MAX) {
                log_error("XDP program file path is too long.");
                return 1;
            } else {
                strcpy(xdp_path, optarg);
            }

            FILE *fp = fopen(xdp_path, "r");
            if (fp == NULL) {
                log_errno("fopen");
                log_error("XDP program file could not be opened.");
                return 1;
            } else {
                fclose(fp);
            }
            break;
        case 'V':
            printf("%s\n", version);
            exit(0);
            break;
        case 'h':
        case '?':
            printf("%s\n", usage);
            exit(0);
            break;
        default:
            fprintf(stderr, "%s\n", usage);
            exit(1);
            break;
        }
    }

    // Check that we have an XDP program.
    if (xdp_path[0] == '\0') {
        log_error("No XDP program found.");
        return 1;
    }

    // Check if XDP program can be read.
    FILE *fp = fopen(xdp_path, "r");
    if (fp == NULL) {
        log_errno("fopen");
        log_error("XDP program file could not be opened.");
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
        log_info("No interfaces specified, will default to all interfaces.");
        num_ifs = populate_all_ifs();
        ifs = (char **)ALL_IFS;
    } else {
        num_ifs = argc - optind;
        ifs = argv + optind;
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

    // Load the XDP program onto selected interfaces.
    log_info("Loading XDP program (xdp: %s, map: %s).", xdp_path, map_path);
    struct XDPState *state = xdp_state__open(xdp_path, num_ifs, ifs);
    if (!state) {
        log_error("Failed to load XDP program.");
        exit(1);
    }

    // Initial map load.
    update_bpf_map(state, map_path);

    // Watch the map file for changes.
    bool watch_success = watch(map_path, &update_bpf_map, state);

    log_info("Unloading XDP program.");
    xdp_state__close(state);

    return watch_success ? 0 : 1;
}
