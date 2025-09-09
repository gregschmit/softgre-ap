/*
 * SoftGRE Access Point Daemon
 *
 * This daemon loads/unload the XDP program and monitors the mapping file to keep the BPF Map
 * updated.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/bpf.h>

#include "device/list.h"
#include "log.h"
#include "watch.h"
#include "xdp_state.h"

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_XDP "softgre_ap_xdp.o"

// Must fit the largest map entry; e.g. `FF:FF:FF:FF:FF:FF 255.255.255.255 4095\0`.
#define MAX_LINE_SIZE 39

int debug = 0;
volatile int interrupt = 0;

void interrupt_handler(int _signum) {
    interrupt = 1;
}

bool get_source_ip(struct in_addr dest_ip, struct in_addr* source_ip) {
    int sockfd;
    struct sockaddr_in dest_addr, src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    // Create UDP socket.
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errno("socket");
        return false;
    }

    // Set up destination address.
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53); // DNS port, but any port works.
    dest_addr.sin_addr = dest_ip;

    // Connect to destination (this doesn't actually send packets for UDP).
    if (connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        log_errno("connect");
        close(sockfd);
        return false;
    }

    // Get the local address the kernel assigned.
    if (getsockname(sockfd, (struct sockaddr*)&src_addr, &src_addr_len) < 0) {
        log_errno("getsockname");
        close(sockfd);
        return false;
    }

    // Copy the source IP.
    *source_ip = src_addr.sin_addr;

    close(sockfd);

    return true;
}

struct DeviceList *parse_map_file(const char *path) {
    struct DeviceList *list = device_list__new();
    if (!list) {
        return NULL;
    }

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
        return list;
    }

    // Read file line by line into the device list.
    char linebuf[MAX_LINE_SIZE] = "";
    while (fgets(linebuf, sizeof(linebuf), fp)) {
        // Ignore comments.
        if (linebuf[0] == '#') { continue; }

        // Parse the line, logging but otherwise disregarding any errors.
        struct Device device = {0};
        char ip[16] = "";
        int res = sscanf(
            linebuf,
            "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %15s %hu",
            &device.mac[0],
            &device.mac[1],
            &device.mac[2],
            &device.mac[3],
            &device.mac[4],
            &device.mac[5],
            ip,
            &device.vlan
        );

        if (res != 8) {
            log_error("Failed to parse line: `%s`", linebuf);
            continue;
        }

        if (!inet_pton(AF_INET, ip, &device.dst_ip)) {
            log_error("Failed to parse dst IP: `%s`", ip);
            continue;
        }

        if (!get_source_ip(device.dst_ip, &device.src_ip)) {
            log_error("Failed to determine src IP for dst IP: `%s`", ip);
            continue;
        }

        device_list__add(list, device);
    }

    fclose(fp);

    return list;
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
    struct bpf_map *mac_map = xdp_state__get_mac_map(state);
    if (!mac_map) {
        log_error("Failed to get MAC map.");
        return;
    }
    struct bpf_map *ip_set = xdp_state__get_ip_set(state);
    if (!ip_set) {
        log_error("Failed to get IP set.");
        return;
    }

    // Get parsed map file.
    struct DeviceList *device_list = parse_map_file(map_path);
    if (!device_list || device_list->length == 0) {
        device_list__free(device_list);
        return;
    }

    // Clear BPF maps.
    // TODO: Improve this; currently we just clear the map which is hacky.
    clear_bpf_map(mac_map, ETH_ALEN);
    clear_bpf_map(ip_set, sizeof(struct in_addr));

    // Update the BPF map with the new devices.
    for (unsigned int i = 0; i < device_list->length; i++) {
        struct Device device = device_list->devices[i];
        bpf_map__update_elem(
            mac_map, &device.mac, sizeof(device.mac), &device, sizeof(device), BPF_ANY
        );
        bpf_map__update_elem(
            ip_set, &device.ip, sizeof(device.ip), &true, sizeof(bool), BPF_ANY
        );
    }

    device_list__free(device_list);
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
    if (xdp_path[0] == '\0' && path_env != NULL) {
        char *path = strtok(path_env, ":");
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

    int ch;
    char version[256] = "softgre_apd " VERSION;
    char usage[2048] = "softgre_apd " VERSION "\n\n"
        "Usage: softgre_apd [-dfVh] [interface(s)...]\n"
        "Options:\n"
        "  -c         Clear existing XDP programs on interfaces.\n"
        "  -d         Enable debug logging.\n"
        "  -f         Foreground mode (no daemonization).\n"
        "  -m FILE    MAC map file (default: " DEFAULT_MAP ").\n"
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
            debug = 1;
            break;
        case 'f':
            foreground = 1;
            // TODO: Implement.
            break;
        case 'm':
            int map_length = strlen(optarg);
            if (map_length <= 0) {
                log_error("Invalid map file.");
                exit(1);
            } else if (map_length > PATH_MAX) {
                log_error("Map file path is too long.");
                exit(1);
            } else {
                strcpy(map_path, optarg);
            }
            break;
        case 'x':
            int xdp_length = strlen(optarg);
            if (xdp_length <= 0) {
                log_error("Invalid XDP program file.");
                exit(1);
            } else if (xdp_length > PATH_MAX) {
                log_error("XDP program file path is too long.");
                exit(1);
            } else {
                strcpy(xdp_path, optarg);
            }

            FILE *fp = fopen(xdp_path, "r");
            if (fp == NULL) {
                log_errno("fopen");
                log_error("XDP program file could not be opened.");
                exit(1);
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
        exit(1);
    }

    // Check if XDP program can be read.
    FILE *fp = fopen(xdp_path, "r");
    if (fp == NULL) {
        log_errno("fopen");
        log_error("XDP program file could not be opened.");
        exit(1);
    } else {
        fclose(fp);
    }

    // Register signal handlers.
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    // Organize interface list.
    int num_ifs = argc - optind;
    char **ifs = argv + optind;

    // Load the XDP program onto selected interfaces.
    log_info("Loading XDP program (xdp: %s, map: %s)...", xdp_path, map_path);
    dbg("XDP Program: %s", xdp_path);
    dbg("Map File: %s", map_path);
    struct XDPState *state = xdp_state__open(xdp_path, num_ifs, ifs);
    if (!state) {
        log_error("Failed to load XDP program.");
        exit(1);
    }

    // Initial map load.
    update_bpf_map(state, map_path);

    // Watch the map file for changes.
    bool watch_success = watch(map_path, &update_bpf_map, state);

    log_info("Unloading XDP program...");
    xdp_state__close(state);

    return watch_success ? 0 : 1;
}
