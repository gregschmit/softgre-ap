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

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/bpf.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "device.h"
#include "log.h"
#include "watch.h"

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_XDP "softgre_ap_xdp.o"

volatile int interrupt = 0;
int debug = 0;

struct xdp_state {
    struct bpf_object *obj;

    int num_ifs;
    int *ifindexes;
    struct bpf_link **links;
};

// Close the XDP state and free all resources. This includes destroying all links, which will detach
// the XDP program from all interfaces. Return NULL so the result can be assigned or returned, which
// will help avoid dangling pointers.
struct xdp_state *close_xdp_state(struct xdp_state *state) {
    if (!state) return NULL;

    if (state->ifindexes) { free(state->ifindexes); }
    if (state->links) {
        for (int i = 0; i < state->num_ifs; i++) {
            if (state->links[i]) {
                int res = bpf_link__destroy(state->links[i]);
                if (res) {
                    log_error("Failed to destroy XDP link (%d).", res);
                }
            }
        }
        free(state->links);
    }
    bpf_object__close(state->obj);
    free(state);

    return NULL;
}

void interrupt_handler(int _signum) {
    interrupt = 1;
}

struct xdp_state *load_xdp_program(char *xdp_path, int num_ifs, char **ifs) {
    log_info("Loading XDP program.");

    // Allocate state structure.
    struct xdp_state *state = calloc(1, sizeof(struct xdp_state));
    if (!state) {
        log_error("Failed to allocate memory for XDP state.");
        return NULL;
    }

    // Allocate memory for interface indexes.
    state->ifindexes = calloc(num_ifs, sizeof(int));
    if (!state->ifindexes) {
        log_error("Failed to allocate memory for interface indexes.");
        return close_xdp_state(state);
    }
    state->num_ifs = num_ifs;

    // Allocate memory for links.
    state->links = calloc(num_ifs, sizeof(struct bpf_link *));
    if (!state->links) {
        log_error("Failed to allocate memory for links.");
        return close_xdp_state(state);
    }

    // Open and load the XDP object file.
    state->obj = bpf_object__open(xdp_path);
    if (!state->obj) {
        log_errno("bpf_object__open");
        log_error("Failed to open XDP object file: %s", xdp_path);
        return close_xdp_state(state);
    }

    // Load the BPF object into the kernel.
    if (bpf_object__load(state->obj)) {
        log_errno("bpf_object__load");
        log_error("Failed to load BPF object.");
        return close_xdp_state(state);
    }

    // Find the XDP program.
    struct bpf_program *prog = bpf_object__find_program_by_name(state->obj, "xdp_softgre_ap");
    if (!prog) {
        log_error("Failed to find XDP program.");
        return close_xdp_state(state);
    }

    // Find the BPF map.
    struct bpf_map *map = bpf_object__find_map_by_name(state->obj, "mac_map");
    if (!map) {
        log_error("Failed to find BPF map.");
        return close_xdp_state(state);
    }

    // Add some sample data to the map.
    struct Device sample_devices[] = {
        {{0xa6, 0x89, 0x75, 0x1f, 0x1c, 0x47}, {.s_addr = inet_addr("192.168.1.10")}, 100},
        {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {.s_addr = inet_addr("192.168.1.20")}, 200},
        {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, {.s_addr = inet_addr("192.168.1.30")}, 0}
    };

    for (int i = 0; i < 3; i++) {
        int ret = bpf_map__update_elem(
            map,
            sample_devices[i].mac,
            sizeof(sample_devices[i].mac),
            &sample_devices[i],
            sizeof(sample_devices[i]),
            BPF_ANY
        );
        if (ret) {
            log_error("Failed to add sample data to map: %d", ret);
        } else if (debug) {
            log_info("Added MAC %02x:%02x:%02x:%02x:%02x:%02x -> IP %s, VLAN %u",
                   sample_devices[i].mac[0], sample_devices[i].mac[1], sample_devices[i].mac[2],
                   sample_devices[i].mac[3], sample_devices[i].mac[4], sample_devices[i].mac[5],
                   inet_ntoa(sample_devices[i].ip), sample_devices[i].vlan);
        }
    }

    // Attach the XDP program to each interface.
    int successful_attachments = 0;
    for (int i = 0; i < num_ifs; i++) {
        int ifindex = if_nametoindex(ifs[i]);
        if (ifindex == 0) {
            log_errno("if_nametoindex");
            log_error("Failed to find interface %s.", ifs[i]);
            state->ifindexes[i] = -1;
            continue;
        }

        struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
        state->links[i] = link;
        if (link) {
            log_info("Attached to interface %s (ifindex %d)", ifs[i], ifindex);
            successful_attachments++;
        } else {
            log_errno("bpf_program__attach_xdp");
            log_error("Failed to attach XDP program to interface %s.", ifs[i]);
            continue;
        }
    }

    if (successful_attachments == 0) {
        log_error("Failed to attach XDP program to any interface.");
        return close_xdp_state(state);
    }

    return state;
}

void parse_config_file(const char *filepath) {
}

void update_ebpf_map(struct xdp_state *state) {
    if (!state) { return; }
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
    struct xdp_state *state = load_xdp_program(xdp_path, num_ifs, ifs);
    if (!state) {
        log_error("Failed to load XDP program.");
        exit(1);
    }

    int res = watch(map_path, &update_ebpf_map, state);

    log_info("Unloading XDP program...");
    state = close_xdp_state(state);

    return res;
}
