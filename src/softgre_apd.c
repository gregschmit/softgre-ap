/*
 * SoftGRE Access Point Daemon
 *
 * This daemon loads/unload the XDP program and monitors the mapping file to keep the eBPF Map
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

#include "log.h"
#include "watch.h"

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_XDP "softgre_ap_xdp.o"

volatile int interrupt = 0;
int debug = 0;

struct Client {
    unsigned char mac[6];
    struct in_addr ip;
    unsigned int vlan;
};

struct xdp_state {
    struct bpf_object *obj;
    int map_fd;
    int *ifindexes;
    int num_ifs;
};

void interrupt_handler(int _signum) {
    interrupt = 1;
}

void parse_config_file(const char *filepath) {
}

struct xdp_state *load_xdp_program(char *xdp_path, char **ifs, int num_ifs) {
    log_info("Loading XDP program.");

    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd;

    // Allocate state structure.
    struct xdp_state *state = malloc(sizeof(struct xdp_state));
    if (!state) {
        log_error("Failed to allocate memory for XDP state.");
        return NULL;
    }

    // Allocate memory for interface indexes.
    state->ifindexes = malloc(num_ifs * sizeof(int));
    if (!state->ifindexes) {
        log_error("Failed to allocate memory for if indexes.");
        free(state);
        return NULL;
    }
    state->num_ifs = num_ifs;

    // Open and load the XDP object file.
    obj = bpf_object__open(xdp_path);
    if (!obj) {
        log_errno("bpf_object__open");
        log_error("Failed to open XDP object file: %s", xdp_path);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    // Load the BPF object into the kernel
    if (bpf_object__load(obj)) {
        log_errno("bpf_object__load");
        log_error("Failed to load BPF object.");
        bpf_object__close(obj);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    // Find the XDP program
    prog = bpf_object__find_program_by_name(obj, "xdp_vlan_tagger");
    if (!prog) {
        log_error("Failed to find XDP program in object file");
        bpf_object__close(obj);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        log_error("Failed to get program file descriptor");
        bpf_object__close(obj);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    // Create a hash map to store MAC -> {IP, VLAN} mappings
    // Key: MAC address (6 bytes), Value: Client struct
    map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "mac_map", 6, sizeof(struct Client), 1024, NULL);
    if (map_fd < 0) {
        log_error("Failed to create MAC map: %d", map_fd);
        bpf_object__close(obj);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    // Store state information
    state->obj = obj;
    state->map_fd = map_fd;

    // Add some sample data to the map
    struct Client sample_clients[] = {
        {{0xa6, 0x89, 0x75, 0x1f, 0x1c, 0x47}, {.s_addr = inet_addr("192.168.1.10")}, 100},
        {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, {.s_addr = inet_addr("192.168.1.20")}, 200},
        {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, {.s_addr = inet_addr("192.168.1.30")}, 0}
    };

    for (int i = 0; i < 3; i++) {
        int ret = bpf_map_update_elem(map_fd, sample_clients[i].mac, &sample_clients[i], BPF_ANY);
        if (ret) {
            log_error("Failed to add sample data to map: %d", ret);
        } else if (debug) {
            log_info("Added MAC %02x:%02x:%02x:%02x:%02x:%02x -> IP %s, VLAN %u\n",
                   sample_clients[i].mac[0], sample_clients[i].mac[1], sample_clients[i].mac[2],
                   sample_clients[i].mac[3], sample_clients[i].mac[4], sample_clients[i].mac[5],
                   inet_ntoa(sample_clients[i].ip), sample_clients[i].vlan);
        }
    }

    // Attach the XDP program to each specified interface
    int successful_attachments = 0;
    for (int i = 0; i < num_ifs; i++) {
        int ifindex = if_nametoindex(ifs[i]);
        if (ifindex == 0) {
            log_errno("if_nametoindex");
            log_error("Failed to find interface %s.", ifs[i]);
            state->ifindexes[i] = -1;
            continue;
        }

        // int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        // if (ret) {
        //     fprintf(stderr, "Failed to attach XDP program to interface %s: %d\n", ifs[i], ret);
        //     state->ifindexes[i] = -1;
        // } else {
        //     if (debug) {
        //         printf("Successfully attached XDP program to interface %s (ifindex %d)\n", ifs[i], ifindex);
        //     }
        //     state->ifindexes[i] = ifindex;
        //     successful_attachments++;
        // }
    }

    if (successful_attachments == 0) {
        fprintf(stderr, "Failed to attach XDP program to any interface\n");
        close(map_fd);
        bpf_object__close(obj);
        free(state->ifindexes);
        free(state);
        return NULL;
    }

    return state;
}

void unload_xdp_program(struct xdp_state *state) {
    log_info("Unloading XDP program...");
    if (!state) { return; }

    // Detach XDP program from all interfaces
    // for (int i = 0; i < state->num_ifs; i++) {
    //     if (state->ifindexes[i] > 0) {
    //         int ret = bpf_xdp_detach(state->ifindexes[i], XDP_FLAGS_UPDATE_IF_NOEXIST);
    //         if (ret) {
    //             fprintf(stderr, "Failed to detach XDP program from interface index %d: %d\n",
    //                     state->ifindexes[i], ret);
    //         } else if (debug) {
    //             printf("Successfully detached XDP program from interface index %d\n",
    //                    state->ifindexes[i]);
    //         }
    //     }
    // }

    // // Close the map file descriptor
    // if (state->map_fd >= 0) {
    //     close(state->map_fd);
    // }

    // // Close the BPF object (this will unload the program from the kernel)
    // if (state->obj) {
    //     bpf_object__close(state->obj);
    // }

    // // Free allocated memory
    // if (state->ifindexes) {
    //     free(state->ifindexes);
    // }
    // free(state);
}

void update_ebpf_map() {
    // TODO
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

    // Register signal handler.
    // signal(SIGINT, interrupt_handler);

    // Organize interface list.
    int num_ifs = argc - optind;
    char **ifs = argv + optind;

    // Load the XDP program onto selected interfaces.
    // struct xdp_state *xdp_state = load_xdp_program(xdp_path, ifs, num_ifs);
    // if (!xdp_state) {
    //     log_error("Failed to load XDP program.");
    //     exit(1);
    // }

    int res = watch(map_path, &update_ebpf_map);

    // unload_xdp_program(xdp_state);

    return res;
}
