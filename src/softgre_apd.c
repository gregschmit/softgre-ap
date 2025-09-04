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

#include "dbg.h"
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

void interrupt_handler(int _signum) {
    interrupt = 1;
}

void parse_config_file(const char *filepath) {
}

// TODO: Load XDP program located at xdp_path onto the interfaces.
int load_xdp_program(char *xdp_path, char **ifs, int num_ifs) {
    return 0;
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
                fprintf(stderr, "Invalid map file.\n");
                exit(1);
            } else if (map_length > PATH_MAX) {
                fprintf(stderr, "Map file path is too long.\n");
                exit(1);
            } else {
                strcpy(map_path, optarg);
            }
            break;
        case 'x':
            int xdp_length = strlen(optarg);
            if (xdp_length <= 0) {
                fprintf(stderr, "Invalid XDP program file.\n");
                exit(1);
            } else if (xdp_length > PATH_MAX) {
                fprintf(stderr, "XDP program file path is too long.\n");
                exit(1);
            } else {
                strcpy(xdp_path, optarg);
            }

            FILE *fp = fopen(xdp_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "XDP program file error: %s\n", strerror(errno));
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
        fprintf(stderr, "No XDP program found.\n");
        exit(1);
    }

    // Check if XDP program can be read.
    FILE *fp = fopen(xdp_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "XDP program file error: %s\n", strerror(errno));
        exit(1);
    } else {
        fclose(fp);
    }

    signal(SIGINT, interrupt_handler);

    int num_ifs = argc - optind;
    char **ifs = argv + optind;
    for (int i = 0; i < num_ifs; i++) {
        printf("interface: %s\n", ifs[i]);
    }

    // TODO: Load the XDP program onto selected interfaces.
    int res = load_xdp_program(xdp_path, ifs, num_ifs);
    if (res < 0) {
        fprintf(stderr, "Failed to load XDP program: %d\n", res);
        exit(1);
    }

    return watch(map_path, &update_ebpf_map);
}
