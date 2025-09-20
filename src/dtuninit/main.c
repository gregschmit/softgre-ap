/*
 * Dynamic Tunnel Initiator: Userspace Program
 *
 * This program's primary subcommand `start` loads/unload the BPF programs and monitors the clients
 * file to keep the BPF maps updated. It also provides subcommands for adding/removing clients, to
 * avoid requiring users of this software from having to manually parse and write to the clients
 * file.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>

#include "../shared.h"
#include "list.h"
#include "log.h"
#include "watch.h"
#include "bpf_state.h"

#define DEFAULT_CLIENTS_PATH "/var/run/dtuninit_clients"
#define DEFAULT_BPF_FN "dtuninit_bpf.o"

#define VERSION_S "dtuninit " VERSION
#define USAGE_S \
    VERSION_S "\nThe Dynamic Tunnel Initiator\n\n" \
    "Usage: dtuninit [OPTIONS]\n\n" \
    "Options:\n" \
    "  -B <FILE>  Set BPF object file (default: " DEFAULT_BPF_FN " from current dir or PATH).\n" \
    "  -C <FILE>  Set Clients file (default: " DEFAULT_CLIENTS_PATH ").\n" \
    "  -d         Enable debug logging.\n" \
    "  -i <IF>    Bind to interface `IF`.\n" \
    "  -V         Show version.\n" \
    "  -h -?      Show usage.\n"

volatile bool INTERRUPT = false;

// Static storage to hold interface data.
#define IFS_MAX_STRLEN 256
static unsigned IFS_COUNT = 0;
static char IFS[MAX_INTERFACES][IFS_MAX_STRLEN] = {0};
static char *IFS_PTRS[MAX_INTERFACES] = {0};

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
    dst_addr.sin_addr = ip_cfg->peer_ip;

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
    if (!ip_cfg || !ip_cfg->peer_ip.s_addr) { return false; }

    // Determine src IP for this GRE IP.
    if (!populate_ip_cfg_src_ip(ip_cfg)) {
        log_error("Failed to determine src IP for GRE IP: %s", inet_ntoa(ip_cfg->peer_ip));
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

char *split(const char *s, char delim) {
    char *d = strchr(s, delim);
    if (!d) { return NULL; }
    if (d == s) { return NULL; }
    if (*(d + 1) == '\0') { return NULL; }
    *d = '\0';
    return d + 1;
}

void parse_clients_file(const char *path, List *clients, List *ip_cfgs, uint8_t cycle) {
    if (!clients || !ip_cfgs) { return; }

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

    // Read file line by line into the client list.
    char linebuf[256] = "";
    while (fgets(linebuf, sizeof(linebuf), fp)) {
        // Ignore comments.
        if (linebuf[0] == '#') { continue; }

        // Parse the line, logging but otherwise disregarding any errors.
        Client client = {.cycle = cycle};
        char protocol[16] = "";
        char args[128] = "";
        int n = sscanf(
            linebuf,
            "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %15s %127[^\n]",
            &client.mac[0],
            &client.mac[1],
            &client.mac[2],
            &client.mac[3],
            &client.mac[4],
            &client.mac[5],
            protocol,
            args
        );

        if (n != 8) {
            log_error("Failed to parse line: `%s`", linebuf);
            continue;
        }

        // Parse proto/subproto.
        char *subprotocol = NULL;
        if (!(subprotocol = split(protocol, '/'))) {
            log_error("Failed to parse protocol/subprotocol: `%s`", protocol);
            continue;
        }

        if (strcmp(protocol, "gre")) {
            log_error("Unsupported protocol: `%s`", protocol);
            continue;
        }
        client.tun_config.proto = TUN_PROTO_GRE;

        if (!strcmp(subprotocol, "v0")) {
            client.tun_config.subproto.gre = TUN_GRE_SUBPROTO_V0;
        } else {
            log_error("Unsupported GRE subprotocol: `%s`", subprotocol);
            continue;
        }

        char *peer_ip = strtok(args, " ");
        if (!peer_ip) {
            log_error("Missing Peer IP in line: `%s`", linebuf);
            continue;
        }

        if (!inet_pton(AF_INET, peer_ip, &client.peer_ip)) {
            log_error("Failed to parse Peer IP: `%s`", peer_ip);
            continue;
        }

        while (true) {
            // Get next arg.
            char *key = strtok(NULL, " ");
            if (!key) { break; }

            // Parse into key/value.
            char *value = NULL;
            if (!(value = split(key, '='))) { break; }

            // For now, only support vlan key.
            if (!strcmp(key, "vlan")) {
                unsigned long vlan = strtoul(value, NULL, 10);
                if (!vlan || vlan > 4094) {
                    log_error("Invalid VLAN: `%s`", value);
                    continue;
                }
                client.vlan = (uint16_t)vlan;
            } else {
                log_error("Unsupported client argument: `%s`", key);
            }
        }

        // See if we already have an IP Config.
        IPCfg *ip_cfg = list__find(ip_cfgs, &client.peer_ip);
        if (ip_cfg) {
            // If the config is not valid, then we previously failed to populate it, so skip this
            // client.
            if (!ip_cfg__is_valid(ip_cfg)) {
                continue;
            }
        } else {
            // We haven't seen this GRE IP before, so populate a new IP config and add it to the
            // list. If we fail to populate it fully, then skip this client. But add the IP config
            // regardless so we don't try again for subsequent clients with the same GRE IP.
            IPCfg ip_cfg = {.peer_ip = client.peer_ip, .cycle = cycle};
            if (!populate_ip_cfg(&ip_cfg)) {
                log_error("Failed to populate IP config for IP: %s", peer_ip);
                continue;
            }

            if (!list__add(ip_cfgs, &ip_cfg)) {
                log_error("Failed to add IP config for IP: %s", peer_ip);
                continue;
            }
        }

        if (!list__add(clients, &client)) {
            log_error("Failed to add client for MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                client.mac[0],
                client.mac[1],
                client.mac[2],
                client.mac[3],
                client.mac[4],
                client.mac[5]
            );
        }
    }

    fclose(fp);
}

void update_bpf_map(BPFState *state, const char *clients_path) {
    if (!state) {
        log_error("BPF state is NULL.");
        return;
    }

    if (!state->obj) {
        log_error("BPF state obj doesn't exist.");
        return;
    }

    // Get the map objects.
    struct bpf_map *client_map = bpf_state__get_client_map(state);
    if (!client_map) {
        log_error("Failed to get Client map.");
        return;
    }
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(state);
    if (!ip_cfg_map) {
        log_error("Failed to get IP Config map.");
        return;
    }

    // Create client and IP config lists.
    List *clients = list__new(
        sizeof(Client), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)client__key_eq
    );
    if (!clients) { return; }
    List *ip_cfgs = list__new(
        sizeof(IPCfg), sizeof(struct in_addr), (list__key_eq_t)ip_cfg__key_eq
    );
    if (!ip_cfgs) {
        list__free(clients);
        return;
    }

    // Bump the state cycle.
    state->cycle++;

    // Parse map file to populate the lists.
    parse_clients_file(clients_path, clients, ip_cfgs, state->cycle);
    if (!clients->length) {
        list__free(clients);
        list__free(ip_cfgs);
        return;
    }
    if (!ip_cfgs->length) {
        list__free(clients);
        list__free(ip_cfgs);
        return;
    }

    // Update the IP config map.
    for (size_t i = 0; i < ip_cfgs->length; i++) {
        IPCfg ip_cfg = ((IPCfg *)ip_cfgs->items)[i];

        if (bpf_map__update_elem(
            ip_cfg_map,
            &ip_cfg.peer_ip,
            sizeof(ip_cfg.peer_ip),
            &ip_cfg,
            sizeof(ip_cfg),
            BPF_ANY
        )) {
            log_error("Failed to update IP map for GRE IP: %s", inet_ntoa(ip_cfg.peer_ip));
            continue;
        }
    }

    // Update the client map.
    for (size_t i = 0; i < clients->length; i++) {
        Client client = ((Client *)clients->items)[i];
        if (bpf_map__update_elem(
            client_map,
            &client.mac,
            sizeof(client.mac),
            &client,
            sizeof(client),
            BPF_ANY
        )) {
            log_error("Failed to update Client map for MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                client.mac[0],
                client.mac[1],
                client.mac[2],
                client.mac[3],
                client.mac[4],
                client.mac[5]
            );
            continue;
        }
    }

    // Remove stale entries.
    bpf_state__remove_stale_clients(state, clients);
    bpf_state__remove_stale_ip_cfgs(state, ip_cfgs);

    list__free(clients);
    list__free(ip_cfgs);
}

bool start(char *bpf_path, char *clients_path) {
    log_info("Registering signal handlers.");
    signal(SIGHUP, interrupt_handler);
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    // Stop libbpf from printing.
    libbpf_set_print(NULL);

    log_info("BPF object file: `%s`.", bpf_path);
    log_info("Clients file: `%s`.", clients_path);
    log_info("Loading BPF programs.");
    BPFState *state = bpf_state__open(bpf_path, IFS_COUNT ? IFS_PTRS : NULL);
    if (!state) {
        log_error("Failed to load BPF state.");
        return false;
    }

    // Initial map load.
    update_bpf_map(state, clients_path);

    // Watch the map file for changes.
    bool watch_success = watch(clients_path, &update_bpf_map, state);

    log_info("Unloading BPF programs.");
    bpf_state__close(state);

    return watch_success;
}

int main(int argc, char *argv[]) {
    char bpf_path[PATH_MAX + sizeof(DEFAULT_BPF_FN) + 1] = "";
    char clients_path[PATH_MAX + 1] = DEFAULT_CLIENTS_PATH;

    // Detect if we have a TTY that also supports color.
    if (isatty(fileno(stderr))) {
        if (getenv("COLORTERM")) {
            COLOR = true;
        }

        char *term = getenv("TERM");
        if (
            strstr(term, "color") ||
            strstr(term, "xterm") ||
            strstr(term, "screen") ||
            strstr(term, "linux") ||
            strstr(term, "rxvt") ||
            strstr(term, "vt100") ||
            strstr(term, "ansi")
        ) {
            COLOR = true;
        }
    }

    // Try to find BPF object file from current directory.
    if (getcwd(bpf_path, sizeof(bpf_path))) {
        strncat(bpf_path, "/" DEFAULT_BPF_FN, sizeof(bpf_path) - strlen(bpf_path) - 1);
        FILE *fp = fopen(bpf_path, "r");
        if (fp == NULL) {
            bpf_path[0] = '\0';
        } else {
            fclose(fp);
        }
    } else {
        log_errno("getcwd");
        log_error("Failed to get current working directory.");
        return 1;
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
            snprintf(bpf_path, sizeof(bpf_path), "%s/" DEFAULT_BPF_FN, path);
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
    while ((ch = getopt(argc, argv, "B:C:di:Vh?")) != -1) {
        switch (ch) {
            case 'B': {
                size_t bpf_length = strlen(optarg);
                if (bpf_length <= 0) {
                    log_error("Invalid BPF object file.");
                    return 1;
                } else if (bpf_length > PATH_MAX) {
                    log_error("BPF object file path is too long.");
                    return 1;
                } else {
                    strcpy(bpf_path, optarg);
                }

                FILE *fp = fopen(bpf_path, "r");
                if (fp == NULL) {
                    log_errno("fopen");
                    log_error("BPF object file could not be opened.");
                    return 1;
                } else {
                    fclose(fp);
                }
                break;
            }
            case 'C': {
                int length = strlen(optarg);
                if (length <= 0) {
                    log_error("Invalid clients file.");
                    return 1;
                } else if (length > PATH_MAX) {
                    log_error("Clients file path is too long.");
                    return 1;
                } else {
                    strcpy(clients_path, optarg);
                }
                break;
            }
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'i': {
                if (IFS_COUNT >= MAX_INTERFACES) {
                    log_error("Exceeded max interfaces (%d); ignoring %s", MAX_INTERFACES, optarg);
                } else {
                    strncpy(IFS[IFS_COUNT], optarg, IFS_MAX_STRLEN - 1);
                    IFS[IFS_COUNT][IFS_MAX_STRLEN - 1] = '\0';
                    IFS_PTRS[IFS_COUNT] = IFS[IFS_COUNT];
                    IFS_COUNT++;
                }
                break;
            }
            case 'V': {
                log_info("%s", VERSION_S);
                exit(0);
                break;
            }
            case 'h':
            case '?': {
                log_info("%s", USAGE_S);
                exit(0);
                break;
            }
            default: {
                log_error("%s", USAGE_S);
                exit(1);
                break;
            }
        }
    }

    // Check that we have a BPF object file.
    if (bpf_path[0] == '\0') {
        log_error("No BPF object file found.");
        return 1;
    }

    // Check if BPF object file can be read.
    FILE *fp = fopen(bpf_path, "r");
    if (fp == NULL) {
        log_errno("fopen");
        log_error("BPF object file could not be opened.");
        return 1;
    } else {
        fclose(fp);
    }

    bool success = start(bpf_path, clients_path);

    return success ? 0 : 1;
}
