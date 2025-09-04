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
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

#include <sys/inotify.h>

#include <netinet/in.h>

#define DEFAULT_MAP "/var/run/softgre_ap_map.conf"
#define DEFAULT_XDP "softgre_ap_xdp.o"
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)
#define TIMEOUT 2

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

void dbg(const char *msg, ...) {
    if (!debug) { return; }

    va_list args;
    fprintf(stderr, "DEBUG: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void dbg_error(const char *s) {
    if (!debug) { return; }

    char *e = strerror(errno);
    fprintf(stderr, "DEBUG: (%s) %s\n", s, e);
}

void parse_config_file(const char *filepath) {
}

/*
 * Watch the specified file for changes and execute the callback when a change is detected.
 */
int watch(char *filepath, void (*callback)()) {
    char *fn = basename(filepath);
    char *dn = dirname(filepath);

    // Initialize `inotify`.
    int fd = inotify_init();
    if (fd < 0) {
        dbg_error("inotify_init");
        return 1;
    }

    // Combine `dn` and `fn` to get the fullpath.
    char fullpath[PATH_MAX + 1];
    int fullpath_len = strlen(dn) + strlen(fn) + 2;
    snprintf(fullpath, fullpath_len, "%s/%s", dn, fn);

    dbg("Watching %s (%s / %s) for changes...", fullpath, dn, fn);

    int wd = -1;
    int wd_is_dir = 0;
    char buf[BUF_LEN];
    while (1) {
        if (interrupt) {
            dbg("Stopping...");
            break;
        }

        // If wd < 0, then try to watch the file.
        if (wd < 0) {
            wd_is_dir = 0;
            wd = inotify_add_watch(fd, fullpath, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
            if (wd < 0) {
                if (errno == ENOENT) {
                    // If file doesn't exist, then watch parent directory.
                    dbg("File not found, watching parent directory: %s", dn);
                    wd_is_dir = 1;
                    wd = inotify_add_watch(fd, dn, IN_CREATE | IN_MOVED_TO);
                    if (wd < 0) {
                        dbg_error("inotify_add_watch");
                        sleep(TIMEOUT);
                        continue;
                    }
                } else {
                    dbg_error("inotify_add_watch");
                    sleep(TIMEOUT);
                    continue;
                }
            }
        }

        // Now we definitely have a watch descriptor. Wait for an event:
        int length = read(fd, buf, BUF_LEN);
        if (length < 0) {
            dbg_error("read");
            if (inotify_rm_watch(fd, wd) < 0) {
                dbg_error("inotify_rm_watch");
                wd = -1;
                sleep(TIMEOUT);
                continue;
            }
            wd = -1;
            sleep(TIMEOUT);
            continue;
        } else if (length == 0) {
            dbg("read returned 0? ...");
            continue;
        }

        // Assume positive length means buffer contains at least one event Also, assume events are
        // never fragmented.
        int offset = 0;
        while (offset < length) {
            struct inotify_event *event = (struct inotify_event *)&buf[offset];
            if (wd_is_dir) {
                if (event->len > 0 && strcmp(event->name, fn) == 0) {
                    if (event->mask & IN_CREATE) {
                        dbg("%s created", event->name);
                        (*callback)();
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    } else if (event->mask & IN_MOVED_TO) {
                        dbg("%s moved in", event->name);
                        (*callback)();
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    }
                }
            } else {
                if (event->mask & IN_MODIFY) {
                    dbg("%s modified", fullpath);
                    (*callback)();
                } else if (event->mask & IN_MOVE_SELF) {
                    dbg("%s moved out", fullpath);
                    (*callback)();
                    inotify_rm_watch(fd, wd);
                    wd = -1;
                    break;
                } else if (event->mask & IN_DELETE_SELF) {
                    dbg("%s deleted", fullpath);
                    (*callback)();
                    inotify_rm_watch(fd, wd);
                    wd = -1;
                    break;
                }
            }

            offset += EVENT_SIZE + event->len;
        }
    }

    // Cleanup.
    if (wd >= 0) {
        inotify_rm_watch(fd, wd);
    }
    close(fd);

    return 0;
}

int load_xdp_program() {
    // TODO
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
        snprintf(xdp_path, sizeof(xdp_path), "%.*s/" DEFAULT_XDP, last_slash - argv[0], argv[0]);

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

    int num_interfaces = argc - optind;
    char **interfaces = argv + optind;
    for (int i = 0; i < num_interfaces; i++) {
        printf("interface: %s\n", interfaces[i]);
    }

    // TODO: Load the XDP program onto selected interfaces.

    return watch(map_path, &update_ebpf_map);
}
