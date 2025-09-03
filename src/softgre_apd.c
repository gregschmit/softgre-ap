/*
 * SoftGRE Access Point Daemon
 * This daemon loads/unload the `softgre_ap_xdp.o` program and monitors the mapping file (default is
 * `/var/run/softgre_ap_map.conf`) to keep the eBPF Map updated.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)
#define TIMEOUT 2

volatile int interrupt = 0;
int debug = 0;

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

int watch(char *path, void (*callback)()) {
    char *fn = basename(path);
    char *dn = dirname(path);

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

void update_ebpf_map() {
    dbg("Updating map.");
}

int main(int argc, char *argv[]) {
    int foreground = 0;

    int ch;
    char version[256] = "softgre_apd " VERSION;
    char usage[2048] = "softgre_apd " VERSION "\n\n"
        "Usage: softgre_apd [-dfVh] <interface(s)...>"
        "  Options:\n"
        "  -d       Enable debug logging.\n"
        "  -f       Foreground mode (no daemonization).\n"
        "  -V       Show version.\n"
        "  -h -?    Show usage.\n";
    int i = 0;
    while ((ch = getopt(argc, argv, "dfVh?")) != -1) {
        i++;
        switch (ch) {
        case 'd':
            debug = 1;
            break;
        case 'f':
            foreground = 1;
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

    char *path = NULL;
    for (int i = optind; i < argc; i++) {
        if (path == NULL) {
            path = argv[i];
        }
        printf("positional: %s\n", argv[i]);
    }

    if (strlen(path) > PATH_MAX) {
        fprintf(stderr, "Watch path is too long.\n");
        exit(EXIT_FAILURE);
    }

    // TODO: Load the XDP program onto selected interfaces.

    return watch(path, &update_ebpf_map);
}
