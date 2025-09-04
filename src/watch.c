#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <limits.h>
#include <errno.h>
#include <libgen.h>

#include <sys/inotify.h>

#include "log.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)
#define TIMEOUT 2

extern volatile int interrupt;

/*
 * Watch the specified file for changes and execute the callback when a change is detected.
 */
int watch(char *filepath, void (*callback)()) {
    char *fn = basename(filepath);
    char *dn = dirname(filepath);

    // Initialize `inotify`.
    int fd = inotify_init();
    if (fd < 0) {
        log_errno("inotify_init");
        return 1;
    }

    // Combine `dn` and `fn` to get the `fullpath`.
    char fullpath[PATH_MAX + 1];
    int fullpath_len = strlen(dn) + strlen(fn) + 2;
    snprintf(fullpath, fullpath_len, "%s/%s", dn, fn);

    log_info("Watching %s...", fullpath);

    int wd = -1;
    int wd_is_dir = 0;
    char buf[BUF_LEN];
    while (1) {
        if (interrupt) {
            dbg("Stopping watch...");
            break;
        }

        // If `wd < 0`, then try to watch the file.
        if (wd < 0) {
            wd_is_dir = 0;
            wd = inotify_add_watch(fd, fullpath, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
            if (wd < 0) {
                if (errno == ENOENT) {
                    // If file doesn't exist, then watch parent directory.
                    dbg("File not found; watching parent directory: %s", dn);
                    wd_is_dir = 1;
                    wd = inotify_add_watch(fd, dn, IN_CREATE | IN_MOVED_TO);
                    if (wd < 0) {
                        dbg_errno("inotify_add_watch");
                        sleep(TIMEOUT);
                        continue;
                    }
                } else {
                    log_errno("inotify_add_watch");
                    log_error("File %s could not be watched.", fullpath);
                    sleep(TIMEOUT);
                    continue;
                }
            }
        }

        // Now we definitely have a watch descriptor; wait for an event:
        int length = read(fd, buf, BUF_LEN);
        if (length < 0) {
            log_errno("read");
            if (inotify_rm_watch(fd, wd) < 0) {
                log_errno("inotify_rm_watch");
                wd = -1;
                sleep(TIMEOUT);
                continue;
            }
            wd = -1;
            sleep(TIMEOUT);
            continue;
        } else if (length == 0) {
            log_error("read returned 0?!");
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
