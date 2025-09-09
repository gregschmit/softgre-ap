#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>

#include <sys/inotify.h>

#include "log.h"

#include "watch.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)
#define TIMEOUT 1

extern volatile int interrupt;

/*
 * Watch the specified file for changes and execute the callback when a change is detected.
 */
bool watch(const char *map_path, callback_t callback, struct XDPState *state) {
    // Extract the directory name and file name without modifying `map_path`.
    char tmp[PATH_MAX + 1];
    strncpy(tmp, map_path, sizeof(tmp));
    char *fn = basename(tmp);
    char *dn = dirname(tmp);

    // Initialize `inotify`.
    int fd = inotify_init();
    if (fd < 0) {
        log_errno("inotify_init");
        return false;
    }

    // Combine `dn` and `fn` to get the `fullpath`.
    char fullpath[PATH_MAX + 1];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", dn, fn);

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
                        log_errno("inotify_add_watch");
                        log_error("Failed to watch %s.", dn);
                        sleep(TIMEOUT);
                        continue;
                    }
                } else {
                    log_errno("inotify_add_watch");
                    log_error("Failed to watch %s.", fullpath);
                    sleep(TIMEOUT);
                    continue;
                }
            }
        }

        // Now we definitely have a watch descriptor; wait for an event:
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int res = poll(&pfd, 1, TIMEOUT * 1000);
        if (res < 0) {
            dbg_errno("poll");
            continue;
        } else if (res == 0) {
            // Continue to check for interrupt.
            continue;
        }

        // Now read the event.
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
                        callback(state, map_path);
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    } else if (event->mask & IN_MOVED_TO) {
                        dbg("%s moved in", event->name);
                        callback(state, map_path);
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    }
                }
            } else {
                if (event->mask & IN_MODIFY) {
                    dbg("%s modified", fullpath);
                    callback(state, map_path);
                } else if (event->mask & IN_MOVE_SELF) {
                    dbg("%s moved out", fullpath);
                    callback(state, map_path);
                    inotify_rm_watch(fd, wd);
                    wd = -1;
                    break;
                } else if (event->mask & IN_DELETE_SELF) {
                    dbg("%s deleted", fullpath);
                    callback(state, map_path);
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

    return true;
}
