#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

extern int debug;

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
