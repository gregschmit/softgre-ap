#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "log.h"

void log_info(const char *msg, ...) {
    fprintf(stdout, " INFO: ");

    va_list args;
    va_start(args, msg);
    vfprintf(stdout, msg, args);
    va_end(args);

    fprintf(stdout, "\n");
}

void log_error(const char *msg, ...) {
    fprintf(stderr, "ERROR: ");

    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    fprintf(stderr, "\n");
}

void log_errno(const char *label) {
    fprintf(stderr, "ERROR: (%s) %s\n", label, strerror(errno));
}

void dbg(const char *msg, ...) {
    if (!DEBUG) { return; }

    va_list args;
    fprintf(stderr, "DEBUG: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void dbg_errno(const char *label) {
    if (!DEBUG) { return; }

    fprintf(stderr, "DEBUG: (%s) %s\n", label, strerror(errno));
}
