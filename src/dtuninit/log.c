#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../shared.h"

#include "log.h"

#define ENABLE_COLOR() if (COLOR) { fprintf(stderr, "\033[1;31m"); }
#define DISABLE_COLOR() if (COLOR) { fprintf(stderr, "\033[0m"); }

bool DEBUG = false;
bool COLOR = false;

void log_info(const char *msg, ...) {
    va_list args;
    va_start(args, msg);
    vfprintf(stdout, msg, args);
    va_end(args);

    fprintf(stdout, "\n");
}

void log_error(const char *msg, ...) {
    ENABLE_COLOR()
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);

    fprintf(stderr, "\n");
    DISABLE_COLOR()
}

void log_errno(const char *label) {
    ENABLE_COLOR()
    fprintf(stderr, "(%s) %s\n", label, strerror(errno));
    DISABLE_COLOR()
}

void dbg(const char *msg, ...) {
    if (!DEBUG) { return; }

    ENABLE_COLOR()
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fprintf(stderr, "\n");
    DISABLE_COLOR()
}

void dbg_errno(const char *label) {
    if (!DEBUG) { return; }

    ENABLE_COLOR()
    fprintf(stderr, "(%s) %s\n", label, strerror(errno));
    DISABLE_COLOR()
}
