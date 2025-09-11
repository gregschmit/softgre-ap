#ifndef WATCH_H
#define WATCH_H

#include <stdbool.h>

#include "list.h"
#include "xdp_state.h"

typedef void (*callback_t)(struct XDPState *state, const char *map_path);

bool watch(const char *filepath, callback_t callback, struct XDPState *state);

#endif  // WATCH_H
