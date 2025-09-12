#ifndef WATCH_H
#define WATCH_H

#include <stdbool.h>

#include "list.h"
#include "bpf_state.h"

typedef void (*callback_t)(BPFState *state, const char *map_path);

bool watch(const char *filepath, callback_t callback, BPFState *state);

#endif  // WATCH_H
