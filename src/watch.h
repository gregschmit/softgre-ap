#include <stdbool.h>

#include "xdp_state.h"

typedef void (*callback_t)(struct XDPState *state, const char *map_path);

bool watch(char *filepath, callback_t callback, struct XDPState *state, const char *map_path);
