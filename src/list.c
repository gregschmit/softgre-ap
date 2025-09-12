/*
 * Implementation of a dynamic homogeneous list of generic items (using void *), having O(1)
 * amortized insertion time and O(n) search time.
 *
 * This is currently used for storing the list of devices and IP configs. The linear search time is
 * acceptable because:
 *   - both the list of devices and IP configs are fairly small (order of number of client stations
 *     on an AP)
 *   - this implementation stores the objects contiguously in memory, so the cache locality is good
 *   - the main thing we do when interacting with the BPF maps it to iterate these lists, so again
 *     cache locality helps us be fast there
 *   - search is only used for the GRE IP config list, which is typically an especially small list
 *   - search is only used when building the initial list to avoid inserting multiple IP configs for
 *     the same GRE IP
 *   - we use a `cycle` for the BPF maps to make it quick and easy to remove stale entries
 *
 *  If we modify the BPF map update behavior or violate any of the other assumptions above, then we
 *  may want to revisit this implementation and consider using some kind of hash/tree data structure
 *  to make search time faster.
 */

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "list.h"

#define INITIAL_LIST_SIZE 32

List *list__new(size_t item_size, size_t key_size, list__key_eq_t key_eq) {
    List *list = malloc(sizeof(List));
    if (!list) {
        log_errno("malloc");
        log_error("Failed to allocate memory for list.");
        return NULL;
    }

    list->item_size = item_size;
    list->key_size = key_size;
    list->key_eq = key_eq;

    list->items = malloc(INITIAL_LIST_SIZE * item_size);
    if (!list->items) {
        log_errno("malloc");
        log_error("Failed to allocate memory for list items.");
        list__free(list);
        return NULL;
    }

    list->size = INITIAL_LIST_SIZE;
    list->length = 0;

    return list;
}

void list__free(List *list) {
    if (!list) { return; }
    if (list->items) { free(list->items); }
    free(list);
}

bool list__add(List *list, const void *item) {
    if (!list || !item) { return false; }

    // Double the list size, if necessary.
    if (list->length >= list->size) {
        // Check for arithmetic overflow.
        if (list->size > (SIZE_MAX / 2)) {
            log_error("List size overflow.");
            return false;
        }

        size_t new_size = list->size * 2;

        // Should never happen unless device list struct is manually modified.
        if (new_size < INITIAL_LIST_SIZE) {
            new_size = INITIAL_LIST_SIZE;
        }

        // Double the list size.
        List *new_items = realloc(list->items, new_size * list->item_size);
        if (!new_items) {
            log_errno("realloc");
            log_error("Failed to allocate memory for list (%u).", new_size);
            return false;
        }
        list->items = new_items;
        list->size = new_size;
    }

    // Copy the new item into the list.
    memcpy(list__nth(list, list->length), item, list->item_size);
    list->length++;

    return true;
}

bool list__contains(List *list, const void *key) {
    if (!list || !key) { return false; }

    for (size_t i = 0; i < list->length; i++) {
        if (list->key_eq(list__nth(list, i), key)) {
            return true;
        }
    }

    return false;
}

void *list__find(List *list, const void *key) {
    if (!list || !key) { return NULL; }

    for (size_t i = 0; i < list->length; i++) {
        void *item = list__nth(list, i);
        if (list->key_eq(item, key)) {
            return item;
        }
    }

    return NULL;
}

void *list__nth(List *list, size_t n) {
    return list->items + (n * list->item_size);
}
