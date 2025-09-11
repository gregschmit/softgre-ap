#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

#include "shared.h"

typedef bool (*list__key_eq_t)(const void* key1, const void* key2);

struct List {
    void *items;
    size_t size;
    size_t length;
    size_t item_size;
    size_t key_size;
    bool (*key_compare)(const void* key1, const void* key2);
};

struct List *list__new(size_t item_size, size_t key_size, list__key_eq_t key_eq);
void list__free(struct List *list);
bool list__add(struct List *list, const void *item);
bool list__contains(struct List *list, const void *key);
void *list__nth(struct List *list, size_t n);

#endif  // LIST_H
