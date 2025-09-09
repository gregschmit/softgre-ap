#include <limits.h>
#include <stdlib.h>

#include "../log.h"

#include "list.h"

#define INITIAL_DEVICE_LIST_SIZE 32

struct DeviceList *device_list__new() {
    struct DeviceList *list = malloc(sizeof(struct DeviceList));
    if (!list) {
        log_errno("malloc");
        log_error("Failed to allocate memory for device list.");
        return NULL;
    }

    list->devices = malloc(INITIAL_DEVICE_LIST_SIZE * sizeof(struct Device));
    if (!list->devices) {
        log_errno("malloc");
        log_error("Failed to allocate memory for device list.");
        device_list__free(list);
        return NULL;
    }

    list->size = INITIAL_DEVICE_LIST_SIZE;
    list->length = 0;

    return list;
}

void device_list__free(struct DeviceList *list) {
    if (!list) { return; }

    if (list->devices) {
        free(list->devices);
        list->devices = NULL;
    }

    free(list);
}

bool device_list__add(struct DeviceList *list, struct Device device) {
    if (!list) { return false; }

    // Double the device list size, if necessary.
    if (list->length >= list->size) {
        // Check for arithmetic overflow.
        if (list->size > (UINT_MAX / 2)) {
            log_error("Device list size overflow.");
            return false;
        }

        unsigned int new_size = list->size * 2;

        // Should never happen unless device list struct is manually modified.
        if (new_size < INITIAL_DEVICE_LIST_SIZE) {
            new_size = INITIAL_DEVICE_LIST_SIZE;
        }

        struct Device *new_devices = realloc(list->devices, new_size * sizeof(struct Device));
        if (!new_devices) {
            log_errno("realloc");
            log_error("Failed to allocate memory for device list (%u).", new_size);
            return false;
        }
        list->devices = new_devices;
        list->size = new_size;
    }

    // Add the new device.
    list->devices[list->length++] = device;

    return true;
}
