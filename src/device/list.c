#include <stdlib.h>

#include "../log.h"
#include "list.h"

#define INITIAL_DEVICE_LIST_SIZE 32

struct DeviceList device_list__new() {
    struct DeviceList list;
    list.devices = malloc(INITIAL_DEVICE_LIST_SIZE * sizeof(struct Device));
    if (!list.devices) {
        log_errno("malloc");
        log_error("Failed to allocate memory for device list.");
        list.size = 0;
        list.length = 0;
        return list;
    }

    list.size = INITIAL_DEVICE_LIST_SIZE;
    list.length = 0;

    return list;
}

void device_list__free(struct DeviceList list) {
    free(list.devices);
    list.devices = NULL;
    list.size = 0;
    list.length = 0;
}

int device_list__add(struct DeviceList list, struct Device device) {
    // Double the device list size, if necessary.
    if (list.length >= list.size) {
        unsigned int new_size = list.size * 2;
        if (new_size < INITIAL_DEVICE_LIST_SIZE) {
            new_size = INITIAL_DEVICE_LIST_SIZE;
        }
        struct Device *new_devices = realloc(list.devices, new_size * sizeof(struct Device));
        if (!new_devices) {
            log_errno("realloc");
            log_error("Failed to reallocate memory for device list (%u).", new_size);
            return -1;
        }
        list.devices = new_devices;
        list.size = new_size;
    }

    // Add the new device.
    list.devices[list.length++] = device;

    return 0;
}
