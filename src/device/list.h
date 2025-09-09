#ifndef DEVICE_LIST_H
#define DEVICE_LIST_H

#include <stdbool.h>

#include "../device.h"

struct DeviceList {
    struct Device *devices;
    unsigned int size;
    unsigned int length;
};

struct DeviceList *device_list__new();
void device_list__free(struct DeviceList *list);
bool device_list__add(struct DeviceList *list, struct Device device);

#endif  // DEVICE_LIST_H
