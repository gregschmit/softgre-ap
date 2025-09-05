#include <netinet/in.h>

struct Device {
    unsigned char mac[6];
    struct in_addr ip;
    unsigned int vlan;
};
