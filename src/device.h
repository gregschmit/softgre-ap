// Detect BPF compilation context.
#ifdef __BPF__
    /* BPF/XDP program: use kernel headers. */
    #include <linux/in.h>
#else
    /* Userspace program: use standard library headers. */
    #include <netinet/in.h>
    #include <netinet/ether.h>
#endif

#define MAX_DEVICES 2048

struct Device {
    unsigned char mac[ETH_ALEN];
    struct in_addr ip;
    unsigned short vlan;
};
