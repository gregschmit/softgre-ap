// Detect BPF compilation context.
#ifdef __BPF__
    /* BPF/XDP program: use kernel headers. */
    #include <linux/in.h>
#else
    /* Userspace program: use standard library headers. */
    #include <netinet/in.h>
#endif

#define MAX_DEVICES 2048
#define MAC_SIZE 6

struct Device {
    unsigned char mac[MAC_SIZE];
    struct in_addr ip;
    unsigned short vlan;
};
