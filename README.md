# dtuninit (Dynamic Tunnel Initiator)

This project implements a tunnel initiator using a userspace daemon and a set of BPF programs. The
daemon mounts the BPF programs to the configured interfaces (should be mounted to the WLAN interface
and the interface that wires the AP into the network) and monitors a clients file that should be
updated by `hostapd` when a RADIUS Access-Accept message is received for a client and the message
includes tunnel information. The BPF program then manages the encapsulation and decapsulation of
packets between the client and the GRE IP endpoint.

## TODO

- Modify watch logic to reload when interfaces change (needed for being a reasonable daemon).
- Implement subcommands so it can be started, but also used as a tool to manage the clients file.
- Implement GRE over UDP to support NAT.
- Implement VXLAN.
- Implement L2TPv3.
- Add support for IPv6 endpoints.
