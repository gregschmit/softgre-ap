# SoftGRE AP Initiator

This project implements a SoftGRE-based Access Point (AP) initiator using a userspace daemon and a
BPF program. The daemon mounts the BPF program to the configured interfaces (should be mounted to
the WLAN interface and the interface that wires the AP into the network) and monitors a config file
that should be updated by `hostapd` when a RADIUS Access-Accept message is received for a client
and the message includes tunnel information. The BPF program then manages the encapsulation and
decapsulation of packets between the client and the GRE IP endpoint.

## TODO

- Implement VLAN-awareness
