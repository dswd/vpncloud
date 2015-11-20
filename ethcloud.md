ethcloud(1) -- Layer 2 VPN over UDP
===================================

## SYNOPSIS

```
Usage:
    ethcloud [options]

Options:
    -d <device>, --device <device>         Name of the tap device [default: ethcloud%d]
    -l <listen>, --listen <listen>         Address to listen on [default: 0.0.0.0:3210]
    -t <token>, --token <token>            Token that identifies the network [default: 0]
    -c <connect>, --connect <connect>      List of peers (addr:port) to connect to
    --peer-timeout <peer_timeout>          Peer timeout in seconds [default: 1800]
    --mac-timeout <mac_timeout>            Mac table entry timeout in seconds [default: 300]
    -v, --verbose                          Log verbosely
    -q, --quiet                            Only print error messages
```

## DESCRIPTION

**Ethcloud** is a simple layer 2 VPN over UDP. It creates an ethernet based
network interface on the host and forwards all received frames via UDP to the
destination.
The forwarding is based on traditional switch behavior with MAC address
learning. Whenever a frame is received, the sender UDP address and MAC address
are associated and used for replies. Frames for unknown addresses will be
broadcast to all peers.
All connected ethcloud programs will form a peer-to-peer network and
cross-connect automatically until the network is fully connected.

The token is used to distinguish different networks and discard foreign packets.
It should be unique.

Ethcloud does not implement any loop-avoidance. Since data received on the UDP
socket will only be sent to the local network interface and vice versa, ethcloud
cannot produce loops on its own.

IEEE 802.1q frames (VLAN tagged) are detected and forwarded based on separate
MAC tables. All frames without a tag will be treated as having tag `0`.

The peer-to-peer protocol will cause nodes to exchange information about their
peers. For nodes behind a firewall or a NAT, this can function as hole-punching.


## NETWORK PROTOCOL

The protocol of `ethcloud` is kept as simple as possible to allow other
implementations and to maximize the performance.

The first 7 bytes of each packet are the token that is used to distinguish
different networks and sort out stray packets that do not belong.

After that, the 8th byte is a switch that determines the structure of the rest
of the packet:

  * **Frame packet** (value `0`):
    This packet contains an actual ethernet frame which starts right after the
    switch byte and ends at the end of the packet. It contains the main
    ethernet frame data starting with the destination MAC and ending with the
    payload. It does not contain the preamble, SFD, padding, and CRC fields.

  * **Peer list** (value `1`):
    This packet contains the peer list of the sender. The first byte after the
    switch byte contains the number of IPv4 addresses that follow.
    After that, the specified number of addresses follow, where each address
    is encoded in 6 bytes. The first 4 bytes are the IPv4 address and the later
    2 bytes are port number (both in network byte order).
    After those addresses, the next byte contains the number of IPv6 addresses
    that follow. After that, the specified number of addresses follow, where
    each address is encoded in 18 bytes. The first 16 bytes are the IPv6 address
    and the later 2 bytes are port number (both in network byte order).

  * **Get peer list** (value `2`):
    This packet requests that the receiver sends its peer list to the sender.
    It does not contain any further data.

  * **Close** (value `3`):
    This packet requests that the receiver removes the sender from its peer list
    and stops sending data to it. It does not contain any further data.

Nodes are expected to request the peer list from the initial nodes they are
connecting to. After that, they should periodically send their peer list to all
of their peers to spread this information and to avoid peer timeouts.
To avoid the cubic growth of management traffic, nodes should select a subset of
peers and send them a subset of their peer information. A reasonable number
would be the square root of the number of peers. The subsets can be selected
using round robin (making sure all peers eventually receive all information)
or randomly.

Nodes should remove peers from their peer list after a certain period of
inactivity or when receiving a `Close` message. Before shutting down, nodes
should send the `Close` message to all of their peers in order to avoid
receiving further data until the timeout is reached.

Nodes should only add nodes to their peer list after receiving a message from
them instead of adding them right from the peer list of another peer. This
is necessary to avoid the case of a large network keeping dead nodes alive


## COPYRIGHT

Copyright (C) 2015 Dennis Schwerdel
