vpncloud(1) -- Peer-to-peer VPN
===============================

## SYNOPSIS

`vpncloud [options] [-t <type>] [-d <name>] [-l <addr>] [-c <addr>...]`


## OPTIONS

  * `-t <type>`, `--type <type>`:

    Set the type of network. There are two options: **tap** devices process
    Ethernet frames **tun** devices process IP packets. [default: `tap`]

  * `-d <name>`, `--device <name>`:

    Name of the virtual device. Any `%d` will be filled with a free number.
    [default: `vpncloud%d`]

  * `-m <mode>`, `--mode <mode>`:

    The mode of the VPN. The VPN can like a router, a switch or a hub. A **hub**
    will send all data always to all peers. A **switch** will learn addresses
    from incoming data and only send data to all peers when the address is
    unknown. A **router** will send data according to known subnets of the
    peers and ignore them otherwise. The **normal** mode is switch for tap
    devices and router for tun devices. [default: `normal`]

  * `-l <addr>`, `--listen <addr>`:

    The address to listen for data. [default: `0.0.0.0:3210`]

  * `-c <addr>`, `--connect <addr>`:

    Address of a peer to connect to. The address should be in the form
    `addr:port`. If the node is not started, the connection will be retried
    periodically. This parameter can be repeated to connect to multiple peers.

  * `--subnet <subnet>`:

    The local subnets to use. This parameter should be in the form
    `address/prefixlen` where address is an IPv4 address, an IPv6 address, or a
    MAC address. The prefix length is the number of significant front bits that
    distinguish the subnet from other subnets. Example: `10.1.1.0/24`.

  * `--shared-key <key>`:

    An optional shared key to encrypt the VPN data. If this option is not set,
    the traffic will be sent unencrypted.

  * `--network-id <id>`:

    An optional token that identifies the network and helps to distinguish it
    from other networks.

  * `--peer-timeout <secs>`:

    Peer timeout in seconds. The peers will exchange information periodically
    and drop peers that are silent for this period of time. [default: `1800`]

  * `--dst-timeout <secs>`:

    Switch table entry timeout in seconds. This parameter is only used in switch
    mode. Addresses that have not been seen for the given period of time  will
    be forgot. [default: `300`]

  * `--ifup <command>`:

    A command to setup the network interface. The command will be run (as
    parameter to `sh -c`) when the device has been created to configure it.
    The name of the allocated device will be available via the environment
    variable `IFNAME`.

  * `--ifdown <command>`:

    A command to bring down the network interface. The command will be run (as
    parameter to `sh -c`) to remove any configuration from the device.
    The name of the allocated device will be available via the environment
    variable `IFNAME`.

  * `-v`, `--verbose`:

    Print debug information, including information for data being received and
    sent.

  * `-q`, `--quiet`:

    Only print errors and warnings.

  * `-h`, `--help`:

    Display the help.


## DESCRIPTION

**VpnCloud** is a simple VPN over UDP. It creates a virtual network interface on
the host and forwards all received data via UDP to the destination. It can work
in 3 different modes:

  * **Switch mode**: In this mode, the VPN will dynamically learn addresses
    as they are used as source addresses and use them to forward data to its
    destination. Addresses that have not been seen for some time
    (option `dst_timeout`) will be forgot. Data for unknown addresses will be
    broadcast to all peers. This mode is the default mode for TAP devices that
    process Ethernet frames but it can also be used with TUN devices and IP
    packets.

  * **Hub mode**: In this mode, all data will always be broadcast to all peers.
    This mode uses lots of bandwidth and should only be used in special cases.

  * **Router mode**: In this mode, data will be forwarded based on preconfigured
    address ranges ("subnets"). Data for unknown nodes will be silently ignored.
    This mode is the default mode for TUN devices that work with IP packets but
    it can also be used with TAP devices and Ethernet frames.

All connected VpnCloud nodes will form a peer-to-peer network and cross-connect
automatically until the network is fully connected. The nodes will periodically
exchange information with the other nodes to signal that they are still active
and to allow the automatic cross-connect behavior. There are some important
things to note:

  - To avoid that different networks that reuse each others addresses merge due
    to the cross-connect behavior, the `network_id` option can be used and set
    to any unique string to identify the network. The `network_id` must be the
    same on all nodes of the same VPN network.

  - The cross-connect behavior can be able to connect nodes that are behind
    firewalls or NATs as it can function as hole-punching.

  - The management traffic will increase with the peer number quadratically.
    It should still be reasonably small for high node numbers (below 10 KiB/s
    for 10.000 nodes). A longer `peer_timeout` can be used to reduce the traffic
    further. For high node numbers, router mode should be used as it never
    broadcasts data.

VpnCloud does not implement any loop-avoidance. Since data received on the UDP
socket will only be sent to the local network interface and vice versa, VpnCloud
cannot produce loops on its own. On the TAP device, however STP data can be
transported to avoid loops caused by other network components.

For TAP devices, IEEE 802.1q frames (VLAN tagged) are detected and forwarded
based on separate MAC tables. Any nested tags (Q-in-Q) will be ignored.


## EXAMPLES

### Switched TAP scenario

In the example scenario, a simple layer 2 network tunnel is established. Most
likely those commands need to be run as **root** using `sudo`.

First, VpnCloud need to be started on both nodes (the address after `-c` is the
address of the remote node and the the `X` in the interface address must be
unique among all nodes, e.g. 0, 1, 2, ...):

```
vpncloud -c REMOTE_HOST:PORT --ifup 'ifconfig $IFNAME 10.0.0.X/24 mtu 1400 up'
```

Afterwards, the interface can be used to communicate.


### Routed TUN example

In this example, 4 nodes should communicate using IP. First, VpnCloud need to
be started on both nodes:

```
vpncloud -t tun -c REMOTE_HOST:PORT --subnet 10.0.0.X/32 --ifup 'ifconfig $IFNAME 10.0.0.0/24 mtu 1400 up'
```


### Important notes

- It is important to configure the interface in a way that all addresses on the
  VPN can be reached directly. E.g. if addresses 10.0.0.1 and 10.0.0.2 are used,
  the interface needs to be configured as /24.
  For TUN devices, this means that the prefix length of the subnets must be
  different than the prefix length that the interface is configured with.

- VpnCloud can be used to connect two separate networks. TAP networks can be
  bridged using `brctl` and TUN networks must be routed. It is very important
  to be careful when setting up such a scenario in order to avoid network loops,
  security issues, DHCP issues and many more problems.

- TAP devices will forward DHCP data. If done intentionally, this can be used
  to assign unique addresses to all participants. If this happens accidentally,
  it can conflict with DHCP servers of the local network and can have severe
  side effects.

- VpnCloud is not designed for high security use cases. Although the used crypto
  primitives are expected to be very secure, their application has not been
  reviewed.
  The shared key is hashed using *ScryptSalsa208Sha256* to derive a key,
  which is used to encrypt the payload of messages using *ChaCha20*. The
  authenticity of messages is verified using *HmacSha512256* hashes.
  This method only protects the contents of the message (payload, peer list,
  etc.) but not the header of each message.
  Also, this method does only protect against attacks on single messages but not
  on attacks that manipulate the message series itself (i.e. suppress messages,
  reorder them, and duplicate them).


## NETWORK PROTOCOL

The protocol of VpnCloud is kept as simple as possible to allow other
implementations and to maximize the performance.

Every packet sent over UDP contains the following header (in order):

  * 3 bytes `magic constant` = `[0x76, 0x70, 0x6e]` ("vpn")

    This field is used to identify the packet and to sort out packets that do
    not belong.

  * 1 byte `version number` = 1 (currently)

    This field specifies the version and helps nodes to parse the rest of the
    header and the packet.

  * 2 `reserved bytes` that are currently unused

  * 1 byte for `flags`

    This byte contains flags that specify the presence of additional headers.
    The flags are enumerated from bit 1 (least significant bit) to bit 8
    (most significant bit). The additional headers must be present in this same
    order. Currently the following additional headers are supported:

    - Bit 1: Network ID
    - Bit 2: Crypto information

  * 1 byte for the `message type`

    This byte specifies the type of message that follows after all additional
    headers. Currently the following message types are supported:

    - Type 0: Data packet
    - Type 1: Peer list
    - Type 2: Initial message
    - Type 3: Closing message

After this 8 byte header, the additional headers as specified in the `flags`
field will follow in the order of their respective flag bits.

  * **Network ID**:

    The network id is encoded as 8 bytes.

  * **Crypto information**:

    If this header is present, the contents of the message are encrypted and
    must have to decrypted before decoding.
    This option contains 40 bytes. The first 8 bytes are the **nonce** for this
    message and the later 32 bytes are the **authentication hash** of the
    message.

After the additional headers, message as specified in the `message type` field
will follow:

  * **Data packet** (message type 0):
    This packet contains payload. The format of the data depends on the device
    type. For TUN devices, this data contains an IP packet. For TAP devices it
    contains an Ethernet frame. The data starts right after all additional
    headers and ends at the end of the packet.
    If it is an Ethernet frame, it will start with the destination MAC and end
    with the payload. It does not contain the preamble, SFD, padding, and CRC
    fields.

  * **Peer list** (message type 1):
    This packet contains the peer list of the sender. The first byte after the
    switch byte contains the number of IPv4 addresses that follow.
    After that, the specified number of addresses follow, where each address
    is encoded in 6 bytes. The first 4 bytes are the IPv4 address and the later
    2 bytes are port number (both in network byte order).
    After those addresses, the next byte contains the number of IPv6 addresses
    that follow. After that, the specified number of addresses follow, where
    each address is encoded in 18 bytes. The first 16 bytes are the IPv6 address
    and the later 2 bytes are port number (both in network byte order).

  * **Initial message** (message type 2):
    This packet contains all the local subnets claimed by the nodes.
    The subnet list is encoded in the following way: The first byte of data
    contains the number of encoded subnets that follow. After that, the given
    number of encoded subnets follow.
    For each subnet, the first byte is the length of bytes in the base address
    and is followed by the given number of base address bytes and one additional
    byte that is the prefix length of the subnet.
    The addresses for the subnet will be encoded like they are encoded in their
    native protocol (4 bytes for IPv4, 16 bytes for IPv6, and 6 bytes for a MAC
    address) with the exception of MAC addresses in a VLan which will be encoded
    in 8 bytes where the first 2 bytes are the VLan number in network byte order
    and the later 6 bytes are the MAC address.

  * **Closing message** (message type 3):
    This packet does not contain any further data.

Nodes are expected to send an **initial message** whenever they connect to a
node they were not connected to before. As a reply to this message, another
initial should be sent if the node was not known before. Also a **peer list**
message should be sent as a reply.

When connected, nodes should periodically send their **peer list** to all
of their peers to spread this information and to avoid peer timeouts.
To avoid the cubic growth of management traffic, nodes should at a certain
network size start sending partial peer lists instead of the full list.
A reasonable number would be the square root of the number of peers.
The subsets can be selected using round robin (making sure all peers eventually
receive all information) or randomly.

Nodes should remove peers from their peer list after a certain period of
inactivity or when receiving a **closing message**. Before shutting down, nodes
should send the closing message to all of their peers in order to avoid
receiving further data until the timeout is reached.

Nodes should only add nodes to their peer list after receiving an initial
message from them instead of adding them right from the peer list of another
peer. This is necessary to avoid the case of a large network keeping dead nodes
alive.


## COPYRIGHT

Copyright (C) 2015 Dennis Schwerdel
