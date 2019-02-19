vpncloud(1) -- Peer-to-peer VPN
===============================

## SYNOPSIS

`vpncloud [options] [--config <file>] [-t <type>] [-d <name>] [-l <addr>] [-c <addr>...]`


## OPTIONS

  * `--config <file>`:

    Read configuration options from the specified file. Please see the section
    **CONFIG FILES** for documentation on the file format.
    If the same option is defined in the config file and as a parameter, the
    parameter overrides the config file.

  * `-t <type>`, `--type <type>`:

    Set the type of network. There are two options: **tap** devices process
    Ethernet frames **tun** devices process IP packets. [default: `tap`]

  * `-d <name>`, `--device <name>`:

    Name of the virtual device. Any `%d` will be filled with a free number.
    [default: `vpncloud%d`]

  * `--device-path <path>`:

    The path of the base device inode, e.g. /dev/net/run.

  * `-m <mode>`, `--mode <mode>`:

    The mode of the VPN. The VPN can like a router, a switch or a hub. A **hub**
    will send all data always to all peers. A **switch** will learn addresses
    from incoming data and only send data to all peers when the address is
    unknown. A **router** will send data according to known subnets of the
    peers and ignore them otherwise. The **normal** mode is switch for tap
    devices and router for tun devices. [default: `normal`]

  * `-l <port>`, `--listen <port>`:

    The port number on which to listen for data. [default: `3210`]

  * `-c <addr>`, `--connect <addr>`:

    Address of a peer to connect to. The address should be in the form
    `addr:port`. If the node is not started, the connection will be retried
    periodically. This parameter can be repeated to connect to multiple peers.

  * `-s <subnet>`, `--subnet <subnet>`:

    The local subnets to use. This parameter should be in the form
    `address/prefixlen` where address is an IPv4 address, an IPv6 address, or a
    MAC address. The prefix length is the number of significant front bits that
    distinguish the subnet from other subnets. Example: `10.1.1.0/24`.

  * `--shared-key <key>`:

    An optional shared key to encrypt the VPN data. If this option is not set,
    the traffic will be sent unencrypted.

  * `--crypto <method>`:

    The encryption method to use ("aes256", or "chacha20"). Most current CPUs
    have special support for AES256 so this should be faster. For older
    computers lacking this support, only CHACHA20 is supported.
    [default: `chacha20`]

  * `--magic <id>`:

    Override the 4-byte magic header of each packet. This header identifies the
    network and helps to distinguish it from other networks and other
    applications. The id can either be a 4 byte / 8 character hexadecimal
    string or an arbitrary string prefixed with "hash:" which will then be
    hashed into 4 bytes.

  * `--peer-timeout <secs>`:

    Peer timeout in seconds. The peers will exchange information periodically
    and drop peers that are silent for this period of time. [default: `1800`]

  * `--dst-timeout <secs>`:

    Switch table entry timeout in seconds. This parameter is only used in switch
    mode. Addresses that have not been seen for the given period of time  will
    be forgotten. [default: `300`]

  * `--beacon-store <path|command>`:
   
    Periodically store beacons containing the address of this node in the given
    file or via the given command. If the parameter value starts with a pipe
    character (`|`), the rest of the value is interpreted as a shell command.
    Otherwise the value is interpreted as a file to write the beacon to.
    If this parameter is not given, beacon storage is disabled.
    Please see the section **BEACONS** for more information.
    
  * `--beacon-load <path|command>`:
  
    Periodically load beacons containing the addresses of other nodes from the
    given file or via the given command. If the parameter value starts with a 
    pipe character (`|`), the rest of the value is interpreted as a shell 
    command. Otherwise the value is interpreted as a file to read the beacon 
    from. 
    If this parameter is not given, beacon loading is disabled.
    Please see the section **BEACONS** for more information.    

  * `--beacon-interval <secs>`:
  
    Beacon storage/loading interval in seconds. If configured to do so via
    `--beacon-store` and `--beacon-load`, the node will periodically store its
    beacon and load beacons of other nodes. This parameter defines the interval
    in seconds. [default: `3600`]  

  * `--ifup <command>`:

    A command to setup the network interface. The command will be run (as
    parameter to `sh -c`) when the device has been created to configure it.
    The name of the allocated device will be available via the environment
    variable `IFNAME`.
    Please note that this command is executed with the full permissions of the
    caller.

  * `--ifdown <command>`:

    A command to bring down the network interface. The command will be run (as
    parameter to `sh -c`) to remove any configuration from the device.
    The name of the allocated device will be available via the environment
    variable `IFNAME`.
    Please note that this command is executed with the (limited) permissions of
    the user and group given as `--user` and `--group`.

  * `--pid-file <file>`:

    Store the process id in this file when running in the background. If set,
    the given file will be created containing the process id of the new
    background process. This option is only used when running in background.

  * `--user <user>`:
  * `--group <group>`:

    Change the user and/or group of the process once all the setup has been
    done and before spawning the background process. This option is only used
    when running in background.

  * `--log-file <file>`:

    If set, print logs also to the given file. The file will be created and
    truncated if is exists.

  * `--stats-file <file>`:
   
    If set, periodically write statistics on peers and current traffic to the
    given file. The file will be periodically overwritten with new data.

  * `--daemon`:

    Spawn a background process instead of running the process in the foreground.
    If this flag is set, the process will first carry out all the
    initialization, then drop permissions if `--user` or `--group` is used and
    then spawn a background process and write its process id to a file if
    `--pid-file` is set. Then, the main process will exit and the background
    process continues to provide the VPN. At the time, when the main process
    exits, the interface exists and is properly configured to be used.

  * `--no-port-forwarding`:

    Disable automatic port forward. If this option is not set, VpnCloud tries to
    detect a NAT router and automatically add a port forwarding to it.

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
    (option `dst_timeout`) will be forgotten. Data for unknown addresses will be
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
    to the cross-connect behavior, the `magic` option can be used and set
    to any unique string to identify the network. The `magic` must be the
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

In this example, 2 nodes and their subnets should communicate using IP.
First, VpnCloud need to be started on both nodes:

```
vpncloud -t tun -c REMOTE_HOST:PORT --subnet 10.0.X.0/24 --ifup 'ifconfig $IFNAME 10.0.X.1/16 mtu 1400 up'
```

It is important to configure the interface in a way that all addresses on the
VPN can be reached directly. E.g. if subnets 10.0.1.0/24, 10.0.2.0/24 and so on
are used, the interface needs to be configured as 10.0.1.1/16.
For TUN devices, this means that the prefix length of the subnets
(/24 in this example) must be different than the prefix length that the
interface is configured with (/16 in this example).


### Important notes

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
  which is used to encrypt the payload of messages using *ChaCha20Poly1305* or
  *AES256-GCM*. The encryption includes an authentication that also protects the
  header.
  This method does only protect against attacks on single messages but not
  against attacks that manipulate the message series itself (i.e. suppress
  messages, reorder them, or duplicate them).


## CONFIG FILES

The config file is a YAML file that contains configuration values. All entries
are optional and override the defaults. Please see the section **OPTIONS** for
detailed descriptions of the options.

* `device_type`: Set the type of network. Same as `--type`
* `device_name`: Name of the virtual device. Same as `--device`
* `device_path`: Set the path of the base device. Same as `--device-path`
* `ifup`: A command to setup the network interface. Same as `--ifup`
* `ifdown`: A command to bring down the network interface. Same as `--ifdown`
* `crypto`: The encryption method to use. Same as `--crypto`
* `shared_key`: The shared key to encrypt all traffic. Same as `--shared-key`
* `magic`: Override the 4-byte magic header of each packet. Same as `--magic`
* `port`: The port number on which to listen for data. Same as `--listen`
* `peers`: A list of addresses to connect to. See `--connect`
* `peer_timeout`: Peer timeout in seconds. Same as`--peer-timeout`
* `beacon_store`: Path or command to store beacons. Same as `--beacon-store`
* `beacon_load`: Path or command to load beacons. Same as `--beacon-load`
* `beacon_interval`: Interval for loading and storing beacons in seconds. Same as `--beacon-interval` 
* `mode`: The mode of the VPN. Same as `--mode`
* `dst_timeout`: Switch table entry timeout in seconds. Same as `--dst-timeout`
* `subnets`: A list of local subnets to use. See `--subnet`
* `port_forwarding`: Whether to activate port forwardig. See `--no-port-forwarding`
* `user`: The name of a user to run the background process under. See `--user`
* `group`: The name of a group to run the background process under. See `--group`
* `pid_file`: The path of the pid file to create. See `--pid-file`
* `stats_file`: The path of the statistics file. See `--stats-file`


### Example

device_type: tun
device_name: vpncloud%d
ifup: ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up
crypto: aes256
shared_key: mysecret
port: 3210
peers:
  - remote.machine.foo:3210
  - remote.machine.bar:3210
peer_timeout: 1800
mode: normal
subnets:
  - 10.0.1.0/24
port_forwarding: true
user: nobody
group: nogroup
pid_file: /run/vpncloud.pid


## BEACONS

Beacons are short character sequences that contain a timestamp and a list of
addresses. They can be published and retrieved by other nodes to find peers
without the need for static addresses.

The beacons are short (less than 100 characters), encrypted and encoded with
printable characters to allow publishing them in various places on the 
internet, e.g.:
- On shared drives or synchronized folders (e.g. on Dropbox)
- Via a dedicated database
- Via a general purpose message board of message service (e.g. Twitter)    

The beacons are very robust. They only consist of alphanumeric characters
and can be interleaved with non-alphanumeric characters (e.g. whitespace).
Also the beacons contain a prefix and suffix that depends on the configured
network magic and secret key (if set) so that all nodes can find beacons in
a long text.

When beacons are stored or loaded via a command (using the pipe character `|`),
the command is interpreted using the configured shell `sh`. This command has 
access to the following environment variables:
* `$begin`: The prefix of the beacon.
* `$end`: The suffix of the beacon.
* `$data` (only on store): The middle part of the beacon. Do not use this 
  without prefix and suffix!
* `$beacon` (only on store): The full beacon consisting of prefix, data and 
  suffix.
The commands are called in separate threads, so even longer running commands 
will not block the node.


## NETWORK PROTOCOL

The protocol of VpnCloud is kept as simple as possible to allow other
implementations and to maximize the performance.

Every packet sent over UDP contains the following header (in order):

  * 4 bytes `magic`

    This field is used to identify the packet and to sort out packets that do
    not belong. The default is `[0x76, 0x70, 0x6e, 0x01]` ("vpn\x01").
    This field can be used to identify VpnCloud packets and might be set to
    something different to hide the protocol.

  * 1 byte `crypto method`

    This field specifies the method that must be used to decrypt the rest of the
    data. The currently supported methods are:

    - Method `0`, **No encryption**: Rest of the data can be read without
      decrypting it.

    - Method `1`, **ChaCha20**: The header is followed by a 12 byte
      *nonce*. The rest of the data is encrypted with the
      `libsodium::crypto_aead_chacha20poly1305_ietf` method, using the 8 byte
      header as additional data.

    - Method `2`, **AES256**: The header is followed by a 12 byte *nonce*.
      The rest of the data is encrypted with the
      `libsodium::crypto_aead_aes256gcm` method, using the 8 byte header
      as additional data.

  * 2 `reserved bytes` that are currently unused and set to 0

  * 1 byte for the `message type`

    This byte specifies the type of message that follows. Currently the
    following message types are supported:

    - Type 0: Data packet
    - Type 1: Peer list
    - Type 2: Initial message
    - Type 3: Closing message

After this 8 byte header, the rest of the message follows. It is encrypted using
the method specified in the header.

In the decrypted data, the message as specified in the `message type` field
will follow:

  * **Data packet** (message type 0):
    This packet contains payload. The format of the data depends on the device
    type. For TUN devices, this data contains an IP packet. For TAP devices it
    contains an Ethernet frame. The data starts right after the header and ends
    at the end of the packet.
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
    This packet contains the following information:
      - The stage of the initialization process
      - A random node id to distinguish different nodes
      - All the local subnets claimed by the nodes

    Its first byte marks the stage of the initial handshake process.
    The next 16 bytes contain the unique node id. After that,
    the list of local subnets follows.
    The subnet list is encoded in the following way: Its first byte of data
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
    This packet does not contain any more data.

Nodes are expected to send an **initial message** with stage 0 whenever they
connect to a node they were not connected to before. As a reply to this message,
another initial should be sent with stage 1. Also a **peer list** message should
be sent as a reply.

When connected, nodes should periodically send their **peer list** to all
of their peers to spread this information and to avoid peer timeouts.
To avoid the cubic growth of management traffic, nodes should at a certain
network size start sending partial peer lists instead of the full list. A
reasonable number would be about 20 peers. The subsets should be selected
randomly.

Nodes should remove peers from their peer list after a certain period of
inactivity or when receiving a **closing message**. Before shutting down, nodes
should send the closing message to all of their peers in order to avoid
receiving further data until the timeout is reached.

Nodes should only add nodes to their peer list after receiving an initial
message from them instead of adding them right from the peer list of another
peer. This is necessary to avoid the case of a large network keeping dead nodes
alive.


## COPYRIGHT

Copyright (C) 2015-2019  Dennis Schwerdel
This software is licensed under GPL-3 or newer (see LICENSE.md)
