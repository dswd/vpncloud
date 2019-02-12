VpnCloud - Peer-to-Peer VPN
---------------------------

[![Build Status](https://travis-ci.org/dswd/vpncloud.rs.svg?branch=master)](https://travis-ci.org/dswd/vpncloud.rs)
[![Coverage Status](https://coveralls.io/repos/dswd/vpncloud.rs/badge.svg?branch=master&service=github)](https://coveralls.io/github/dswd/vpncloud.rs?branch=master)

**VpnCloud** is a simple VPN over UDP. It creates a virtual network interface on
the host and forwards all received data via UDP to the destination. VpnCloud
establishes a fully-meshed VPN network in a peer-to-peer manner. It can work
on TUN devices (IP based) and TAP devices (Ethernet based). Tunneling traffic
between two nodes can be as easy as:

```
vpncloud -c REMOTE_HOST:PORT --ifup 'ifconfig $IFNAME 10.0.0.1/24 mtu 1400 up'
```

For more information, please see the [Website](https://vpncloud.ddswd.de).


### Project Status

This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. VpnCloud features the following functionality:

* Setting up tunnels between two networks via Ethernet (TAP) and IP (TUN)
* Connecting multiple networks with multiple forwarding behaviors (Hub, Switch,
  Router)
* Encrypted connections
* Automatic peer-to-peer meshing, no central servers
* NAT and (limited) firewall traversal using hole punching
* Automatic reconnecting when connections are lost
* Non-native forwarding modes, e.g. IP based learning switch and prefix routed
  Ethernet networks.
* High throughput and low additional latency (see [performance page](https://vpncloud.ddswd.de/features/performance))
* Support for tunneled VLans (TAP device)
* Option to hide protocol header
* Automatic port forwarding via UPnP


### Installing

##### Compiling from source
Prerequisites: Git, [Cargo](https://www.rust-lang.org/install.html),
  Full C build environment including autotools (for building libsodium)

The checked-out code can be compiled with ``make``.
The binary could then be found in `target/release/vpncloud`.
The tests can be run via ``cargo test``.


##### Debian / Ubuntu
Deb packages for each release can be found in the
[releases](https://github.com/dswd/vpncloud/releases) section. Currently only
packages for amd64 are available (I am accepting help on building and packaging
for other platforms).


##### Arch Linux (AUR)
There is a [VpnCloud package for Arch Linux](https://aur.archlinux.org/packages/vpncloud/)
thanks to Oscar Rainford (fourbytes).


### Contributions welcome

There are several areas in which still some work has to be done and where
contributions are very welcome:

* **Linux packages**: VpnCloud is stable enough to be packaged for Linux
  distributions. Maintainers who want to package VpnCloud are very welcome.
* **Security review**: The security has been implemented with strong security
  primitives but it would be great if a cryptography expert could verify the
  system.
* **Feedback on use cases**: Some feedback on how VpnCloud is being used and
  maybe some tutorials covering common use cases would be nice.


### Semantic Versioning

This project uses [semantic versioning](http://semver.org). Currently that means
that everything can change between versions before 1.0 is finally released.
However I am considering to release 1.0 soon.
