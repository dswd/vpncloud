VpnCloud - Peer-to-Peer VPN
---------------------------

[![Build Status](https://travis-ci.org/dswd/vpncloud.rs.svg?branch=master)](https://travis-ci.org/dswd/vpncloud.rs)
[![Coverage Status](https://coveralls.io/repos/dswd/vpncloud.rs/badge.svg?branch=master&service=github)](https://coveralls.io/github/dswd/vpncloud.rs?branch=master)
[![Latest Version](https://img.shields.io/crates/v/vpncloud.svg)](https://crates.io/crates/vpncloud)

**VpnCloud** is a simple VPN over UDP. It creates a virtual network interface on
the host and forwards all received data via UDP to the destination. VpnCloud
establishes a fully-meshed VPN network in a peer-to-peer manner. It can work
on TUN devices (IP based) and TAP devices (Ethernet based). Tunneling traffic
between two nodes can be as easy as:

```
vpncloud -c REMOTE_HOST:PORT --ifup 'ifconfig $IFNAME 10.0.0.1/24 mtu 1400 up'
```

For more information, please see the [Wiki](wiki).


### Project Status

This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. VpnCloud features the following functionality:

* Setting up tunnels between two networks via Ethernet (TAP) and IP (TUN)
* Connecting multiple networks with multiple forwarding behaviors (Hub, Switch,
  Router)
* Encrypted connections using [libsodium](https://github.com/jedisct1/libsodium)
* Automatic peer-to-peer meshing, no central servers
* NAT and (limited) firewall traversal using hole punching
* Automatic reconnecting when connections are lost
* Non-native forwarding modes, e.g. IP based learning switch and prefix routed
  Ethernet networks.
* High throughput and low additional latency (see [performance page](wiki/Performance-Measurements))
* Support for tunneled VLans (TAP device)


### Contributions welcome

There are several areas in which still some work has to be done and where
contributions are very welcome:

* **Linux packages**: VpnCloud is stable enough to be packaged for Linux
  distributions.
* **Security review**: The security has been implemented with strong security
  primitives but it would great if a cryptography expert could verify the
  system.
* **Feedback on use cases**: Some feedback on how VpnCloud is being used and
  maybe some tutorials covering common use cases would be nice.


### Semantic Versioning

This project uses [semantic versioning](http://semver.org). Currently that means
that everything can change between versions before 1.0 is finally released.
However I am considering to release 1.0 soon.
