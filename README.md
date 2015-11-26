VpnCloud - Peer-to-Peer VPN
---------------------------

[![Build Status](https://travis-ci.org/dswd/vpncloud.rs.svg?branch=master)](https://travis-ci.org/dswd/vpncloud.rs)
[![Coverage Status](https://coveralls.io/repos/dswd/vpncloud.rs/badge.svg?branch=master&service=github)](https://coveralls.io/github/dswd/vpncloud.rs?branch=master)
[![Latest Version](https://img.shields.io/crates/v/vpncloud.svg)](https://crates.io/crates/vpncloud)

**VpnCloud** is a simple VPN over UDP. It creates a virtual network interface on
the host and forwards all received data via UDP to the destination. It can work
on TUN devices (IP based) and TAP devices (Ethernet based). Tunneling traffic
between two nodes can be as easy as:

```
vpncloud -c REMOTE_HOST:PORT --ifup 'ifconfig $IFNAME 10.0.0.1/24 mtu 1400 up'
```

More details can be found in [the manpage](vpncloud.md).
Some performance measurements can be found [here](performance.md).


### Current Status

This project is still under development and has yet to reach a stable state.
However, the main functionality should work and you are invited to test it.
This is what works:

* Setting up tunnels between two networks via Ethernet (TAP) and IP (TUN)
* Connecting multiple networks with multiple forwarding behaviors (Hub, Switch, Router)
* Encrypted connections using *libsodium*
* Automatic peer-to-peer meshing
* NAT and (limited) firewall traversal using hole punching
* Automatic reconnecting when connections are lost
* Non-native forwarding modes, e.g. IP based learning switch and prefix routed Ethernet networks.
* High throughput and low additional latency (see [performance page](performance.md))

However there are some open issues:

* Encryption has not been thoroughly reviewed, use with care.
* The software is not very well tested and the protocol can change.

Please feel free to help and contribute code.


### Semantic Versioning

This project uses [semantic versioning](http://semver.org). Currently that means that everything can change between versions before 1.0 is finally released.
