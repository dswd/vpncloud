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


### Current Status

This project is under heavy development and has not reached a stable state yet.
This is what currently works:

* Normal operation using TUN/TAP interfaces and different forwarding modes (Hub, Switch, Router)
* Encryption using *libsodium*

However there are some open issues:

* Encryption has not been thoroughly reviewed, use with care.
* The protocol can still change.
* The software is not very well tested.
* The coverage score includes all unused methods from *libsodium*

Please feel free to help and contribute code.


### Semantic Versioning

This project uses [semantic versioning](http://semver.org). Currently that means that everything can change between versions before 1.0 is finally released. This is especially true for the network protocol and even more for the crypto part of it. Expect them to change before 1.0.
