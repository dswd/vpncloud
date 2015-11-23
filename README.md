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
