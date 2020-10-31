VpnCloud - Peer-to-Peer VPN
---------------------------
![Checks](https://github.com/dswd/vpncloud/workflows/Checks/badge.svg?branch=master)
![Security audit](https://github.com/dswd/vpncloud/workflows/Security%20audit/badge.svg?branch=master)

**VpnCloud** is a simple VPN over UDP. It creates a virtual network interface on
the host and forwards all received data via UDP to the destination. VpnCloud
establishes an encrypted fully-meshed VPN network in a peer-to-peer manner. 
It can work on TUN devices (IP based) and TAP devices (Ethernet based). 
Tunneling traffic between two nodes can be as easy as:

       $> vpncloud -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24

or as config file:

       crypto:
         password: mysecret
       ip: 10.0.0.1
       peers:
         - REMOTE_HOST:PORT

For more information, please see the [Website](https://vpncloud.ddswd.de) or the [Forum](https://groups.google.com/forum/#!forum/vpncloud).


### Project Status
This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. VpnCloud features the following functionality:

* Setting up tunnels between two networks via Ethernet (TAP) and IP (TUN)
* Connecting multiple networks with multiple forwarding behaviors (Hub, Switch,
  Router)
* Strong encryption using Curve25519 key pairs and AES methods
* Automatic peer-to-peer meshing, no central servers
* NAT and (limited) firewall traversal using hole punching
* Automatic reconnecting when connections are lost
* Non-native forwarding modes, e.g. IP based learning switch and prefix routed
  Ethernet networks.
* High throughput and low additional latency (see [performance page](https://vpncloud.ddswd.de/features/performance))
* Support for tunneled VLans (TAP device)
* Automatic port forwarding via UPnP
* Support for publishing [beacons](https://vpncloud.ddswd.de/docs/beacons) to help nodes find each others
* Support for statsd monitoring


### Installing

#### Compiling from source
Prerequisites: Git, [Cargo](https://www.rust-lang.org/install.html), asciidoctor

The checked-out code can be compiled with ``cargo build`` or ``cargo build --release`` (release version). The binary could then be found in `target/release/vpncloud`.

The tests can be run via ``cargo test``.


#### Cross-Compiling & packaging
Please see the [builder folder](builder).


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
This project uses [semantic versioning](http://semver.org).
