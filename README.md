VpnCloud - Peer-to-Peer VPN
---------------------------
![Checks](https://github.com/dswd/vpncloud/workflows/Checks/badge.svg?branch=master)
![Security audit](https://github.com/dswd/vpncloud/workflows/Security%20audit/badge.svg?branch=master)

**VpnCloud** is a high performance peer-to-peer mesh VPN over UDP supporting strong encryption, NAT traversal and a simple configuration. It establishes a fully-meshed self-healing VPN network in a peer-to-peer manner with strong end-to-end encryption based on elliptic curve keys and AES-256. VpnCloud creates a virtual network interface on the host and forwards all received data via UDP to the destination. It can work on TUN devices (IP based) and TAP devices (Ethernet based).

```sh
$> vpncloud -c REMOTE_HOST:PORT -p 'mypassword' --ip 10.0.0.1/24
```

or as config file:

```yaml
crypto:
  password: mysecret
ip: 10.0.0.1
peers:
  - REMOTE_HOST:PORT
```

For more information, please see the [Website](https://vpncloud.ddswd.de) or the [Discussions group](https://github.com/dswd/vpncloud/discussions).


### Project Status
This project is still [under development](CHANGELOG.md) but has reached a
somewhat stable state. VpnCloud features the following functionality:

* Automatic peer-to-peer meshing, no central servers
* Automatic reconnecting when connections are lost
* Connecting hundreds of nodes with the VPN
* High throughput and low additional latency (see [performance page](https://vpncloud.ddswd.de/features/performance))
* Creating virtual network interfaces based on Ethernet (TAP) and IP (TUN)
* Strong end-to-end encryption using Curve25519 key pairs and AES methods
* Support for different forwarding/routing behaviors (Hub, Switch, Router)
* NAT and firewall traversal using hole punching
* Automatic port forwarding via UPnP
* Websocket proxy mode for restrictive environments
* Support for tunneled VLans (TAP devices)
* Support for publishing [beacons](https://vpncloud.ddswd.de/docs/beacons) to help nodes find each others
* Support for statsd monitoring
* Low memory footprint
* Single binary, no dependencies, no kernel module

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
* **Help with other platforms**: If you are a Rust developer with experience
  on Windows or MacOS your help on porting VpnCloud to those platforms is very
  welcome.
* **Security review**: The security has been implemented with strong security
  primitives but it would be great if a cryptography expert could verify the
  system.
* **Feedback on use cases**: Some feedback on how VpnCloud is being used and
  maybe some tutorials covering common use cases would be nice.


### Semantic Versioning
This project uses [semantic versioning](http://semver.org).
