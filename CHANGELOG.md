# Changelog

This project follows [semantic versioning](http://semver.org).

### v2.3.0 (2021-12-23)

- [added] Added build for armv5te (thanks to xek)
- [added] Option to specify advertised addresses
- [added] Peers now learn their own address from peers
- [changed] Changed Rust version to 1.57.0
- [changed] Updated dependencies
- [fixed] Fixed problem with IPv4 addresses in listen option
- [fixed] Fixed periodic broadcast messages in switch mode

### v2.2.0 (2021-04-06)

- [added] Service target file (thanks to mnhauke)
- [added] Added interactive configuration wizard
- [added] Support for (un-)installation
- [added] Building static binaries
- [added] Building i686 rpm
- [changed] Restructured example config
- [changed] Changed Rust version to 1.51.0
- [changed] Updated dependencies
- [changed] Change permissions of /etc/vpncloud

### v2.1.0 (2021-02-06)

- [added] Support for websocket proxy mode
- [added] Support for hook scripts to handle certain situations
- [added] Support for creating shell completions
- [removed] Removed dummy device type
- [changed] Updated dependencies
- [changed] Changed Rust version to 1.49.0
- [fixed] Added missing peer address propagation
- [fixed] Fixed problem with peer addresses without port

### v2.0.1 (2020-11-07)

- [changed] Changed documentation
- [changed] Updated dependencies
- [changed] Retrying connections for 120 secs
- [changed] Resetting own addresses periodically
- [changed] Using smallvec everywhere
- [changed] Assume default port for peers without port
- [fixed] Fixed corner case with lost init message
- [fixed] Do not reconnect to timed out pending connections
- [fixed] Most specific claims beat less specific claims
- [fixed] Count all invalid protocol traffic
- [fixed] Fixed compile with musl
- [fixed] Fixed time format in logs

### v2.0.0 (2020-10-30)

- [added] **Add strong crypto, complete rewrite of crypto system**
- [added] Automatically claim addresses based on interface addresses (disable with --no-auto-claim)
- [added] Allow to give --ip instead of ifup cmd
- [added] Automatically set optimal MTU on interface
- [added] Warning for disabled or loose rp_filter setting
- [added] Add --fix-rp-filter to fix rp filter settings
- [added] Offer to migrate old configs
- [changed] **Complete change of network protocol**
- [changed] Negotiate crypto method per peer, select best method
- [changed] Make encryption the default, no encryption must be stated explicitly
- [changed] Changed default device type to TUN
- [changed] Rename subnet to claim
- [changed] Set peer exchange interval to 5 minutes
- [changed] Periodically send claims with peer list
- [changed] Changed Rust version to 1.47.0
- [removed] Remove network-id parameter
- [removed] Remove port config option in favor of --listen

### UNRELEASED v1.x.y

- [added] Added crypto option AES128
- [added] Default port for peers
- [changed] Updated dependencies
- [changed] Removed C code, now 100% Rust
- [fixed] Fixed keepalive for small timeouts
- [fixed] Fixed problem with port forwarding
- [fixed] Fixed problem with TUN on dynamic host addresses

### v1.4.0 (2020-06-03)

- [added] Added option to listen on specified IP
- [added] Added support for statsd monitoring
- [changed] No longer using two sockets for ipv4 and ipv6
- [changed] Warning for missing router is now info
- [changed] New warning on claimed addresses in learning mode
- [changed] Rewrote argument parsing
- [changed] Changed stats file format to YAML
- [changed] Using asciidoc for manpage
- [changed] Updated dependencies
- [fixed] Fixed problem that could lead to 100% cpu consumption
- [fixed] Fixed startup race condition

### v1.3.0 (2020-01-25)

- [added] Building for aarch64 aka arm64 (thanks to Ivan)
- [added] Added feature to disable special NAT support
- [changed] Improved port forwarding on quirky routers
- [changed] Reduced peer timeout to 5min to work better with NAT
- [changed] Improved builder scripts
- [changed] Updated dependencies
- [fixed] Fixed problem with growing stats file

### v1.2.1 (2019-12-22)

- [fixed] Fixed a problem with service restrictions

### v1.2.0 (2019-12-20)

- [added] Added service restrictions to systemd
- [changed] Rust version 1.40.0
- [changed] Also drop privileges in foreground mode
- [changed] Set builders to Ubuntu 16.04 and CentOS 7
- [changed] Set keepalive to 120 secs when NAT is detected
- [changed] Deleting beacon file at shutdown
- [changed] Updated dependencies
- [fixed] Added parameter keepalive to manpage
- [fixed] Fixed problems on stats file when dropping permissions
- [fixed] Deleting files before overwriting them
- [fixed] Fixed duplicate port bindings

### v1.1.0 (2019-12-04)

- [added] Exchange peer timeout and adapt keepalive accordingly
- [added] Reducing published peer timeout to 5 min when NAT is detected
- [added] Added more tests
- [changed] Rust version 1.39.0
- [changed] Updated dependencies
- [fixed] Fixed potential startup dependency issue
- [fixed] Fixed wrong base62 encoding

### v1.0.0 (2019-03-21)

- [added] Added ability to publish small beacons for rendezvous
- [added] Added build chain for packages
- [added] Added more tests
- [changed] Allow to build binary without manpage
- [changed] Rust edition 2018
- [changed] Rust version 1.33.0
- [changed] Updated dependencies
- [fixed] Fixed bug that could cause repeated initialization messages

### v0.9.1 (2019-02-16)

- [fixed] Fixed bug in new hex secret key functionality

### v0.9.0 (2019-02-15)

- [added] Added support for cross-compilation
- [added] Added keepalive option for nodes behind NAT
- [added] Added ability to write out statistics file with peers and traffic info
- [added] Added dummy device type that does not allocate an interface
- [added] Added ability to change /dev/tun path
- [changed] Using ring instead of libsodium
- [changed] Using PBKDF2 for shared keys (**incompatible**)
- [changed] Updated dependencies
- [fixed] Hashed magics now also consider first character (**incompatible**)

### v0.8.2 (2019-01-02)

- [changed] Using serde instead of rustc_serialize
- [changed] Updated libsodium to 1.0.16
- [changed] Updated dependencies
- [changed] Making clippy happy
- [fixed] Fixed wrong address

### v0.8.1 (2017-05-09)

- [added] Added more tests
- [changed] Updated dependencies
- [changed] Updated libsodium to 1.0.12
- [changed] Small fixes to make clippy happy
- [changed] Removed a layer of indirection from inner loop
- [fixed] Fixed two problems with routing table

### v0.8.0 (2016-11-25)

- [added] Support for automatic port forwarding via UPnP
- [added] Added `-s` shorthand for `--subnet`
- [added] Support for YAML config file via `--config`
- [added] Support for running in the background
- [added] Support for dropping permissions
- [added] Support for writing a pid file
- [added] Support for writing logs to logfile
- [changed] Not overriding recently learnt addresses in switch mode
- [changed] Caching resolved addresses to increase performance
- [changed] Configurable magic header is now used instead of Network-ID (**incompatible**)
- [changed] Clarified documentation on TUN netmasks
- [changed] Added timestamps to output
- [changed] Using new YAML config instead of old config files (**incompatible**)
- [changed] Prefer IPv4 over IPv6 when possible
- [changed] Updated dependencies
- [fixed] Fixed documentation of listen parameter
- [fixed] Fixed problem with multiple subnets
- [fixed] Fixed problem with interrupted poll after suspend to ram
- [fixed] Forgot to extend peer timeout on peer exchange
- [fixed] No longer broadcasting to additional addresses

### v0.7.0 (2016-08-05)

- [added] Added more tests
- [added] Added pluggable polling system
- [added] Added documentation
- [changed] Code cleanup
- [changed] Updated dependencies
- [changed] Turned some clippy warnings off
- [changed] Cross-compiling for ARM
- [changed] Updated libsodium to 1.0.11
- [removed] Removed Address remove code for prefix table
- [fixed] Reconnecting to lost peers when receiving from them or sending to them
- [fixed] Sending peer list more often to prevent timeouts
- [fixed] Removing learnt addresses of lost peers
- [fixed] Fixed possible crash in message decoding

### v0.6.0 (2016-06-02)

- [added] Exponential backoff for reconnect timeouts
- [added] Systemd compatible startup scripts
- [changed] Repeatedly resolving connect addresses to allow DynDNS
- [changed] Listening on IPv4 and IPv6
- [changed] Using SO_REUSEADDR to allow frequent rebinding
- [changed] Building and using local libsodium library automatically
- [changed] Updated dependencies

### v0.5.0 (2016-04-05)

- [added] Added license and copyright information
- [added] Added documentation for daemon config files
- [added] Script for performance measurements
- [added] Added more tests and benchmarks
- [changed] Daemon now detects network config files on its own
- [changed] Using display format for addresses
- [changed] Updated dependencies
- [changed] New measurements
- [changed] Only calling crypto_init once
- [changed] Passing listen address as &str
- [changed] Using FNV hash for better performance
- [changed] Using slice operations instead of loops
- [changed] Updated libsodium to 1.0.10
- [changed] Renamed default.net to example.net
- [fixed] Fixed wrong hex address formatting
- [fixed] Fixed peer exchange for more than 65000 peers
- [fixed] Initializing crypto for benchmarks
- [fixed] Removing learned addresses of lost peers

### v0.4.3 (2016-02-02)

- [changed] Updated libsodium to 1.0.8
- [fixed] Fixed problem with nodes broadcasting to themselves

### v0.4.2 (2016-01-19)

- [changed] Updated dependencies
- [changed] New measurements
- [changed] Using copy trait more often
- [fixed] Fixed deb changelog

### v0.4.1 (2015-12-22)

- [changed] Logging more verbosely
- [fixed] Removing NULL-bytes from interface name
- [fixed] Supporting hostnames as peers
- [fixed] No longer encrypting multiple times
- [fixed] Properly decoding protocol header when sending
- [fixed] Corrected size of read data

### v0.4.0 (2015-12-22)

- [added] Init script
- [changed] Removed last payload memcopy
- [changed] Using RNG to select peers for peers list exchange
- [changed] Updated dependency versions
- [changed] Updated documentation
- [fixed] Printing errors instead of panics in some cases
- [fixed] Build script for Debian packages

### v0.3.1 (2015-12-03)

- [added] Unique node ids to avoid connecting to self (**incompatible**)
- [fixed] Calling sync when writing to TUN/TAP device

### v0.3.0 (2015-12-02)

- [added] Support for AES256GCM encryption
- [added] Including current libsodium in builds
- [added] --crypto parameter to select encryption method
- [changed] Increased ChaCha20Poly1305 nonce from 8 to 12 bytes (**incompatible**)
- [changed] Updated dependency versions
- [changed] More tests
- [changed] Removed more "unsafe" blocks
- [fixed] Forgot to call `sodium_init`, huge performance increase

### v0.2.0 (2015-11-26)

- [added] Sending close message at the end
- [added] Support for IPv6 addresses
- [added] Support for ChaCha20Poly1305 encryption
- [removed] Support for ChaCha20HmacSha512256 encryption
- [changed] Complete rewrite of encryption code (**incompatible**)
- [changed] Removed unused code
- [changed] Some speed improvements
- [changed] Removed lots of "unsafe" blocks (**fixes security issue**)
- [changed] Added benchmarks
- [changed] Two step handshake in order to fix problems with inconsistent state
- [fixed] Pretty error messages instead of panics with traces
- [fixed] Pretty addresses instead of debug representation

### v0.1.0 (2015-11-25)

- First release
