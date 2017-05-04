# Changelog

This project follows [semantic versioning](http://semver.org).

### UNRELEASED

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
