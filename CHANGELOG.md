# Changelog

This project follows [semantic versioning](http://semver.org).

### Unreleased

- [changed] Logging more verbosely
- [fixed] Removing NULL-bytes from interface name

### v0.4 (2015-12-22)

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
- [changed] Removed lots of "unsafe" blocks
- [changed] Added benchmarks
- [changed] Two step handshake in order to fix problems with inconsistent state
- [fixed] Pretty error messages instead of panics with traces
- [fixed] Pretty addresses instead of debug representation

### v0.1.0 (2015-11-25)

- First release
