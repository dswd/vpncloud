# Planned breaking changes

Due to semantic versioning, any breaking change after 1.0 requires a new major version number.
This is a list of breaking changes to do in such a case:

[x] Add strong crypto, change network protocol
[x] Negotiate crypto method per peer
[x] Make encryption the default, no encryption must be stated explicitly
[x] Changed default device type to TUN
[x] Remove network-id parameter
[x] Remove port config option
[x] Rename subnet to claim
[x] Automatically claim addresses based on interface addresses (disable with --no-auto-claim)
[x] Set peer exchange interval to 5min
[x] Periodically send claims with peer list
[x] Allow to give --ip instead of ifup cmd
[x] Automatically set optimal MTU on interface
[x] Warning for disabled or loose rp_filter https://seclists.org/oss-sec/2019/q4/122


## TODOs

- Send keepalive messages on NAT every 10secs
- https://github.com/tokio-rs/mio
- https://docs.rs/tun/0.5.0/tun/