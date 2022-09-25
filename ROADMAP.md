# Roadmap

## Multithreading functionality

- [x] Timeout for device read
- [x] Timeout for net read
- [x] Check how async affects performance
- [x] Sync traffic stats
- [x] Sync forwarding table
- [x] Fix WS Proxy code
- [x] Fix Ctrl-C
- [x] Fix auto-claim IP

## More threads

- [ ] abstract socket + peers + traffic + table into one class + shared part
- [ ] management thread
- [ ] Send peer list
- [ ] Statsd
- [ ] Write out stats
- [ ] Port forwarding

## VIA Feature

- [ ] Implement message type VIA for relaying messages
- [ ] Advertize VIA addresses (optional) as claims from own peers
- [ ] Use VIA if no peer found
- [ ] Make sure VIA does not recurse
- [ ] Allow enabling VIA in config

## REST API