Performance Tests
-----------------

### Test setup

Sender node:
  * Intel(R) Core(TM) i5-2540M CPU @ 2.60GHz
  * 8 GiB Ram
  * Intel 82579LM Gigabit Network
  * Ubuntu 14.04 (Kernel 3.13.0-65-generic)

Receiver node:
  * Intel(R) Core(TM) i5-3450 CPU @ 3.10GHz
  * 16 GiB Ram
  * Realtek RTL8111/8168/8411 Gigabit Network
  * Ubuntu 14.04 (Kernel 3.13.0-63-generic)

VpnCloud version: `VpnCloud v0.3.1, protocol version 1, libsodium 1.0.7 (AES256: true)`

The sender runs the following command:

```
$> ./vpncloud -t tap -l SENDER:3210 -c RECEIVER:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.1/24 mtu 1400 up' &
```

and the receiver runs:

```
$> ./vpncloud -t tap -l RECEIVER:3210 -c SENDER:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.2/24 mtu 1400 up' &
$> iperf -s &
$> top
```

For encrypted tests, `--shared-key test --crypto METHOD` is appended.


### Throughput

The throughput is measured with the following command:

```
$> iperf -c DST -t 60
```

The test is run in 3 steps:
* Native throughput without VpnCloud (`DST` is the native address of the receiver)
* Throughput via VpnCloud (`DST` is `10.2.1.2`)
* Encrypted throughput via VpnCloud (`DST` is `10.2.1.2`)


| Throughput test               | Bandwidth     | CPU usage (one core) |
| ----------------------------- | ------------- | -------------------- |
| Without VpnCloud              | 920 Mbits/sec |  -                   |
| Unencrypted VpnCloud          | 883 Mbits/sec | 80% / 75%            |
| Encrypted VpnCloud (ChaCha20) | 814 Mbits/sec | 90% / 90%            |
| Encrypted VpnCloud (AES256)   | 821 Mbits/sec | 85% / 85%           |


### Latency

The latency is measured with the following command:
```
$> ping DST -c 100000 -i 0.001 -s SIZE -U -q
```

For all the test, the best average RTT out of 3 runs is selected. The latency is
assumed to be half of the RTT.


| Payload size                  | 100 bytes       | 500 bytes       | 1000 bytes      |
| ----------------------------- | --------------- | --------------- | --------------- |
| Without VpnCloud              | 156 µs          | 164 µs          | 171 µs          |
| Unencrypted VpnCloud          | 205 µs (+50 µs) | 220 µs (+61 µs) | 236 µs (+65 µs) |
| Encrypted VpnCloud (ChaCha20) | 222 µs (+17 µs) | 242 µs (+22 µs) | 258 µs (+22 µs) |
| Encrypted VpnCloud (AES256)   | 216 µs (+15 µs) | 232 µs (+12 µs) | 250 µs (+14 µs) |


### Conclusion

* VpnCloud achieves over 850 MBit/s with default MTU settings.
* In encrypted mode, VpnCloud reaches over 800 MBit/s with default MTU settings.
* VpnCloud adds about 70µs to the latency.
* Encryption adds an additional latency up to 20µs.
