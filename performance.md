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

VpnCloud version: `VpnCloud v0.5.0, protocol version 1, libsodium 1.0.10 (AES256: true)`

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

For increased MTU tests `mtu 7000` is used in `--ifup`.

### Throughput

The throughput is measured with the following command:

```
$> iperf -c DST -t 30
```

The test is run in 3 steps:
* Native throughput without VpnCloud (`DST` is the native address of the receiver)
* Throughput via VpnCloud (`DST` is `10.2.1.2`)
* Encrypted throughput via VpnCloud (`DST` is `10.2.1.2`)


| Throughput test                         | Bandwidth     | CPU usage (one core) |
| --------------------------------------- | ------------- | -------------------- |
| Without VpnCloud                        | 923 Mbits/sec |  -                   |
| Unencrypted VpnCloud                    | 877 Mbits/sec | 85% / 95%            |
| Encrypted VpnCloud (ChaCha20)           | 760 Mbits/sec | 90% / 90%            |
| Encrypted VpnCloud (AES256)             | 824 Mbits/sec | 85% / 85%            |
| Unencrypted VpnCloud (MTU 7000)         | 943 Mbits/sec | 75% / 75%            |
| Encrypted VpnCloud (ChaCha20, MTU 7000) | 922 Mbits/sec | 75% / 75%            |
| Encrypted VpnCloud (AES256, MTU 7000)   | 928 Mbits/sec | 75% / 75%            |

### Latency

The latency is measured with the following command:
```
$> ping DST -c 30000 -i 0.001 -s SIZE -U -q
```

For all the test, the best average RTT out of 3 runs is selected. The latency is
assumed to be half of the RTT.


| Payload size                  | 100 bytes       | 500 bytes       | 1000 bytes      |
| ----------------------------- | --------------- | --------------- | --------------- |
| Without VpnCloud              | 159 µs          | 167 µs          | 174 µs          |
| Unencrypted VpnCloud          | 220 µs (+61 µs) | 228 µs (+61 µs) | 238 µs (+64 µs) |
| Encrypted VpnCloud (ChaCha20) | 230 µs (+10 µs) | 246 µs (+18 µs) | 263 µs (+25 µs) |
| Encrypted VpnCloud (AES256)   | 227 µs ( +7 µs) | 241 µs (+13 µs) | 258 µs (+20 µs) |


### Conclusion

* VpnCloud achieves over 850 MBit/s with default MTU settings.
* In encrypted mode, VpnCloud reaches over 800 MBit/s with default MTU settings.
* With increased MTU, VpnCloud reaches over 900 Mbit/s, encrypted and unencrypted.
* VpnCloud adds about 70µs to the latency.
* Encryption adds an additional latency up to 20µs.
