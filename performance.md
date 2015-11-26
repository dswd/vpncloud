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

VpnCloud version: `VpnCloud v0.2.0 (with crypto support, protocol version 1)`

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

For encrypted tests, `--shared-key test` is appended.


### Throughput

The throughput is measured with the following command:

```
$> iperf -c DST -t 60
```

The test is run in 3 steps:
* Native throughput without VpnCloud (`DST` is the native address of the receiver)
* Throughput via VpnCloud (`DST` is `10.2.1.2`)
* Encrypted throughput via VpnCloud (`DST` is `10.2.1.2`)


| Throughput test      | Bandwidth     | CPU usage (one core) |
| -------------------- | ------------- | -------------------- |
| Without VpnCloud     | 926 Mbits/sec |  -                   |
| Unencrypted VpnCloud | 873 Mbits/sec | 80% / 95%            |
| Encrypted VpnCloud   | 635 Mbits/sec | 100%                 |


### Latency

The latency is measured with the following command:
```
$> ping DST -c 10000 -i 0.001 -s SIZE -U -q
```

For all the test, the best average RTT out of 5 runs is selected. The latency is
assumed to be half of the RTT.


| Payload size         | 100 bytes | 500 bytes | 1000 bytes |
| -------------------- | --------- | --------- | ---------- |
| Without VpnCloud     | 158 µs    | 165 µs    | 178 µs     |
| Unencrypted VpnCloud | 210 µs    | 216 µs    | 237 µs     |
| Difference           | +52 µs    | +51 µs    | +59 µs     |
| Encrypted VpnCloud   | 225 µs    | 252 µs    | 262 µs     |
| Difference           | +15 µs    | +36 µs    | +25 µs     |


### Conclusion

* VpnCloud achieves over 850 MBit/s with default MTU settings.
* In encrypted mode, VpnCloud reaches over 600 MBit/s with default MTU settings.
* VpnCloud adds about 60µs to the latency.
* Encryption adds an additional latency between 10µs and 35µs depending on the packet size.
