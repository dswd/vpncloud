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

VpnCloud version: `VpnCloud v0.1.0 (with crypto support, protocol version 1)`


### Test 1: Unencrypted throughput

Node 1:
```
$> ./vpncloud -t tap -l NODE1:3210 -c NODE2:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.1/24 mtu MTU up' &
```

Node 2:
```
$> ./vpncloud -t tap -l NODE2:3210 -c NODE1:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.2/24 mtu MTU up' &
$> iperf -s &
$> top
```

First, the test is run **without VpnCloud**:
```
$> iperf -c NODE2 -t 60
```

and then **via VpnCloud**:
```
$> iperf -c 10.2.1.2 -t 60
```

**Results:**
  * Throughput without VpnCloud: 926 Mbits/sec
  * Throughput via VpnCloud (MTU=1400): 885 Mbits/sec
  * CPU usage for VpnCloud (MTU=1400): ~85%/ ~95% of one core (sender, receiver)
  * Throughput via VpnCloud (MTU=16384): 947 Mbits/sec
  * CPU usage for VpnCloud (MTU=16384): ~40%/ ~45% of one core (sender, receiver)


### Test 2: Unencrypted ping

Node 1:
```
$> ./vpncloud -t tap -l NODE1:3210 -c NODE2:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.1/24 mtu 1400 up' &
```

Node 2:
```
$> ./vpncloud -t tap -l NODE2:3210 -c NODE1:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.2/24 mtu 1400 up' &
```

Each test is first run without VpnCloud:
```
$> ping NODE2 -c 10000 -i 0.001 -s SIZE -U -q
```

and then with VpnCloud:
```
$> ping 10.2.1.2 -c 10000 -i 0.001 -s SIZE -U -q
```

For all the test, the best result out of 5 is selected.

SIZE: 50 bytes
  * Without VpnCloud: Ø= 164 µs
  * With VpnCloud: Ø= 433 µs

SIZE: 500 bytes
  * Without VpnCloud: Ø= 330 µs
  * With VpnCloud: Ø= 446 µs

SIZE: 1000 bytes
  * Without VpnCloud: Ø= 356 µs
  * With VpnCloud: Ø= 473 µs


### Test 3: Encrypted throughput

Node 1:
```
$> ./vpncloud -t tap -l NODE1:3210 -c NODE2:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.1/24 mtu MTU up' --shared-key test &
```

Node 2:
```
$> ./vpncloud -t tap -l NODE2:3210 -c NODE1:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.2/24 mtu MTU up' --shared-key test &
$> iperf -s &
$> top
```

First, the test is run **without VpnCloud**:
```
$> iperf -c NODE2 -t 60
```

and then **via VpnCloud**:
```
$> iperf -c 10.2.1.2 -t 60
```

**Results:**
  * Throughput without VpnCloud: 926 Mbits/sec
  * Throughput via VpnCloud (MTU=1400): 633 Mbits/sec
  * CPU usage for VpnCloud (MTU=1400): 100% of one core on both sides
  * Throughput via VpnCloud (MTU=16384): 918 Mbits/sec
  * CPU usage for VpnCloud (MTU=16384): ~90% of one core on both sides


### Test 4: Encrypted ping

Node 1:
```
$> ./vpncloud -t tap -l NODE1:3210 -c NODE2:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.1/24 mtu 1400 up' --shared-key test &
```

Node 2:
```
$> ./vpncloud -t tap -l NODE2:3210 -c NODE1:3210 \
   --ifup 'ifconfig $IFNAME 10.2.1.2/24 mtu 1400 up' --shared-key test &
```

Each test is first run without VpnCloud:
```
$> ping NODE2 -c 10000 -i 0.001 -s SIZE -U -q
```

and then with VpnCloud:
```
$> ping 10.2.1.2 -c 10000 -i 0.001 -s SIZE -U -q
```

For all the test, the best result out of 5 is selected.

SIZE: 50 bytes
  * Without VpnCloud: Ø= 164 µs
  * With VpnCloud: Ø= 456 µs

SIZE: 500 bytes
  * Without VpnCloud: Ø= 330 µs
  * With VpnCloud: Ø= 492 µs

SIZE: 1000 bytes
  * Without VpnCloud: Ø= 356 µs
  * With VpnCloud: Ø= 543 µs


### Conclusion

* VpnCloud achieves about 885 MBit/s with default MTU settings.
* In encrypted mode, VpnCloud reaches aboud 663 MBit/s with default MTU settings.
* At increased MTU, VpnCloud is able to saturate a Gigabit link even when encrypting.
* VpnCloud adds about 120µs to the round trip times, i.e. 60µs latency increase.
* Encryption adds an additional latency between 10µs and 35µs depending on the packet size.
