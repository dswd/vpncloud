# Point-to-Point Tutorial

## Goals
* Connect several single nodes via a VPN
* Nodes should be able to reach each others even through NATs
* Traffic should be secured with a password
* Nodes should be accessible by IP addresses and names like `NODE.myvpn`


## Preparations
To be able to set up the VPN, at least one node needs to be reachable by an
unchanging address of hostname. This is normally not the case with common
DSL uplinks (they change addresses every day).
To mitigate this problem and get a fixed hostname, there are services called
dynamic DNS or short DDNS. There are lots of [different DDNS services][1], some
are free, some cost money.
Most of those services provide a common API that can be used by freely available
tools to update the address whenever it changes. Mainstream DSL routers have
built-in clients for this API so nothing has to be installed to set up DDNS.

Besides this unchanging address, a port has to be opened for VpnCloud. This has
to be done in the settings of the DSL router. The default port for VpnCloud
is 3210. This process is different for every router but it usually can be found
under the name of "Port forwarding" or "Exposed ports" (not "exposed host").

[1]: http://dnslookup.me/dynamic-dns/


## Setup
The actual VpnCloud setup is pretty simple.

A new network config in `/etc/vpncloud` has to be created on each node.
There is an example file to start with in `/etc/vpncloud/example.net`.

    $> sudo cp /etc/vpncloud/example.net /etc/vpncloud/mynet.net

Now that file has to edited to change a few values:

    $> sudo nano /etc/vpncloud/mynet.net

The following values have to be modified:

- **PEERS**: This is a list of all peers that this node should connect to.
  Only unchanging addresses can be used here. Several addresses can be appended
  and separated by spaces like `"node1.dyndns.org:3210 node2.dyndns.org:3210"`.
  All nodes that have an unchanging address should be listed here.

- **SHARED_KEY**: This is a shared password for all nodes that secures the
  communication. It must be the same on all nodes and of course it should be a
  strong password.

- **IFUP**: `ifconfig $IFNAME 10.0.0.X/24 mtu 1400` where `X` is different for
  every node. It is good idea to use incrementing numbers here and to track the
  assigned numbers and nodes in a list.

- **ENABLED**: This needs to be set to `1` when everything is finished so the
  network is started automatically.

After the config file has been set up correctly, VpnCloud needs to be restarted:

    $> sudo /etc/init.d/vpncloud restart

Finally, on each host the names of the nodes should by associated with their
address. This can be done by editing `/etc/hosts`:

    $> sudo nano /etc/hosts

For each node a line with `NAME.myvpn 10.0.0.X` needs to be added.


## Testing the network
When everything has been setup properly, the connection can be checked using the
`ping` command:

    $> ping NAME.myvpn
