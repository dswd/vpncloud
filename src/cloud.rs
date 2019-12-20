// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp::min,
    collections::HashMap,
    fmt,
    fs::{self, File},
    hash::BuildHasherDefault,
    io::{self, Write},
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    path::Path
};

use fnv::FnvHasher;
use rand::{prelude::*, random, thread_rng};

use super::{
    beacon::BeaconSerializer,
    config::Config,
    crypto::Crypto,
    device::Device,
    net::Socket,
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    traffic::TrafficStats,
    types::{Error, HeaderMagic, NodeId, Protocol, Range, Table},
    udpmessage::{decode, encode, Message},
    util::{resolve, CtrlC, Duration, Time, TimeSource}
};

pub type Hash = BuildHasherDefault<FnvHasher>;

const MAX_RECONNECT_INTERVAL: u16 = 3600;
const RESOLVE_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;


struct PeerData {
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    alt_addrs: Vec<SocketAddr>
}

pub struct PeerList<TS: TimeSource> {
    timeout: Duration,
    peers: HashMap<SocketAddr, PeerData, Hash>,
    nodes: HashMap<NodeId, SocketAddr, Hash>,
    addresses: HashMap<SocketAddr, NodeId, Hash>,
    _dummy_ts: PhantomData<TS>
}

impl<TS: TimeSource> PeerList<TS> {
    fn new(timeout: Duration) -> PeerList<TS> {
        PeerList {
            peers: HashMap::default(),
            timeout,
            nodes: HashMap::default(),
            addresses: HashMap::default(),
            _dummy_ts: PhantomData
        }
    }

    fn timeout(&mut self) -> Vec<SocketAddr> {
        let now = TS::now();
        let mut del: Vec<SocketAddr> = Vec::new();
        for (&addr, ref data) in &self.peers {
            if data.timeout < now {
                del.push(addr);
            }
        }
        for addr in &del {
            info!("Forgot peer: {}", addr);
            if let Some(data) = self.peers.remove(addr) {
                self.nodes.remove(&data.node_id);
                self.addresses.remove(addr);
                for addr in &data.alt_addrs {
                    self.addresses.remove(addr);
                }
            }
        }
        del
    }

    pub fn min_peer_timeout(&self) -> u16 {
        self.peers.iter().map(|p| p.1.peer_timeout).min().unwrap_or(1800)
    }

    #[inline]
    pub fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.addresses.contains_key(addr)
    }

    #[inline]
    pub fn is_connected<Addr: ToSocketAddrs + fmt::Debug>(&self, addr: Addr) -> Result<bool, Error> {
        for addr in resolve(&addr)? {
            if self.contains_addr(&addr) {
                return Ok(true)
            }
        }
        Ok(false)
    }

    #[inline]
    pub fn contains_node(&self, node_id: &NodeId) -> bool {
        self.nodes.contains_key(node_id)
    }


    #[inline]
    fn add(&mut self, node_id: NodeId, addr: SocketAddr, peer_timeout: u16) {
        if self.nodes.insert(node_id, addr).is_none() {
            info!("New peer: {}", addr);
            self.peers.insert(addr, PeerData {
                timeout: TS::now() + Time::from(self.timeout),
                node_id,
                alt_addrs: vec![],
                peer_timeout
            });
            self.addresses.insert(addr, node_id);
        }
    }

    #[inline]
    fn refresh(&mut self, addr: &SocketAddr) {
        if let Some(ref mut data) = self.peers.get_mut(addr) {
            data.timeout = TS::now() + Time::from(self.timeout);
        }
    }

    #[inline]
    fn make_primary(&mut self, node_id: NodeId, addr: SocketAddr) {
        if self.peers.contains_key(&addr) {
            return
        }
        let old_addr = match self.nodes.remove(&node_id) {
            Some(old_addr) => old_addr,
            None => return error!("Node not connected")
        };
        self.nodes.insert(node_id, addr);
        let mut peer = match self.peers.remove(&old_addr) {
            Some(peer) => peer,
            None => return error!("Main address for node is not connected")
        };
        peer.alt_addrs.retain(|i| i != &addr);
        peer.alt_addrs.push(old_addr);
        self.peers.insert(addr, peer);
        self.addresses.insert(addr, node_id);
    }

    #[inline]
    pub fn get_node_id(&self, addr: &SocketAddr) -> Option<NodeId> {
        self.addresses.get(addr).cloned()
    }

    #[inline]
    pub fn as_vec(&self) -> Vec<SocketAddr> {
        self.addresses.keys().cloned().collect()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    #[inline]
    fn subset(&self, size: usize) -> Vec<SocketAddr> {
        self.peers.keys().choose_multiple(&mut thread_rng(), size).into_iter().cloned().collect()
    }

    #[inline]
    fn remove(&mut self, addr: &SocketAddr) {
        if let Some(data) = self.peers.remove(addr) {
            info!("Removed peer: {}", addr);
            self.nodes.remove(&data.node_id);
            self.addresses.remove(addr);
            for addr in data.alt_addrs {
                self.addresses.remove(&addr);
            }
        }
    }

    #[inline]
    fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        writeln!(out, "Peers:")?;
        let now = TS::now();
        for (addr, data) in &self.peers {
            writeln!(out, " - {} (ttl: {} s)", addr, data.timeout - now)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ReconnectEntry {
    address: String,
    resolved: Vec<SocketAddr>,
    next_resolve: Time,
    tries: u16,
    timeout: u16,
    next: Time
}


pub struct GenericCloud<D: Device, P: Protocol, T: Table, S: Socket, TS: TimeSource> {
    config: Config,
    magic: HeaderMagic,
    node_id: NodeId,
    peers: PeerList<TS>,
    addresses: Vec<Range>,
    learning: bool,
    broadcast: bool,
    reconnect_peers: Vec<ReconnectEntry>,
    own_addresses: Vec<SocketAddr>,
    table: T,
    socket4: S,
    socket6: S,
    device: D,
    crypto: Crypto,
    next_peerlist: Time,
    peer_timeout_publish: u16,
    update_freq: u16,
    buffer_out: [u8; 64 * 1024],
    stats_file: Option<File>,
    next_housekeep: Time,
    next_stats_out: Time,
    next_beacon: Time,
    port_forwarding: Option<PortForwarding>,
    traffic: TrafficStats,
    beacon_serializer: BeaconSerializer<TS>,
    _dummy_p: PhantomData<P>,
    _dummy_ts: PhantomData<TS>
}

impl<D: Device, P: Protocol, T: Table, S: Socket, TS: TimeSource> GenericCloud<D, P, T, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, device: D, table: T, learning: bool, broadcast: bool, addresses: Vec<Range>, crypto: Crypto,
        port_forwarding: Option<PortForwarding>, stats_file: Option<File>
    ) -> Self
    {
        let socket4 = match S::listen_v4("0.0.0.0", config.port) {
            Ok(socket) => socket,
            Err(err) => fail!("Failed to open ipv4 address 0.0.0.0:{}: {}", config.port, err)
        };
        let socket6 = match S::listen_v6("::", config.port) {
            Ok(socket) => socket,
            Err(err) => fail!("Failed to open ipv6 address ::{}: {}", config.port, err)
        };
        let now = TS::now();
        let update_freq = if socket4.detect_nat() && config.get_keepalive() > 120 {
            info!("Private IP detected, setting keepalive interval to 120s");
            120
        } else {
            config.get_keepalive() as u16
        };
        let mut res = GenericCloud {
            magic: config.get_magic(),
            node_id: random(),
            peers: PeerList::new(config.peer_timeout),
            addresses,
            learning,
            broadcast,
            reconnect_peers: Vec::new(),
            own_addresses: Vec::new(),
            peer_timeout_publish: config.peer_timeout as u16,
            table,
            socket4,
            socket6,
            device,
            next_peerlist: now,
            update_freq,
            stats_file,
            buffer_out: [0; 64 * 1024],
            next_housekeep: now,
            next_stats_out: now + STATS_INTERVAL,
            next_beacon: now,
            port_forwarding,
            traffic: TrafficStats::default(),
            beacon_serializer: BeaconSerializer::new(&config.get_magic(), crypto.get_key()),
            crypto,
            config: config.clone(),
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData
        };
        res.initialize();
        res
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    /// Sends the message to all peers
    ///
    /// # Errors
    /// Returns an `Error::SocketError` when the underlying system call fails or only part of the
    /// message could be sent (can this even happen?).
    /// Some messages could have been sent.
    #[inline]
    fn broadcast_msg(&mut self, msg: &mut Message) -> Result<(), Error> {
        debug!("Broadcasting {:?}", msg);
        // Encrypt and encode once and send several times
        let msg_data = encode(msg, &mut self.buffer_out, self.magic, &mut self.crypto);
        for addr in self.peers.peers.keys() {
            self.traffic.count_out_traffic(*addr, msg_data.len());
            let socket = match *addr {
                SocketAddr::V4(_) => &mut self.socket4,
                SocketAddr::V6(_) => &mut self.socket6
            };
            match socket.send(msg_data, *addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => {
                    Err(Error::Socket("Sent out truncated packet", io::Error::new(io::ErrorKind::Other, "truncated")))
                }
                Err(e) => Err(Error::Socket("IOError when sending", e))
            }?
        }
        Ok(())
    }

    /// Sends a message to one peer
    ///
    /// # Errors
    /// Returns an `Error::SocketError` when the underlying system call fails or only part of the
    /// message could be sent (can this even happen?).
    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, msg: &mut Message) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        // Encrypt and encode
        let msg_data = encode(msg, &mut self.buffer_out, self.magic, &mut self.crypto);
        self.traffic.count_out_traffic(addr, msg_data.len());
        let socket = match addr {
            SocketAddr::V4(_) => &mut self.socket4,
            SocketAddr::V6(_) => &mut self.socket6
        };
        match socket.send(msg_data, addr) {
            Ok(written) if written == msg_data.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet", io::Error::new(io::ErrorKind::Other, "truncated"))),
            Err(e) => Err(Error::Socket("IOError when sending", e))
        }
    }

    /// Returns the self-perceived addresses (IPv4 and IPv6) of this node
    ///
    /// Note that those addresses could be private addresses that are not reachable by other nodes,
    /// or only some other nodes inside the same network.
    ///
    /// # Errors
    /// Returns an IOError if the underlying system call fails
    #[allow(dead_code)]
    pub fn address(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        Ok((self.socket4.address()?, self.socket6.address()?))
    }

    /// Returns the number of peers
    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Adds a peer to the reconnect list
    ///
    /// This method adds a peer to the list of nodes to reconnect to. A periodic task will try to
    /// connect to the peer if it is not already connected.
    pub fn add_reconnect_peer(&mut self, add: String) {
        let now = TS::now();
        let resolved = match resolve(&add as &str) {
            Ok(addrs) => addrs,
            Err(err) => {
                warn!("Failed to resolve {}: {:?}", add, err);
                vec![]
            }
        };
        self.reconnect_peers.push(ReconnectEntry {
            address: add,
            tries: 0,
            timeout: 1,
            resolved,
            next_resolve: now,
            next: now
        })
    }

    /// Returns whether the address is of this node
    ///
    /// # Errors
    /// Returns an `Error::SocketError` if the given address is a name that failed to resolve to
    /// actual addresses.
    fn is_own_address<Addr: ToSocketAddrs + fmt::Debug>(&self, addr: Addr) -> Result<bool, Error> {
        for addr in resolve(&addr)? {
            if self.own_addresses.contains(&addr) {
                return Ok(true)
            }
        }
        Ok(false)
    }

    /// Connects to a node given by its address
    ///
    /// This method connects to node by sending a `Message::Init` to it. If `addr` is a name that
    /// resolves to multiple addresses, one message is sent to each of them.
    /// If the node is already a connected peer or the address is blacklisted, no message is sent.
    ///
    /// # Errors
    /// This method returns `Error::NameError` if the address is a name that fails to resolve.
    pub fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        if self.peers.is_connected(addr.clone())? || self.is_own_address(addr.clone())? {
            return Ok(())
        }
        debug!("Connecting to {:?}", addr);
        let subnets = self.addresses.clone();
        let node_id = self.node_id;
        // Send a message to each resolved address
        for a in resolve(&addr)? {
            // Ignore error this time
            let mut msg = Message::Init(0, node_id, subnets.clone(), self.peer_timeout_publish);
            self.send_msg(a, &mut msg).ok();
        }
        Ok(())
    }

    /// Connects to a node given by its address
    ///
    /// This method connects to node by sending a `Message::Init` to it. If `addr` is a name that
    /// resolves to multiple addresses, one message is sent to each of them.
    /// If the node is already a connected peer or the address is blacklisted, no message is sent.
    ///
    /// # Errors
    /// This method returns `Error::NameError` if the address is a name that fails to resolve.
    fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        if self.peers.contains_addr(&addr) || self.own_addresses.contains(&addr) {
            return Ok(())
        }
        debug!("Connecting to {:?}", addr);
        let subnets = self.addresses.clone();
        let node_id = self.node_id;
        let mut msg = Message::Init(0, node_id, subnets, self.peer_timeout_publish);
        self.send_msg(addr, &mut msg)
    }

    /// Run all periodic housekeeping tasks
    ///
    /// This method executes several tasks:
    /// - Remove peers that have timed out
    /// - Remove switch table entries that have timed out
    /// - Periodically send the peers list to all peers
    /// - Periodically reconnect to peers in the reconnect list
    ///
    /// # Errors
    /// This method returns errors if sending a message fails or resolving an address fails.
    fn housekeep(&mut self) -> Result<(), Error> {
        for peer in self.peers.timeout() {
            self.table.remove_all(&peer);
        }
        self.table.housekeep();
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        // Periodically send peer list to peers
        let now = TS::now();
        if self.next_peerlist <= now {
            debug!("Send peer list to all peers");
            let mut peer_num = self.peers.len();
            // If the number of peers is high, send only a fraction of the full peer list to
            // reduce the management traffic. The number of peers to send is limited by 20.
            peer_num = min(peer_num, 20);
            // Select that many peers...
            let peers = self.peers.subset(peer_num);
            // ...and send them to all peers
            let mut msg = Message::Peers(peers);
            self.broadcast_msg(&mut msg)?;
            // Reschedule for next update
            let interval = min(self.update_freq as u16, self.peers.min_peer_timeout());
            self.next_peerlist = now + Time::from(interval);
        }
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue
            }
            self.connect(&entry.resolved as &[SocketAddr])?;
        }
        for entry in &mut self.reconnect_peers {
            // Schedule for next second if node is connected
            if self.peers.is_connected(&entry.resolved as &[SocketAddr])? {
                entry.tries = 0;
                entry.timeout = 1;
                entry.next = now + 1;
                continue
            }
            // Resolve entries anew
            if entry.next_resolve <= now {
                if let Ok(addrs) = resolve(&entry.address as &str) {
                    entry.resolved = addrs;
                }
                entry.next_resolve = now + RESOLVE_INTERVAL;
            }
            // Ignore if next attempt is already in the future
            if entry.next > now {
                continue
            }
            // Exponential backoff: every 10 tries, the interval doubles
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            // Maximum interval is one hour
            if entry.timeout > MAX_RECONNECT_INTERVAL {
                entry.timeout = MAX_RECONNECT_INTERVAL;
            }
            // Schedule next connection attempt
            entry.next = now + Time::from(entry.timeout);
        }
        if self.next_stats_out < now {
            // Write out the statistics
            self.write_out_stats().map_err(|err| Error::File("Failed to write stats file", err))?;
            self.next_stats_out = now + STATS_INTERVAL;
            self.traffic.period(Some(5));
        }
        if let Some(peers) = self.beacon_serializer.get_cmd_results() {
            debug!("Loaded beacon with peers: {:?}", peers);
            for peer in peers {
                self.connect_sock(peer)?;
            }
        }
        if self.next_beacon < now {
            self.store_beacon()?;
            self.load_beacon()?;
            self.next_beacon = now + Time::from(self.config.beacon_interval);
        }
        Ok(())
    }

    /// Stores the beacon
    fn store_beacon(&mut self) -> Result<(), Error> {
        if let Some(ref path) = self.config.beacon_store {
            let peers: Vec<_> = self.own_addresses.choose_multiple(&mut thread_rng(), 3).cloned().collect();
            if path.starts_with('|') {
                self.beacon_serializer
                    .write_to_cmd(&peers, &path[1..])
                    .map_err(|e| Error::Beacon("Failed to call beacon command", e))?;
            } else {
                self.beacon_serializer
                    .write_to_file(&peers, &path)
                    .map_err(|e| Error::Beacon("Failed to write beacon to file", e))?;
            }
        }
        Ok(())
    }

    /// Loads the beacon
    fn load_beacon(&mut self) -> Result<(), Error> {
        let peers;
        if let Some(ref path) = self.config.beacon_load {
            if path.starts_with('|') {
                self.beacon_serializer
                    .read_from_cmd(&path[1..], Some(50))
                    .map_err(|e| Error::Beacon("Failed to call beacon command", e))?;
                return Ok(())
            } else {
                peers = self
                    .beacon_serializer
                    .read_from_file(&path, Some(50))
                    .map_err(|e| Error::Beacon("Failed to read beacon from file", e))?;
            }
        } else {
            return Ok(())
        }
        debug!("Loaded beacon with peers: {:?}", peers);
        for peer in peers {
            self.connect_sock(peer)?;
        }
        Ok(())
    }

    /// Calculates, resets and writes out the statistics to a file
    fn write_out_stats(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut f) = self.stats_file {
            debug!("Writing out stats");
            f.set_len(0)?;
            self.peers.write_out(f)?;
            writeln!(f)?;
            self.table.write_out(f)?;
            writeln!(f)?;
            self.traffic.write_out(f)?;
            writeln!(f)?;
        }
        Ok(())
    }

    /// Handles payload data coming in from the local network device
    ///
    /// This method takes payload data received from the local device and parses it to obtain the
    /// destination address. Then it checks the lookup table to get the peer for that destination
    /// address. If a peer is found, the message is sent to it, otherwise the message is either
    /// broadcast to all peers or dropped (depending on mode).
    ///
    /// The parameter `payload` contains the payload data starting at position `start` and ending
    /// at `end`. It is important that the buffer has enough space before the payload data to
    /// prepend a header of max 64 bytes and enough space after the payload data to append a mac of
    /// max 64 bytes.
    ///
    /// # Errors
    /// This method fails
    /// - with `Error::ParseError` if the payload data failed to parse
    /// - with `Error::SocketError` if sending a message fails
    pub fn handle_interface_data(&mut self, payload: &mut [u8], start: usize, end: usize) -> Result<(), Error> {
        let (src, dst) = P::parse(&payload[start..end])?;
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, end - start);
        self.traffic.count_out_payload(dst, src, end - start);
        match self.table.lookup(&dst) {
            Some(addr) => {
                // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                self.send_msg(addr, &mut Message::Data(payload, start, end))?;
                if !self.peers.contains_addr(&addr) {
                    // If the peer is not actually connected, remove the entry in the table and try
                    // to reconnect.
                    warn!("Destination for {} not found in peers: {}", dst, addr);
                    self.table.remove(&dst);
                    self.connect_sock(addr)?;
                }
            }
            None => {
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    let mut msg = Message::Data(payload, start, end);
                    self.broadcast_msg(&mut msg)?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                }
            }
        }
        Ok(())
    }

    /// Handles a message received from the network
    ///
    /// This method handles messages from the network, i.e. from peers. `peer` contains the sender
    /// of the message and `msg` contains the message.
    ///
    /// Then this method will check the message type and will handle each message type differently.
    ///
    /// # `Message::Data` messages
    /// This message type contains payload data and therefore this path is optimized for speed.
    ///
    /// The payload of data messages is written to the local network device and if the node is in
    /// a learning mode it will associate the sender peer with the source address.
    ///
    /// # `Message::Peers` messages
    /// If this message is received, the local node will use all the node addresses in the message
    /// as well as the senders address to connect to.
    ///
    /// # `Message::Init` messages
    /// This message is used in the peer connection handshake.
    ///
    /// To make sure, the node does not connect to itself, it will compare the remote `node_id` to
    /// the local one. If the id is the same, it will ignore the message and blacklist the address
    /// so that it won't be used in the future.
    ///
    /// If the message is coming from a different node, the nodes address is added to the peer list
    /// and its claimed addresses are associated with it.
    ///
    /// If the `stage` of the message is 1, a `Message::Init` message with `stage=1` is sent in
    /// reply, together with a peer list.
    ///
    /// # `Message::Close` message
    /// If this message is received, the sender is removed from the peer list and its claimed
    /// addresses are removed from the table.
    pub fn handle_net_message(&mut self, peer: SocketAddr, msg: Message) -> Result<(), Error> {
        debug!("Received {:?} from {}", msg, peer);
        match msg {
            Message::Data(payload, start, end) => {
                let (src, dst) = P::parse(&payload[start..end])?;
                debug!("Writing data to device: {} bytes", end - start);
                self.traffic.count_in_payload(src, dst, end - start);
                if let Err(e) = self.device.write(&mut payload[..end], start) {
                    error!("Failed to send via device: {}", e);
                    return Err(e)
                }
                if self.learning {
                    // Learn single address
                    self.table.learn(src, None, peer);
                }
                // Not adding peer in this case to increase performance
            }
            Message::Peers(peers) => {
                // Connect to sender if not connected
                if !self.peers.contains_addr(&peer) {
                    self.connect_sock(peer)?;
                }
                if let Some(node_id) = self.peers.get_node_id(&peer) {
                    self.peers.make_primary(node_id, peer);
                }
                // Connect to all peers in the message
                for p in &peers {
                    self.connect_sock(*p)?;
                }
                // Refresh peer
                self.peers.refresh(&peer);
            }
            Message::Init(stage, node_id, ranges, peer_timeout) => {
                // Avoid connecting to self
                if node_id == self.node_id {
                    self.own_addresses.push(peer);
                    return Ok(())
                }
                // Add sender as peer or as alternative address to existing peer
                if self.peers.contains_node(&node_id) {
                    self.peers.make_primary(node_id, peer);
                } else {
                    self.peers.add(node_id, peer, peer_timeout);
                    for range in ranges {
                        self.table.learn(range.base, Some(range.prefix_len), peer);
                    }
                }
                // Reply with stage=1 if stage is 0
                if stage == 0 {
                    let own_addrs = self.addresses.clone();
                    let own_node_id = self.node_id;
                    self.send_msg(
                        peer,
                        &mut Message::Init(stage + 1, own_node_id, own_addrs, self.peer_timeout_publish)
                    )?;
                }
                // Send peers in any case
                let peers = self.peers.as_vec();
                self.send_msg(peer, &mut Message::Peers(peers))?;
            }
            Message::Close => {
                self.peers.remove(&peer);
                self.table.remove_all(&peer);
            }
        }
        Ok(())
    }

    fn initialize(&mut self) {
        match self.address() {
            Err(err) => error!("Failed to obtain local addresses: {}", err),
            Ok((v4, v6)) => {
                self.own_addresses.push(v4);
                self.own_addresses.push(v6);
            }
        }
    }

    fn handle_socket_data(&mut self, src: SocketAddr, data: &mut [u8]) {
        let size = data.len();
        if let Err(e) = decode(data, self.magic, &self.crypto).and_then(|msg| {
            self.traffic.count_in_traffic(src, size);
            self.handle_net_message(src, msg)
        }) {
            error!("Error: {}, from: {}", e, src);
        }
    }

    fn handle_socket_v4_event(&mut self, buffer: &mut [u8]) {
        let (size, src) = try_fail!(self.socket4.receive(buffer), "Failed to read from ipv4 network socket: {}");
        self.handle_socket_data(src, &mut buffer[..size])
    }

    fn handle_socket_v6_event(&mut self, buffer: &mut [u8]) {
        let (size, src) = try_fail!(self.socket6.receive(buffer), "Failed to read from ipv6 network socket: {}");
        self.handle_socket_data(src, &mut buffer[..size])
    }

    fn handle_device_event(&mut self, buffer: &mut [u8]) {
        let mut start = 64;
        let (offset, size) = try_fail!(self.device.read(&mut buffer[start..]), "Failed to read from tap device: {}");
        start += offset;
        if let Err(e) = self.handle_interface_data(buffer, start, start + size) {
            error!("Error: {}", e);
        }
    }

    /// The main method of the node
    ///
    /// This method will use epoll to wait in the sockets and the device at the same time.
    /// It will read from the sockets, decode and decrypt the message and then call the
    /// `handle_net_message` method. It will also read from the device and call
    /// `handle_interface_data` for each packet read.
    /// Also, this method will call `housekeep` every second.
    pub fn run(&mut self) {
        let ctrlc = CtrlC::new();
        let waiter =
            try_fail!(WaitImpl::new(&self.socket4, &self.socket6, &self.device, 1000), "Failed to setup poll: {}");
        let mut buffer = [0; 64 * 1024];
        let mut poll_error = false;
        for evt in waiter {
            match evt {
                WaitResult::Error(err) => {
                    if poll_error {
                        fail!("Poll wait failed again: {}", err);
                    }
                    error!("Poll wait failed: {}, retrying...", err);
                    poll_error = true;
                }
                WaitResult::Timeout => {}
                WaitResult::SocketV4 => self.handle_socket_v4_event(&mut buffer),
                WaitResult::SocketV6 => self.handle_socket_v6_event(&mut buffer),
                WaitResult::Device => self.handle_device_event(&mut buffer)
            }
            if self.next_housekeep < TS::now() {
                poll_error = false;
                if ctrlc.was_pressed() {
                    break
                }
                if let Err(e) = self.housekeep() {
                    error!("Error: {}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
        info!("Shutting down...");
        self.broadcast_msg(&mut Message::Close).ok();
        if let Some(ref path) = self.config.beacon_store {
            let path = Path::new(path);
            if path.exists() {
                info!("Removing beacon file");
                if let Err(e) = fs::remove_file(path) {
                    error!("Failed to remove beacon file: {}", e)
                }
            }
        }
    }
}


#[cfg(test)] use super::device::MockDevice;
#[cfg(test)] use super::net::MockSocket;
#[cfg(test)] use super::util::MockTimeSource;

#[cfg(test)]
impl<P: Protocol, T: Table> GenericCloud<MockDevice, P, T, MockSocket, MockTimeSource> {
    pub fn socket4(&mut self) -> &mut MockSocket {
        &mut self.socket4
    }

    pub fn socket6(&mut self) -> &mut MockSocket {
        &mut self.socket6
    }

    pub fn device(&mut self) -> &mut MockDevice {
        &mut self.device
    }

    pub fn trigger_socket_v4_event(&mut self) {
        let mut buffer = [0; 64 * 1024];
        self.handle_socket_v4_event(&mut buffer);
    }

    pub fn trigger_socket_v6_event(&mut self) {
        let mut buffer = [0; 64 * 1024];
        self.handle_socket_v6_event(&mut buffer);
    }

    pub fn trigger_device_event(&mut self) {
        let mut buffer = [0; 64 * 1024];
        self.handle_device_event(&mut buffer);
    }

    pub fn trigger_housekeep(&mut self) {
        assert!(self.housekeep().is_ok())
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn peers(&self) -> &PeerList<MockTimeSource> {
        &self.peers
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.own_addresses
    }

    pub fn decode_message<'a>(&self, msg: &'a mut [u8]) -> Result<Message<'a>, Error> {
        decode(msg, self.magic, &self.crypto)
    }
}
