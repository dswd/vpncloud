// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::io;
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::marker::PhantomData;
use std::hash::BuildHasherDefault;
use std::time::Instant;
use std::cmp::{min, max};

use fnv::FnvHasher;
use nix::sys::signal::{SIGTERM, SIGQUIT, SIGINT};
use signal::trap::Trap;
use rand::{random, sample, thread_rng};
use net2::UdpBuilder;

use super::types::{Table, Protocol, Range, Error, HeaderMagic, NodeId};
use super::device::Device;
use super::udpmessage::{encode, decode, Message};
use super::crypto::Crypto;
use super::port_forwarding::PortForwarding;
use super::util::{now, Time, Duration, resolve};
use super::poll::{self, Poll};

type Hash = BuildHasherDefault<FnvHasher>;

struct PeerList {
    timeout: Duration,
    peers: HashMap<SocketAddr, (Time, NodeId, Vec<SocketAddr>), Hash>,
    nodes: HashMap<NodeId, SocketAddr, Hash>,
    addresses: HashSet<SocketAddr, Hash>
}

impl PeerList {
    fn new(timeout: Duration) -> PeerList {
        PeerList{
            peers: HashMap::default(),
            timeout: timeout,
            nodes: HashMap::default(),
            addresses: HashSet::default()
        }
    }

    fn timeout(&mut self) -> Vec<SocketAddr> {
        let now = now();
        let mut del: Vec<SocketAddr> = Vec::new();
        for (&addr, &(timeout, _nodeid, ref _alt_addrs)) in &self.peers {
            if timeout < now {
                del.push(addr);
            }
        }
        for addr in &del {
            info!("Forgot peer: {}", addr);
            if let Some((_timeout, nodeid, alt_addrs)) = self.peers.remove(addr) {
                self.nodes.remove(&nodeid);
                self.addresses.remove(addr);
                for addr in &alt_addrs {
                    self.addresses.remove(addr);
                }
            }
        }
        del
    }

    #[inline]
    fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.addresses.contains(addr)
    }

    #[inline]
    fn is_connected<Addr: ToSocketAddrs+fmt::Display>(&self, addr: Addr) -> Result<bool, Error> {
        for addr in try!(resolve(addr)) {
            if self.contains_addr(&addr) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[inline]
    fn contains_node(&self, node_id: &NodeId) -> bool {
        self.nodes.contains_key(node_id)
    }


    #[inline]
    fn add(&mut self, node_id: NodeId, addr: SocketAddr) {
        if self.nodes.insert(node_id, addr).is_none() {
            info!("New peer: {}", addr);
            self.peers.insert(addr, (now()+self.timeout as Time, node_id, vec![]));
            self.addresses.insert(addr);
        }
    }

    #[inline]
    fn add_alt_addr(&mut self, node_id: NodeId, addr: SocketAddr) {
        if let Some(main_addr) = self.nodes.get(&node_id) {
            if let Some(&mut (_timeout, _node_id, ref mut alt_addrs)) = self.peers.get_mut(main_addr) {
                alt_addrs.push(addr);
                self.addresses.insert(addr);
            } else {
                error!("Main address for node is not connected");
            }
        } else {
            error!("Node not connected");
        }
    }

    #[inline]
    fn as_vec(&self) -> Vec<SocketAddr> {
        self.addresses.iter().cloned().collect()
    }

    #[inline]
    fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    #[inline]
    fn subset(&self, size: usize) -> Vec<SocketAddr> {
        sample(&mut thread_rng(), self.as_vec(), size)
    }

    #[inline]
    fn remove(&mut self, addr: &SocketAddr) {
        if let Some((_timeout, node_id, alt_addrs)) = self.peers.remove(addr) {
            info!("Removed peer: {}", addr);
            self.nodes.remove(&node_id);
            self.addresses.remove(addr);
            for addr in alt_addrs {
                self.addresses.remove(&addr);
            }
        }
    }
}

#[derive(Clone)]
pub struct ReconnectEntry {
    address: String,
    tries: u16,
    timeout: u16,
    next: Time
}

pub struct GenericCloud<P: Protocol> {
    magic: HeaderMagic,
    node_id: NodeId,
    peers: PeerList,
    addresses: Vec<Range>,
    learning: bool,
    broadcast: bool,
    reconnect_peers: Vec<ReconnectEntry>,
    blacklist_peers: Vec<SocketAddr>,
    table: Box<Table>,
    socket4: UdpSocket,
    socket6: UdpSocket,
    device: Device,
    crypto: Crypto,
    next_peerlist: Time,
    update_freq: Duration,
    buffer_out: [u8; 64*1024],
    next_housekeep: Time,
    port_forwarding: Option<PortForwarding>,
    _dummy_p: PhantomData<P>,
}

impl<P: Protocol> GenericCloud<P> {
    #[allow(unknown_lints)]
    #[allow(too_many_arguments)]
    pub fn new(magic: HeaderMagic, device: Device, listen: u16, table: Box<Table>,
        peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>,
        crypto: Crypto, port_forwarding: Option<PortForwarding>) -> Self {
        let socket4 = match UdpBuilder::new_v4().expect("Failed to obtain ipv4 socket builder")
            .reuse_address(true).expect("Failed to set so_reuseaddr").bind(("0.0.0.0", listen)) {
            Ok(socket) => socket,
            Err(err) => fail!("Failed to open ipv4 address 0.0.0.0:{}: {}", listen, err)
        };
        let socket6 = match UdpBuilder::new_v6().expect("Failed to obtain ipv6 socket builder")
            .only_v6(true).expect("Failed to set only_v6")
            .reuse_address(true).expect("Failed to set so_reuseaddr").bind(("::", listen)) {
            Ok(socket) => socket,
            Err(err) => fail!("Failed to open ipv6 address ::{}: {}", listen, err)
        };
        GenericCloud{
            magic: magic,
            node_id: random(),
            peers: PeerList::new(peer_timeout),
            addresses: addresses,
            learning: learning,
            broadcast: broadcast,
            reconnect_peers: Vec::new(),
            blacklist_peers: Vec::new(),
            table: table,
            socket4: socket4,
            socket6: socket6,
            device: device,
            crypto: crypto,
            next_peerlist: now(),
            update_freq: peer_timeout/2-60,
            buffer_out: [0; 64*1024],
            next_housekeep: now(),
            port_forwarding: port_forwarding,
            _dummy_p: PhantomData,
        }
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
        for addr in self.peers.as_vec() {
            let socket = match addr {
                SocketAddr::V4(_) => &self.socket4,
                SocketAddr::V6(_) => &self.socket6
            };
            try!(match socket.send_to(msg_data, addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet", io::Error::new(io::ErrorKind::Other, "truncated"))),
                Err(e) => Err(Error::Socket("IOError when sending", e))
            })
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
        let socket = match addr {
            SocketAddr::V4(_) => &self.socket4,
            SocketAddr::V6(_) => &self.socket6
        };
        match socket.send_to(msg_data, addr) {
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
        Ok((try!(self.socket4.local_addr()), try!(self.socket6.local_addr())))
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
        self.reconnect_peers.push(ReconnectEntry {
            address: add,
            tries: 0,
            timeout: 1,
            next: now()
        })
    }

    /// Returns whether the address  is blacklisted
    ///
    /// # Errors
    /// Returns an `Error::SocketError` if the given address is a name that failed to resolve to
    /// actual addresses.
    fn is_blacklisted<Addr: ToSocketAddrs+fmt::Display>(&self, addr: Addr) -> Result<bool, Error> {
        for addr in try!(resolve(addr)) {
            if self.blacklist_peers.contains(&addr) {
                return Ok(true);
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
    pub fn connect<Addr: ToSocketAddrs+fmt::Display+Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        if try!(self.peers.is_connected(addr.clone())) || try!(self.is_blacklisted(addr.clone())) {
            return Ok(())
        }
        debug!("Connecting to {}", addr);
        let subnets = self.addresses.clone();
        let node_id = self.node_id;
        // Send a message to each resolved address
        for a in try!(resolve(addr)) {
            // Ignore error this time
            let mut msg = Message::Init(0, node_id, subnets.clone());
            self.send_msg(a, &mut msg).ok();
        }
        Ok(())
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
        let now = now();
        if self.next_peerlist <= now {
            debug!("Send peer list to all peers");
            let mut peer_num = self.peers.len();
            // If the number of peers is high, send only a fraction of the full peer list to
            // reduce the management traffic. The number of peers to send is the square root of the
            // total number of peers.
            if peer_num > 10 {
                peer_num = max(10, min(255, (peer_num as f32).sqrt().ceil() as usize));
            }
            // Select that many peers...
            let peers = self.peers.subset(peer_num);
            // ...and send them to all peers
            let mut msg = Message::Peers(peers);
            try!(self.broadcast_msg(&mut msg));
            // Reschedule for next update
            self.next_peerlist = now + self.update_freq as Time;
        }
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue
            }
            try!(self.connect(&entry.address as &str));
        }
        for entry in &mut self.reconnect_peers {
            // Schedule for next second if node is connected
            if try!(self.peers.is_connected(&entry.address as &str)) {
                entry.tries = 0;
                entry.timeout = 1;
                entry.next = now + 1;
                continue
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
            if entry.timeout > 3600 {
                entry.timeout = 3600;
            }
            // Schedule next connection attempt
            entry.next = now + entry.timeout as Time;
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
        let (src, dst) = try!(P::parse(&payload[start..end]));
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, end-start);
        match self.table.lookup(&dst) {
            Some(addr) => { // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                try!(self.send_msg(addr, &mut Message::Data(payload, start, end)));
                if !self.peers.contains_addr(&addr) {
                    // If the peer is not actually conected, remove the entry in the table and try
                    // to reconnect.
                    warn!("Destination for {} not found in peers: {}", dst, addr);
                    self.table.remove(&dst);
                    try!(self.connect(&addr));
                }
            },
            None => {
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    let mut msg = Message::Data(payload, start, end);
                    try!(self.broadcast_msg(&mut msg));
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
                let (src, _dst) = try!(P::parse(&payload[start..end]));
                debug!("Writing data to device: {} bytes", end-start);
                if let Err(e) = self.device.write(&mut payload[..end], start) {
                    error!("Failed to send via device: {}", e);
                    return Err(e);
                }
                if self.learning {
                    // Learn single address
                    self.table.learn(src, None, peer);
                }
                // Not adding peer in this case to increase performance
            },
            Message::Peers(peers) => {
                // Connect to sender if not connected
                if !self.peers.contains_addr(&peer) {
                    try!(self.connect(&peer));
                }
                // Connect to all peers in the message
                for p in &peers {
                    if ! self.peers.contains_addr(p) && ! self.blacklist_peers.contains(p) {
                        try!(self.connect(p));
                    }
                }
            },
            Message::Init(stage, node_id, ranges) => {
                // Avoid connecting to self
                if node_id == self.node_id {
                    self.blacklist_peers.push(peer);
                    return Ok(())
                }
                // Add sender as peer or as alternative address to existing peer
                if self.peers.contains_node(&node_id) {
                    self.peers.add_alt_addr(node_id, peer);
                } else {
                    self.peers.add(node_id, peer);
                    for range in ranges {
                        self.table.learn(range.base, Some(range.prefix_len), peer);
                    }
                }
                // Reply with stage=1 if stage is 0
                if stage == 0 {
                    let peers = self.peers.as_vec();
                    let own_addrs = self.addresses.clone();
                    let own_node_id = self.node_id;
                    try!(self.send_msg(peer, &mut Message::Init(stage+1, own_node_id, own_addrs)));
                    try!(self.send_msg(peer, &mut Message::Peers(peers)));
                }
            },
            Message::Close => {
                self.peers.remove(&peer);
                self.table.remove_all(&peer);
            }
        }
        Ok(())
    }

    /// The main method of the node
    ///
    /// This method will use epoll to wait in the sockets and the device at the same time.
    /// It will read from the sockets, decode and decrypt the message and then call the
    /// `handle_net_message` method. It will also read from the device and call
    /// `handle_interface_data` for each packet read.
    /// Also, this method will call `housekeep` every second.
    #[allow(unknown_lints)]
    #[allow(cyclomatic_complexity)]
    pub fn run(&mut self) {
        let dummy_time = Instant::now();
        let trap = Trap::trap(&[SIGINT, SIGTERM, SIGQUIT]);
        let mut poll_handle = try_fail!(Poll::new(3), "Failed to create poll handle: {}");
        let socket4_fd = self.socket4.as_raw_fd();
        let socket6_fd = self.socket6.as_raw_fd();
        let device_fd = self.device.as_raw_fd();
        try_fail!(poll_handle.register(socket4_fd, poll::READ), "Failed to add ipv4 socket to poll handle: {}");
        try_fail!(poll_handle.register(socket6_fd, poll::READ), "Failed to add ipv4 socket to poll handle: {}");
        try_fail!(poll_handle.register(device_fd, poll::READ), "Failed to add ipv4 socket to poll handle: {}");
        let mut buffer = [0; 64*1024];
        let mut poll_error = false;
        loop {
            let evts = match poll_handle.wait(1000) {
                Ok(evts) => evts,
                Err(err) => {
                    if poll_error {
                        fail!("Poll wait failed again: {}", err);
                    }
                    error!("Poll wait failed: {}, retrying...", err);
                    poll_error = true;
                    continue
                }
            };
            for evt in evts {
                match evt.fd() {
                    fd if (fd == socket4_fd || fd == socket6_fd) => {
                        let (size, src) = match evt.fd() {
                            fd if fd == socket4_fd => try_fail!(self.socket4.recv_from(&mut buffer), "Failed to read from ipv4 network socket: {}"),
                            fd if fd == socket6_fd => try_fail!(self.socket6.recv_from(&mut buffer), "Failed to read from ipv6 network socket: {}"),
                            _ => unreachable!()
                        };
                        if let Err(e) = decode(&mut buffer[..size], self.magic, &mut self.crypto).and_then(|msg| self.handle_net_message(src, msg)) {
                            error!("Error: {}, from: {}", e, src);
                        }
                    },
                    fd if (fd == device_fd) => {
                        let mut start = 64;
                        let (offset, size) = try_fail!(self.device.read(&mut buffer[start..]), "Failed to read from tap device: {}");
                        start += offset;
                        if let Err(e) = self.handle_interface_data(&mut buffer, start, start+size) {
                            error!("Error: {}", e);
                        }
                    },
                    _ => unreachable!()
                }
            }
            if self.next_housekeep < now() {
                poll_error = false;
                // Check for signals
                if trap.wait(dummy_time).is_some() {
                    break;
                }
                // Do the housekeeping
                if let Err(e) = self.housekeep() {
                    error!("Error: {}", e)
                }
                self.next_housekeep = now() + 1
            }
        }
        info!("Shutting down...");
        self.broadcast_msg(&mut Message::Close).ok();
    }
}
