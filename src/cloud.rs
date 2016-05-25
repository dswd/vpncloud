// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::io::Result as IoResult;
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::marker::PhantomData;
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;
use epoll;
use nix::sys::signal::{SIGTERM, SIGQUIT, SIGINT};
use signal::trap::Trap;
use time::SteadyTime;
use rand::{random, sample, thread_rng};
use net2::UdpBuilder;

use super::types::{Table, Protocol, Range, Error, NetworkId, NodeId};
use super::device::Device;
use super::udpmessage::{encode, decode, Options, Message};
use super::crypto::Crypto;
use super::util::{now, Time, Duration};

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
            debug!("Forgot peer: {}", addr);
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

    #[inline(always)]
    fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.addresses.contains(addr)
    }

    #[inline]
    fn is_connected<Addr: ToSocketAddrs+fmt::Display>(&self, addr: Addr) -> Result<bool, Error> {
        let mut addrs = try!(addr.to_socket_addrs().map_err(|_| Error::SocketError("Error looking up name")));
        while let Some(a) = addrs.next() {
            if self.contains_addr(&a) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[inline(always)]
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
        self.addresses.iter().map(|addr| *addr).collect()
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    fn subset(&self, size: usize) -> Vec<SocketAddr> {
        sample(&mut thread_rng(), self.as_vec(), size)
    }

    #[inline]
    fn remove(&mut self, addr: &SocketAddr) {
        if let Some((_timeout, node_id, alt_addrs)) = self.peers.remove(&addr) {
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
    options: Options,
    crypto: Crypto,
    next_peerlist: Time,
    update_freq: Duration,
    buffer_out: [u8; 64*1024],
    next_housekeep: Time,
    _dummy_p: PhantomData<P>,
}

impl<P: Protocol> GenericCloud<P> {
    pub fn new(device: Device, listen: u16, network_id: Option<NetworkId>, table: Box<Table>,
        peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>,
        crypto: Crypto) -> Self {
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
        let mut options = Options::default();
        options.network_id = network_id;
        GenericCloud{
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
            options: options,
            crypto: crypto,
            next_peerlist: now(),
            update_freq: peer_timeout/2,
            buffer_out: [0; 64*1024],
            next_housekeep: now(),
            _dummy_p: PhantomData,
        }
    }

    #[inline]
    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    #[inline]
    fn broadcast_msg(&mut self, msg: &mut Message) -> Result<(), Error> {
        debug!("Broadcasting {:?}", msg);
        let msg_data = encode(&mut self.options, msg, &mut self.buffer_out, &mut self.crypto);
        for addr in &self.peers.as_vec() {
            let socket = match addr {
                &SocketAddr::V4(_) => &self.socket4,
                &SocketAddr::V6(_) => &self.socket6
            };
            try!(match socket.send_to(msg_data, addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
                Err(e) => {
                    error!("Failed to send via network {:?}", e);
                    Err(Error::SocketError("IOError when sending"))
                }
            })
        }
        Ok(())
    }

    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, msg: &mut Message) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let msg_data = encode(&mut self.options, msg, &mut self.buffer_out, &mut self.crypto);
        let socket = match &addr {
            &SocketAddr::V4(_) => &self.socket4,
            &SocketAddr::V6(_) => &self.socket6
        };
        match socket.send_to(msg_data, addr) {
            Ok(written) if written == msg_data.len() => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    #[allow(dead_code)]
    pub fn address(&self) -> IoResult<(SocketAddr, SocketAddr)> {
        Ok((try!(self.socket4.local_addr()), try!(self.socket6.local_addr())))
    }

    #[allow(dead_code)]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn add_reconnect_peer(&mut self, add: String) {
        self.reconnect_peers.push(ReconnectEntry {
            address: add,
            tries: 0,
            timeout: 1,
            next: now()
        })
    }

    fn is_blacklisted<Addr: ToSocketAddrs+fmt::Display>(&self, addr: Addr) -> Result<bool, Error> {
        let mut addrs = try!(addr.to_socket_addrs().map_err(|_| Error::SocketError("Error looking up name")));
        while let Some(a) = addrs.next() {
            if self.blacklist_peers.contains(&a) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn connect<Addr: ToSocketAddrs+fmt::Display+Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        if try!(self.peers.is_connected(addr.clone())) || try!(self.is_blacklisted(addr.clone())) {
            return Ok(())
        }
        debug!("Connecting to {}", addr);
        let subnets = self.addresses.clone();
        let node_id = self.node_id.clone();
        let mut msg = Message::Init(0, node_id, subnets);
        if let Ok(addrs) = addr.to_socket_addrs() {
            let mut addrs = addrs.collect::<Vec<_>>();
            addrs.dedup();
            for a in addrs {
                //Ignore error this time
                self.send_msg(a, &mut msg).ok();
            }
        }
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peers.timeout();
        self.table.housekeep();
        let now = now();
        if self.next_peerlist <= now {
            debug!("Send peer list to all peers");
            let mut peer_num = self.peers.len();
            if peer_num > 10 {
                peer_num = (peer_num as f32).sqrt().ceil() as usize;
                if peer_num < 10 {
                    peer_num = 10;
                }
                if peer_num > 255 {
                    peer_num = 255
                }
            }
            let peers = self.peers.subset(peer_num);
            let mut msg = Message::Peers(peers);
            try!(self.broadcast_msg(&mut msg));
            self.next_peerlist = now + self.update_freq as Time;
        }
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue
            }
            try!(self.connect(&entry.address as &str));
        }
        for entry in &mut self.reconnect_peers {
            if try!(self.peers.is_connected(&entry.address as &str)) {
                entry.tries = 0;
                entry.timeout = 1;
                entry.next = now + 1;
                continue
            }
            if entry.next > now {
                continue
            }
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            if entry.timeout > 3600 {
                entry.timeout = 3600;
            }
            entry.next = now + entry.timeout as Time;
        }
        Ok(())
    }

    pub fn handle_interface_data(&mut self, payload: &mut [u8], start: usize, end: usize) -> Result<(), Error> {
        let (src, dst) = try!(P::parse(&payload[start..end]));
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, end-start);
        match self.table.lookup(&dst) {
            Some(addr) => {
                debug!("Found destination for {} => {}", dst, addr);
                if self.peers.contains_addr(&addr) {
                    try!(self.send_msg(addr, &mut Message::Data(payload, start, end)))
                } else {
                    warn!("Destination for {} not found in peers: {}", dst, addr);
                    self.table.remove(&dst);
                }
            },
            None => {
                if !self.broadcast {
                    debug!("No destination for {} found, dropping", dst);
                    return Ok(());
                }
                debug!("No destination for {} found, broadcasting", dst);
                let mut msg = Message::Data(payload, start, end);
                try!(self.broadcast_msg(&mut msg));
            }
        }
        Ok(())
    }

    pub fn handle_net_message(&mut self, peer: SocketAddr, options: Options, msg: Message) -> Result<(), Error> {
        if self.options.network_id != options.network_id {
            info!("Ignoring message from {} with wrong token {:?}", peer, options.network_id);
            return Err(Error::WrongNetwork(options.network_id));
        }
        debug!("Received {:?} from {}", msg, peer);
        match msg {
            Message::Data(payload, start, end) => {
                let (src, _dst) = try!(P::parse(&payload[start..end]));
                debug!("Writing data to device: {} bytes", end-start);
                match self.device.write(&payload[start..end]) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to send via device: {}", e);
                        return Err(Error::TunTapDevError("Failed to write to device"));
                    }
                }
                // not adding peer to increase performance
                if self.learning {
                    //learn single address
                    self.table.learn(src, None, peer);
                }
            },
            Message::Peers(peers) => {
                for p in &peers {
                    if ! self.peers.contains_addr(p) && ! self.blacklist_peers.contains(p) {
                        try!(self.connect(p));
                    }
                }
            },
            Message::Init(stage, node_id, ranges) => {
                if node_id == self.node_id {
                    self.blacklist_peers.push(peer);
                    return Ok(())
                }
                if self.peers.contains_node(&node_id) {
                    self.peers.add_alt_addr(node_id, peer);
                } else {
                    self.peers.add(node_id, peer);
                    for range in ranges {
                        self.table.learn(range.base, Some(range.prefix_len), peer.clone());
                    }
                }
                if stage == 0 {
                    let peers = self.peers.as_vec();
                    let own_addrs = self.addresses.clone();
                    let own_node_id = self.node_id.clone();
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

    pub fn run(&mut self) {
        let dummy_time = SteadyTime::now();
        let trap = Trap::trap(&[SIGINT, SIGTERM, SIGQUIT]);
        let epoll_handle = try_fail!(epoll::create1(0), "Failed to create epoll handle: {}");
        let socket4_fd = self.socket4.as_raw_fd();
        let socket6_fd = self.socket6.as_raw_fd();
        let device_fd = self.device.as_raw_fd();
        let mut socket4_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 0};
        let mut socket6_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 1};
        let mut device_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 2};
        try_fail!(epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, socket4_fd, &mut socket4_event), "Failed to add ipv4 socket to epoll handle: {}");
        try_fail!(epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, socket6_fd, &mut socket6_event), "Failed to add ipv6 socket to epoll handle: {}");
        try_fail!(epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, device_fd, &mut device_event), "Failed to add device to epoll handle: {}");
        let mut events = [epoll::EpollEvent{events: 0, data: 0}; 2];
        let mut buffer = [0; 64*1024];
        loop {
            let count = try_fail!(epoll::wait(epoll_handle, &mut events, 1000), "Epoll wait failed: {}") as usize;
            // Process events
            for i in 0..count {
                match &events[i].data {
                    &0 => {
                        let (size, src) = try_fail!(self.socket4.recv_from(&mut buffer), "Failed to read from ipv4 network socket: {}");
                        match decode(&mut buffer[..size], &mut self.crypto).and_then(|(options, msg)| self.handle_net_message(src, options, msg)) {
                            Ok(_) => (),
                            Err(e) => error!("Error: {}, from: {}", e, src)
                        }
                    },
                    &1 => {
                        let (size, src) = try_fail!(self.socket6.recv_from(&mut buffer), "Failed to read from ipv6 network socket: {}");
                        match decode(&mut buffer[..size], &mut self.crypto).and_then(|(options, msg)| self.handle_net_message(src, options, msg)) {
                            Ok(_) => (),
                            Err(e) => error!("Error: {}, from: {}", e, src)
                        }
                    },
                    &2 => {
                        let start = 64;
                        let size = try_fail!(self.device.read(&mut buffer[start..]), "Failed to read from tap device: {}");
                        match self.handle_interface_data(&mut buffer, start, start+size) {
                            Ok(_) => (),
                            Err(e) => error!("Error: {}", e)
                        }
                    },
                    _ => unreachable!()
                }
            }
            if self.next_housekeep < now() {
                // Check for signals
                if trap.wait(dummy_time).is_some() {
                    break;
                }
                // Do the housekeeping
                match self.housekeep() {
                    Ok(_) => (),
                    Err(e) => error!("Error: {}", e)
                }
                self.next_housekeep = now() + 1
            }
        }
        info!("Shutting down...");
        self.broadcast_msg(&mut Message::Close).ok();
    }
}
