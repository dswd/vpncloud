use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::Read;
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::marker::PhantomData;

use epoll;
use nix::sys::signal::{SIGTERM, SIGQUIT, SIGINT};
use signal::trap::Trap;
use time::SteadyTime;
use rand::{random, sample, thread_rng};

use super::types::{Table, Protocol, Range, Error, NetworkId, NodeId};
use super::device::Device;
use super::udpmessage::{encode, decode, Options, Message};
use super::crypto::Crypto;
use super::util::{now, Time, Duration};

struct PeerList {
    timeout: Duration,
    peers: HashMap<SocketAddr, Time>
}

impl PeerList {
    fn new(timeout: Duration) -> PeerList {
        PeerList{peers: HashMap::new(), timeout: timeout}
    }

    fn timeout(&mut self) -> Vec<SocketAddr> {
        let now = now();
        let mut del: Vec<SocketAddr> = Vec::new();
        for (&addr, &timeout) in &self.peers {
            if timeout < now {
                del.push(addr);
            }
        }
        for addr in &del {
            debug!("Forgot peer: {:?}", addr);
            self.peers.remove(addr);
        }
        del
    }

    #[inline(always)]
    fn contains(&mut self, addr: &SocketAddr) -> bool {
        self.peers.contains_key(addr)
    }

    #[inline]
    fn add(&mut self, addr: &SocketAddr) {
        if self.peers.insert(*addr, now()+self.timeout as Time).is_none() {
            info!("New peer: {:?}", addr);
        }
    }

    #[inline]
    fn as_vec(&self) -> Vec<SocketAddr> {
        self.peers.keys().map(|addr| *addr).collect()
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
        if self.peers.remove(&addr).is_some() {
            info!("Removed peer: {:?}", addr);
        }
    }
}


pub struct GenericCloud<P: Protocol> {
    node_id: NodeId,
    peers: PeerList,
    addresses: Vec<Range>,
    learning: bool,
    broadcast: bool,
    reconnect_peers: Vec<SocketAddr>,
    blacklist_peers: Vec<SocketAddr>,
    table: Box<Table>,
    socket: UdpSocket,
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
    pub fn new(device: Device, listen: String, network_id: Option<NetworkId>, table: Box<Table>,
        peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>,
        crypto: Crypto) -> Self {
        let socket = match UdpSocket::bind(&listen as &str) {
            Ok(socket) => socket,
            _ => fail!("Failed to open socket {}", listen)
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
            socket: socket,
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
            try!(match self.socket.send_to(msg_data, addr) {
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
        match self.socket.send_to(msg_data, addr) {
            Ok(written) if written == msg_data.len() => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    pub fn connect<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, reconnect: bool) -> Result<(), Error> {
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                if self.peers.contains(&a) || self.blacklist_peers.contains(&a) {
                    return Ok(());
                }
            }
        }
        debug!("Connecting to {}", addr);
        if reconnect {
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                while let Some(a) = addrs.next() {
                    self.reconnect_peers.push(a);
                }
            }
        }
        let subnets = self.addresses.clone();
        let node_id = self.node_id.clone();
        let mut msg = Message::Init(0, node_id, subnets);
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(a) = addrs.next() {
                //Ignore error this time
                self.send_msg(a, &mut msg).ok();
            }
        }
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peers.timeout();
        self.table.housekeep();
        if self.next_peerlist <= now() {
            debug!("Send peer list to all peers");
            let mut peer_num = self.peers.len();
            if peer_num > 10 {
                peer_num = (peer_num as f32).sqrt().ceil() as usize;
                if peer_num < 10 {
                    peer_num = 10;
                }
            }
            let peers = self.peers.subset(peer_num);
            let mut msg = Message::Peers(peers);
            try!(self.broadcast_msg(&mut msg));
            self.next_peerlist = now() + self.update_freq as Time;
        }
        for addr in self.reconnect_peers.clone() {
            try!(self.connect(addr, false));
        }
        Ok(())
    }

    fn handle_interface_data(&mut self, payload: &mut [u8], start: usize, end: usize) -> Result<(), Error> {
        let (src, dst) = try!(P::parse(&payload[start..end]));
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, end-start);
        match self.table.lookup(&dst) {
            Some(addr) => {
                debug!("Found destination for {} => {}", dst, addr);
                if self.peers.contains(&addr) {
                    try!(self.send_msg(addr, &mut Message::Data(payload, start, end)))
                } else {
                    warn!("Destination for {} not found in peers: {}", dst, addr);
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

    fn handle_net_message(&mut self, peer: SocketAddr, options: Options, msg: Message) -> Result<(), Error> {
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
                    if ! self.peers.contains(p) && ! self.blacklist_peers.contains(p) {
                        try!(self.connect(p, false));
                    }
                }
            },
            Message::Init(stage, node_id, ranges) => {
                if node_id == self.node_id {
                    self.blacklist_peers.push(peer);
                    return Ok(())
                }
                self.peers.add(&peer);
                for range in ranges {
                    self.table.learn(range.base, Some(range.prefix_len), peer.clone());
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
            }
        }
        Ok(())
    }

    pub fn run(&mut self) {
        let dummy_time = SteadyTime::now();
        let trap = Trap::trap(&[SIGINT, SIGTERM, SIGQUIT]);
        let epoll_handle = try_fail!(epoll::create1(0), "Failed to create epoll handle: {}");
        let socket_fd = self.socket.as_raw_fd();
        let device_fd = self.device.as_raw_fd();
        let mut socket_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 0};
        let mut device_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 1};
        try_fail!(epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, socket_fd, &mut socket_event), "Failed to add socket to epoll handle: {}");
        try_fail!(epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, device_fd, &mut device_event), "Failed to add device to epoll handle: {}");
        let mut events = [epoll::EpollEvent{events: 0, data: 0}; 2];
        let mut buffer = [0; 64*1024];
        loop {
            let count = try_fail!(epoll::wait(epoll_handle, &mut events, 1000), "Epoll wait failed: {}");
            // Process events
            for i in 0..count {
                match &events[i as usize].data {
                    &0 => {
                        let (size, src) = try_fail!(self.socket.recv_from(&mut buffer), "Failed to read from network socket: {}");
                        match decode(&mut buffer[..size], &mut self.crypto).and_then(|(options, msg)| self.handle_net_message(src, options, msg)) {
                            Ok(_) => (),
                            Err(e) => error!("Error: {}, from: {}", e, src)
                        }
                    },
                    &1 => {
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
