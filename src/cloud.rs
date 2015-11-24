use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::Read;
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::marker::PhantomData;

use time::{Duration, SteadyTime, precise_time_ns};
use epoll;

use super::types::{Table, Protocol, Range, Error, NetworkId};
use super::device::Device;
use super::udpmessage::{encode, decode, Options, Message};
use super::{ethernet, ip};
use super::crypto::Crypto;

struct PeerList {
    timeout: Duration,
    peers: HashMap<SocketAddr, SteadyTime>
}

impl PeerList {
    fn new(timeout: Duration) -> PeerList {
        PeerList{peers: HashMap::new(), timeout: timeout}
    }

    fn timeout(&mut self) -> Vec<SocketAddr> {
        let now = SteadyTime::now();
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
        if self.peers.insert(*addr, SteadyTime::now()+self.timeout).is_none() {
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
    fn subset(&self, size: usize, seed: u32) -> Vec<SocketAddr> {
        let mut peers = self.as_vec();
        let mut psrng = seed;
        let len = peers.len();
        for i in size..len {
            peers.swap_remove(psrng as usize % (len - i));
            psrng = ((1664525 as u64) * (psrng as u64) + (1013904223 as u64)) as u32;
        }
        peers
    }

    #[inline]
    fn remove(&mut self, addr: &SocketAddr) {
        if self.peers.remove(&addr).is_some() {
            info!("Removed peer: {:?}", addr);
        }
    }
}


pub struct GenericCloud<P: Protocol> {
    peers: PeerList,
    addresses: Vec<Range>,
    learning: bool,
    broadcast: bool,
    reconnect_peers: Vec<SocketAddr>,
    table: Box<Table>,
    socket: UdpSocket,
    device: Device,
    options: Options,
    crypto: Crypto,
    next_peerlist: SteadyTime,
    update_freq: Duration,
    buffer_out: [u8; 64*1024],
    next_housekeep: SteadyTime,
    _dummy_p: PhantomData<P>,
}

impl<P: Protocol> GenericCloud<P> {
    pub fn new(device: Device, listen: String, network_id: Option<NetworkId>, table: Box<Table>,
        peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>,
        crypto: Crypto) -> Self {
        let socket = match UdpSocket::bind(&listen as &str) {
            Ok(socket) => socket,
            _ => panic!("Failed to open socket")
        };
        let mut options = Options::default();
        options.network_id = network_id;
        GenericCloud{
            peers: PeerList::new(peer_timeout),
            addresses: addresses,
            learning: learning,
            broadcast: broadcast,
            reconnect_peers: Vec::new(),
            table: table,
            socket: socket,
            device: device,
            options: options,
            crypto: crypto,
            next_peerlist: SteadyTime::now(),
            update_freq: peer_timeout/2,
            buffer_out: [0; 64*1024],
            next_housekeep: SteadyTime::now(),
            _dummy_p: PhantomData,
        }
    }

    pub fn ifname(&self) -> &str {
        self.device.ifname()
    }

    fn send_msg<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, msg: &Message) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let size = encode(&mut self.options, msg, &mut self.buffer_out, &mut self.crypto);
        match self.socket.send_to(&self.buffer_out[..size], addr) {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    pub fn connect<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, reconnect: bool) -> Result<(), Error> {
        if let Ok(mut addrs) = addr.to_socket_addrs() {
            while let Some(addr) = addrs.next() {
                if self.peers.contains(&addr) {
                    return Ok(());
                }
            }
        }
        debug!("Connecting to {}", addr);
        if reconnect {
            let addr = addr.to_socket_addrs().unwrap().next().unwrap();
            self.reconnect_peers.push(addr);
        }
        let addrs = self.addresses.clone();
        self.send_msg(addr, &Message::Init(addrs))
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peers.timeout();
        self.table.housekeep();
        if self.next_peerlist <= SteadyTime::now() {
            debug!("Send peer list to all peers");
            let mut peer_num = self.peers.len();
            if peer_num > 10 {
                peer_num = (peer_num as f32).sqrt().ceil() as usize;
                if peer_num < 10 {
                    peer_num = 10;
                }
            }
            let peers = self.peers.subset(peer_num, precise_time_ns() as u32);
            let msg = Message::Peers(peers);
            for addr in &self.peers.as_vec() {
                try!(self.send_msg(addr, &msg));
            }
            self.next_peerlist = SteadyTime::now() + self.update_freq;
        }
        for addr in self.reconnect_peers.clone() {
            try!(self.connect(addr, false));
        }
        Ok(())
    }

    fn handle_interface_data(&mut self, payload: &[u8]) -> Result<(), Error> {
        let (src, dst) = try!(P::parse(payload));
        debug!("Read data from interface: src: {:?}, dst: {:?}, {} bytes", src, dst, payload.len());
        match self.table.lookup(&dst) {
            Some(addr) => {
                debug!("Found destination for {:?} => {}", dst, addr);
                if self.peers.contains(&addr) {
                    try!(self.send_msg(addr, &Message::Data(payload)))
                } else {
                    warn!("Destination for {:?} not found in peers: {}", dst, addr);
                }
            },
            None => {
                if !self.broadcast {
                    debug!("No destination for {:?} found, dropping", dst);
                    return Ok(());
                }
                debug!("No destination for {:?} found, broadcasting", dst);
                let msg = Message::Data(payload);
                for addr in &self.peers.as_vec() {
                    try!(self.send_msg(addr, &msg));
                }
            }
        }
        Ok(())
    }

    fn handle_net_message(&mut self, peer: SocketAddr, options: Options, msg: Message) -> Result<(), Error> {
        if let Some(id) = self.options.network_id {
            if options.network_id != Some(id) {
                info!("Ignoring message from {} with wrong token {:?}", peer, options.network_id);
                return Err(Error::WrongNetwork(options.network_id));
            }
        }
        debug!("Recieved {:?} from {}", msg, peer);
        match msg {
            Message::Data(payload) => {
                let (src, _dst) = try!(P::parse(payload));
                debug!("Writing data to device: {} bytes", payload.len());
                match self.device.write(&payload) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to send via device {:?}", e);
                        return Err(Error::TunTapDevError("Failed to write to device"));
                    }
                }
                self.peers.add(&peer);
                if self.learning {
                    //learn single address
                    self.table.learn(src, None, peer);
                }
            },
            Message::Peers(peers) => {
                self.peers.add(&peer);
                for p in &peers {
                    if ! self.peers.contains(p) {
                        try!(self.connect(p, false));
                    }
                }
            },
            Message::Init(ranges) => {
                if self.peers.contains(&peer) {
                    return Ok(());
                }
                self.peers.add(&peer);
                let peers = self.peers.as_vec();
                let own_addrs = self.addresses.clone();
                try!(self.send_msg(peer, &Message::Init(own_addrs)));
                try!(self.send_msg(peer, &Message::Peers(peers)));
                for range in ranges {
                    self.table.learn(range.base, Some(range.prefix_len), peer.clone());
                }
            },
            Message::Close => {
                self.peers.remove(&peer);
            }
        }
        Ok(())
    }

    pub fn run(&mut self) {
        let epoll_handle = epoll::create1(0).expect("Failed to create epoll handle");
        let socket_fd = self.socket.as_raw_fd();
        let device_fd = self.device.as_raw_fd();
        let mut socket_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 0};
        let mut device_event = epoll::EpollEvent{events: epoll::util::event_type::EPOLLIN, data: 1};
        epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, socket_fd, &mut socket_event).expect("Failed to add socket to epoll handle");
        epoll::ctl(epoll_handle, epoll::util::ctl_op::ADD, device_fd, &mut device_event).expect("Failed to add device to epoll handle");
        let mut events = [epoll::EpollEvent{events: 0, data: 0}; 2];
        let mut buffer = [0; 64*1024];
        loop {
            let count = epoll::wait(epoll_handle, &mut events, 1000).expect("Epoll wait failed");
            // Process events
            for i in 0..count {
                match &events[i as usize].data {
                    &0 => match self.socket.recv_from(&mut buffer) {
                        Ok((size, src)) => {
                            match decode(&mut buffer[..size], &mut self.crypto).and_then(|(options, msg)| self.handle_net_message(src, options, msg)) {
                                Ok(_) => (),
                                Err(e) => error!("Error: {:?}", e)
                            }
                        },
                        Err(_error) => panic!("Failed to read from network socket")
                    },
                    &1 => match self.device.read(&mut buffer) {
                        Ok(size) => match self.handle_interface_data(&buffer[..size]) {
                            Ok(_) => (),
                            Err(e) => error!("Error: {:?}", e)
                        },
                        Err(_error) => panic!("Failed to read from tap device")
                    },
                    _ => unreachable!()
                }
            }
            // Do the housekeeping
            if self.next_housekeep < SteadyTime::now() {
                match self.housekeep() {
                    Ok(_) => (),
                    Err(e) => error!("Error: {:?}", e)
                }
                self.next_housekeep = SteadyTime::now() + Duration::seconds(1)
            }
        }
    }
}


pub type TapCloud = GenericCloud<ethernet::Frame>;
pub type TunCloud = GenericCloud<ip::Packet>;
