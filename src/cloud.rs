use std::net::{SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::Read;
use std::{fmt, ptr};
use std::os::unix::io::AsRawFd;
use std::marker::PhantomData;
use std::str::FromStr;

use time::{Duration, SteadyTime, precise_time_ns};
use epoll;

use super::device::{TunDevice, TapDevice};
use super::udpmessage::{encode, decode, Options, Message};
use super::ethernet::{Frame, MacTable};
use super::ip::{InternetProtocol, RoutingTable};
use super::util::as_bytes;


pub type NetworkId = u64;

#[derive(PartialEq, PartialOrd, Eq, Ord, Hash, Clone)]
pub struct Address(pub Vec<u8>);

impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.0.len() {
            4 => write!(formatter, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3]),
            6 => write!(formatter, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]),
            16 => write!(formatter, "{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15]
            ),
            _ => self.0.fmt(formatter)
        }
    }
}

impl FromStr for Address {
    type Err=Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = Ipv4Addr::from_str(text) {
            let ip = addr.octets();
            let mut res = Vec::with_capacity(4);
            unsafe {
                res.set_len(4);
                ptr::copy_nonoverlapping(ip.as_ptr(), res.as_mut_ptr(), ip.len());
            }
            return Ok(Address(res));
        }
        if let Ok(addr) = Ipv6Addr::from_str(text) {
            let mut segments = addr.segments();
            for i in 0..8 {
                segments[i] = segments[i].to_be();
            }
            let bytes = unsafe { as_bytes(&segments) };
            let mut res = Vec::with_capacity(16);
            unsafe {
                res.set_len(16);
                ptr::copy_nonoverlapping(bytes.as_ptr(), res.as_mut_ptr(), bytes.len());
            }
            return Ok(Address(res));
        }
        //FIXME: implement for mac addresses
        return Err(Error::ParseError("Failed to parse address"))
    }
}


#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Clone)]
pub struct Range {
    pub base: Address,
    pub prefix_len: u8
}

impl FromStr for Range {
    type Err=Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let pos = match text.find("/") {
            Some(pos) => pos,
            None => return Err(Error::ParseError("Invalid range format"))
        };
        let prefix_len = try!(u8::from_str(&text[pos+1..])
            .map_err(|_| Error::ParseError("Failed to parse prefix length")));
        let base = try!(Address::from_str(&text[..pos]));
        Ok(Range{base: base, prefix_len: prefix_len})
    }
}


#[derive(RustcDecodable, Debug)]
pub enum Behavior {
    Normal, Hub, Switch, Router
}

pub trait Table {
    fn learn(&mut self, Address, Option<u8>, SocketAddr);
    fn lookup(&self, &Address) -> Option<SocketAddr>;
    fn housekeep(&mut self);
    fn remove_all(&mut self, SocketAddr);
}

pub trait Protocol: Sized {
    fn parse(&[u8]) -> Result<(Address, Address), Error>;
}

pub trait VirtualInterface: AsRawFd {
    fn read(&mut self, &mut [u8]) -> Result<usize, Error>;
    fn write(&mut self, &[u8]) -> Result<(), Error>;
}


#[derive(Debug)]
pub enum Error {
    ParseError(&'static str),
    WrongNetwork(Option<NetworkId>),
    SocketError(&'static str),
    TunTapDevError(&'static str),
}


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


pub struct GenericCloud<T: Table, P: Protocol, I: VirtualInterface> {
    peers: PeerList,
    addresses: Vec<Range>,
    learning: bool,
    broadcast: bool,
    reconnect_peers: Vec<SocketAddr>,
    table: T,
    socket: UdpSocket,
    device: I,
    network_id: Option<NetworkId>,
    next_peerlist: SteadyTime,
    update_freq: Duration,
    buffer_out: [u8; 64*1024],
    next_housekeep: SteadyTime,
    _dummy_m: PhantomData<P>,
}

impl<T: Table, P: Protocol, I: VirtualInterface> GenericCloud<T, P, I> {
    pub fn new(device: I, listen: String, network_id: Option<NetworkId>, table: T,
        peer_timeout: Duration, learning: bool, broadcast: bool, addresses: Vec<Range>) -> Self {
        let socket = match UdpSocket::bind(&listen as &str) {
            Ok(socket) => socket,
            _ => panic!("Failed to open socket")
        };
        GenericCloud{
            peers: PeerList::new(peer_timeout),
            addresses: addresses,
            learning: learning,
            broadcast: broadcast,
            reconnect_peers: Vec::new(),
            table: table,
            socket: socket,
            device: device,
            network_id: network_id,
            next_peerlist: SteadyTime::now(),
            update_freq: peer_timeout/2,
            buffer_out: [0; 64*1024],
            next_housekeep: SteadyTime::now(),
            _dummy_m: PhantomData,
        }
    }

    fn send_msg<Addr: ToSocketAddrs+fmt::Display>(&mut self, addr: Addr, msg: &Message) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let mut options = Options::default();
        options.network_id = self.network_id;
        let size = encode(&options, msg, &mut self.buffer_out);
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
        info!("Connecting to {}", addr);
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
        if let Some(id) = self.network_id {
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
                            match decode(&buffer[..size]).and_then(|(options, msg)| self.handle_net_message(src, options, msg)) {
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


pub type TapCloud = GenericCloud<MacTable, Frame, TapDevice>;

impl TapCloud {
    pub fn new_tap_cloud(device: &str, listen: String, behavior: Behavior, network_id: Option<NetworkId>, mac_timeout: Duration, peer_timeout: Duration) -> Self {
        let device = match TapDevice::new(device) {
            Ok(device) => device,
            _ => panic!("Failed to open tap device")
        };
        info!("Opened tap device {}", device.ifname());
        let table = MacTable::new(mac_timeout);
        let (learning, broadcasting) = match behavior {
            Behavior::Normal => (true, true),
            Behavior::Switch => (true, true),
            Behavior::Hub => (false, true),
            Behavior::Router => (false, false)
        };
        Self::new(device, listen, network_id, table, peer_timeout, learning, broadcasting, vec![])
    }
}


pub type TunCloud = GenericCloud<RoutingTable, InternetProtocol, TunDevice>;

impl TunCloud {
    pub fn new_tun_cloud(device: &str, listen: String, behavior: Behavior, network_id: Option<NetworkId>, range_strs: Vec<String>, peer_timeout: Duration) -> Self {
        let device = match TunDevice::new(device) {
            Ok(device) => device,
            _ => panic!("Failed to open tun device")
        };
        info!("Opened tun device {}", device.ifname());
        let table = RoutingTable::new();
        let mut ranges = Vec::with_capacity(range_strs.len());
        for s in range_strs {
            ranges.push(Range::from_str(&s).expect("Invalid subnet"));
        }
        let (learning, broadcasting) = match behavior {
            Behavior::Normal => (false, false),
            Behavior::Switch => (true, true),
            Behavior::Hub => (false, true),
            Behavior::Router => (false, false)
        };
        Self::new(device, listen, network_id, table, peer_timeout, learning, broadcasting, ranges)
    }
}
