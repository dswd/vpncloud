use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::{Read, ErrorKind};
use std::os::unix::io::AsRawFd;
use std::fmt;

use time::{Duration, SteadyTime};
use libc;

pub use ethernet::{encode as eth_encode, decode as eth_decode, Frame as EthernetFrame};
pub use tapdev::TapDevice;
pub use udpmessage::{encode as udp_encode, decode as udp_decode, Message as UdpMessage};


#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl fmt::Debug for Mac {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}


pub type Token = u64;

#[derive(Debug)]
pub enum Error {
    ParseError(&'static str),
    WrongToken(Token),
    SocketError(&'static str),
    TapdevError(&'static str),
}


struct PeerList {
    timeout: Duration,
    peers: HashMap<SocketAddr, SteadyTime>
}

impl PeerList {
    fn new(timeout: Duration) -> PeerList {
        PeerList{peers: HashMap::new(), timeout: timeout}
    }

    fn timeout(&mut self) {
        let now = SteadyTime::now();
        let mut del: Vec<SocketAddr> = Vec::new();
        for (&addr, &timeout) in &self.peers {
            if timeout < now {
                del.push(addr);
            }
        }
        for addr in del {
            debug!("Forgot peer: {:?}", addr);
            self.peers.remove(&addr);
        }
    }

    fn contains(&mut self, addr: &SocketAddr) -> bool {
        self.peers.contains_key(addr)
    }

    fn add(&mut self, addr: &SocketAddr) {
        if self.peers.insert(*addr, SteadyTime::now()+self.timeout).is_none() {
            info!("New peer: {:?}", addr);
        }
    }

    fn as_vec(&self) -> Vec<SocketAddr> {
        self.peers.keys().map(|addr| *addr).collect()
    }

    fn remove(&mut self, addr: &SocketAddr) {
        if self.peers.remove(&addr).is_some() {
            info!("Removed peer: {:?}", addr);
        }
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MacTableKey {
    mac: Mac,
    vlan: u16
}

struct MacTableValue {
    address: SocketAddr,
    timeout: SteadyTime
}

struct MacTable {
    table: HashMap<MacTableKey, MacTableValue>,
    timeout: Duration
}

impl MacTable {
    fn new(timeout: Duration) -> MacTable {
        MacTable{table: HashMap::new(), timeout: timeout}
    }

    fn timeout(&mut self) {
        let now = SteadyTime::now();
        let mut del: Vec<MacTableKey> = Vec::new();
        for (&key, val) in &self.table {
            if val.timeout < now {
                del.push(key);
            }
        }
        for key in del {
            info!("Forgot mac: {:?} (vlan {})", key.mac, key.vlan);
            self.table.remove(&key);
        }
    }

    fn learn(&mut self, mac: &Mac, vlan: u16, addr: &SocketAddr) {
       let key = MacTableKey{mac: *mac, vlan: vlan};
       let value = MacTableValue{address: *addr, timeout: SteadyTime::now()+self.timeout};
       if self.table.insert(key, value).is_none() {
           info!("Learned mac: {:?} (vlan {}) => {}", mac, vlan, addr);
       }
    }

    fn lookup(&self, mac: &Mac, vlan: u16) -> Option<SocketAddr> {
       let key = MacTableKey{mac: *mac, vlan: vlan};
       match self.table.get(&key) {
           Some(value) => Some(value.address),
           None => None
       }
    }
}


pub struct EthCloud {
    peers: PeerList,
    mactable: MacTable,
    socket: UdpSocket,
    tapdev: TapDevice,
    token: Token,
    next_peerlist: SteadyTime,
    update_freq: Duration
}

impl EthCloud {
    pub fn new(device: &str, listen: String, token: Token, mac_timeout: Duration, peer_timeout: Duration) -> Self {
        let socket = match UdpSocket::bind(&listen as &str) {
            Ok(socket) => socket,
            _ => panic!("Failed to open socket")
        };
        let res: i32;
        unsafe {
            res = libc::fcntl(socket.as_raw_fd(), libc::consts::os::posix01::F_SETFL, libc::consts::os::extra::O_NONBLOCK);
        }
        if res != 0 {
            panic!("Failed to set socket to non-blocking");
        }
        let tapdev = match TapDevice::new(device) {
            Ok(tapdev) => tapdev,
            _ => panic!("Failed to open tap device")
        };
        info!("Opened tap device {}", tapdev.ifname());
        EthCloud{
            peers: PeerList::new(peer_timeout),
            mactable: MacTable::new(mac_timeout),
            socket: socket,
            tapdev: tapdev,
            token: token,
            next_peerlist: SteadyTime::now(),
            update_freq: peer_timeout/2
        }
    }

    fn send_msg<A: ToSocketAddrs + fmt::Display>(&mut self, addr: A, msg: &UdpMessage) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let mut buffer = [0u8; 64*1024];
        let size = udp_encode(self.token, msg, &mut buffer);
        match self.socket.send_to(&buffer[..size], addr) {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    pub fn connect<A: ToSocketAddrs + fmt::Display>(&mut self, addr: A) -> Result<(), Error> {
        info!("Connecting to {}", addr);
        self.send_msg(addr, &UdpMessage::GetPeers)
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peers.timeout();
        self.mactable.timeout();
        if self.next_peerlist <= SteadyTime::now() {
            debug!("Send peer list to all peers");
            let peers = self.peers.as_vec();
            let msg = UdpMessage::Peers(peers);
            for addr in &self.peers.as_vec() {
                try!(self.send_msg(addr, &msg));
            }
            self.next_peerlist = SteadyTime::now() + self.update_freq;
        }
        Ok(())
    }

    fn handle_ethernet_frame(&mut self, frame: EthernetFrame) -> Result<(), Error> {
        debug!("Read ethernet frame from tap {:?}", frame);
        match self.mactable.lookup(frame.dst, frame.vlan) {
            Some(addr) => {
                debug!("Found destination for {:?} (vlan {}) => {}", frame.dst, frame.vlan, addr);
                try!(self.send_msg(addr, &UdpMessage::Frame(frame)))
            },
            None => {
                debug!("No destination for {:?} (vlan {}) found, broadcasting", frame.dst, frame.vlan);
                let msg = UdpMessage::Frame(frame);
                for addr in &self.peers.as_vec() {
                    try!(self.send_msg(addr, &msg));
                }
            }
        }
        Ok(())
    }

    fn handle_net_message(&mut self, peer: SocketAddr, token: Token, msg: UdpMessage) -> Result<(), Error> {
        if token != self.token {
            info!("Ignoring message from {} with wrong token {}", peer, token);
            return Err(Error::WrongToken(token));
        }
        debug!("Recieved {:?} from {}", msg, peer);
        match msg {
            UdpMessage::Frame(frame) => {
                self.peers.add(&peer);
                self.mactable.learn(frame.src, frame.vlan, &peer);
                let mut buffer = [0u8; 64*1024];
                let size = eth_encode(&frame, &mut buffer);
                debug!("Writing ethernet frame to tap: {:?}", frame);
                match self.tapdev.write(&buffer[..size]) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to send via tap device {:?}", e);
                        return Err(Error::TapdevError("Failed to write to tap device"));
                    }
                }
            },
            UdpMessage::Peers(peers) => {
                self.peers.add(&peer);
                for p in &peers {
                    if ! self.peers.contains(p) {
                        try!(self.connect(p));
                    }
                }
            },
            UdpMessage::GetPeers => {
                self.peers.add(&peer);
                let peers = self.peers.as_vec();
                try!(self.send_msg(peer, &UdpMessage::Peers(peers)));
            },
            UdpMessage::Close => self.peers.remove(&peer)
        }
        Ok(())
    }

    pub fn run(&mut self) {
        let mut buffer = [0u8; 64*1024];
        loop {
            match self.socket.recv_from(&mut buffer) {
                Ok((size, src)) => {
                    match udp_decode(&buffer[..size]).and_then(|(token, msg)| self.handle_net_message(src, token, msg)) {
                        Ok(_) => (),
                        Err(e) => error!("Error: {:?}", e)
                    }
                },
                Err(error) => match error.kind() {
                    ErrorKind::WouldBlock => (),
                    _ => panic!("Failed to read from network socket")
                }
            }
            match self.tapdev.read(&mut buffer) {
                Ok(size) => {
                    match eth_decode(&buffer[..size]).and_then(|frame| self.handle_ethernet_frame(frame)) {
                        Ok(_) => (),
                        Err(e) => error!("Error: {:?}", e)
                    }
                },
                Err(error) => match error.kind() {
                    ErrorKind::WouldBlock => (),
                    _ => panic!("Failed to read from tap device")
                }
            }
            match self.housekeep() {
                Ok(_) => (),
                Err(e) => error!("Error: {:?}", e)
            }
        }
    }
}
