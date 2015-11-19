use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::hash::Hasher;
use std::net::UdpSocket;
use std::io::Read;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::ops::Deref;
use std::time::Duration as StdDuration;

use time::{Duration, SteadyTime};

use super::{ethernet, udpmessage};
use super::tapdev::TapDevice;


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

pub struct EthCloudInner {
    peers: Mutex<PeerList>,
    mactable: Mutex<MacTable>,
    socket: Mutex<UdpSocket>,
    tapdev: Mutex<TapDevice>,
    token: Token,
    next_peerlist: Mutex<SteadyTime>,
    update_freq: Duration
}

#[derive(Clone)]
pub struct EthCloud(Arc<EthCloudInner>);

impl Deref for EthCloud {
    type Target = EthCloudInner;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EthCloud {
    pub fn new(device: &str, listen: String, token: Token, mac_timeout: Duration, peer_timeout: Duration) -> Self {
        let socket = match UdpSocket::bind(&listen as &str) {
            Ok(socket) => socket,
            _ => panic!("Failed to open socket")
        };
        let tapdev = match TapDevice::new(device) {
            Ok(tapdev) => tapdev,
            _ => panic!("Failed to open tap device")
        };
        info!("Opened tap device {}", tapdev.ifname());
        EthCloud(Arc::new(EthCloudInner{
            peers: Mutex::new(PeerList::new(peer_timeout)),
            mactable: Mutex::new(MacTable::new(mac_timeout)),
            socket: Mutex::new(socket),
            tapdev: Mutex::new(tapdev),
            token: token,
            next_peerlist: Mutex::new(SteadyTime::now()),
            update_freq: peer_timeout/2
        }))
    }

    fn send_msg<A: ToSocketAddrs + fmt::Display>(&self, addr: A, msg: &udpmessage::Message) -> Result<(), Error> {
        debug!("Sending {:?} to {}", msg, addr);
        let mut buffer = [0u8; 64*1024];
        let size = udpmessage::encode(self.token, msg, &mut buffer);
        match self.socket.lock().expect("Lock poisoned").send_to(&buffer[..size], addr) {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::SocketError("Sent out truncated packet")),
            Err(e) => {
                error!("Failed to send via network {:?}", e);
                Err(Error::SocketError("IOError when sending"))
            }
        }
    }

    pub fn connect<A: ToSocketAddrs + fmt::Display>(&self, addr: A) -> Result<(), Error> {
        info!("Connecting to {}", addr);
        self.send_msg(addr, &udpmessage::Message::GetPeers)
    }

    fn housekeep(&self) -> Result<(), Error> {
        self.peers.lock().expect("Lock poisoned").timeout();
        self.mactable.lock().expect("Lock poisoned").timeout();
        let mut next_peerlist = self.next_peerlist.lock().expect("Lock poisoned");
        if *next_peerlist <= SteadyTime::now() {
            debug!("Send peer list to all peers");
            let peers = self.peers.lock().expect("Lock poisoned").as_vec();
            let msg = udpmessage::Message::Peers(peers.clone());
            for addr in &peers {
                try!(self.send_msg(addr, &msg));
            }
            *next_peerlist = SteadyTime::now() + self.update_freq;
        }
        Ok(())
    }

    fn handle_ethernet_frame(&self, frame: ethernet::Frame) -> Result<(), Error> {
        debug!("Read ethernet frame from tap {:?}", frame);
        match self.mactable.lock().expect("Lock poisoned").lookup(frame.dst, frame.vlan) {
            Some(addr) => {
                debug!("Found destination for {:?} (vlan {}) => {}", frame.dst, frame.vlan, addr);
                try!(self.send_msg(addr, &udpmessage::Message::Frame(frame)))
            },
            None => {
                debug!("No destination for {:?} (vlan {}) found, broadcasting", frame.dst, frame.vlan);
                let msg = udpmessage::Message::Frame(frame);
                for addr in &self.peers.lock().expect("Lock poisoned").as_vec() {
                    try!(self.send_msg(addr, &msg));
                }
            }
        }
        Ok(())
    }

    fn handle_net_message(&self, peer: SocketAddr, token: Token, msg: udpmessage::Message) -> Result<(), Error> {
        if token != self.token {
            info!("Ignoring message from {} with wrong token {}", peer, token);
            return Err(Error::WrongToken(token));
        }
        debug!("Recieved {:?} from {}", msg, peer);
        match msg {
            udpmessage::Message::Frame(frame) => {
                let mut buffer = [0u8; 64*1024];
                let size = ethernet::encode(&frame, &mut buffer);
                debug!("Writing ethernet frame to tap: {:?}", frame);
                match self.tapdev.lock().expect("Lock poisoned").write(&buffer[..size]) {
                    Ok(()) => (),
                    Err(e) => {
                        error!("Failed to send via tap device {:?}", e);
                        return Err(Error::TapdevError("Failed to write to tap device"));
                    }
                }
                self.peers.lock().expect("Lock poisoned").add(&peer);
                self.mactable.lock().expect("Lock poisoned").learn(frame.src, frame.vlan, &peer);
            },
            udpmessage::Message::Peers(peers) => {
                self.peers.lock().expect("Lock poisoned").add(&peer);
                for p in &peers {
                    if ! self.peers.lock().expect("Lock poisoned").contains(p) {
                        try!(self.connect(p));
                    }
                }
            },
            udpmessage::Message::GetPeers => {
                self.peers.lock().expect("Lock poisoned").add(&peer);
                let peers = self.peers.lock().expect("Lock poisoned").as_vec();
                try!(self.send_msg(peer, &udpmessage::Message::Peers(peers)));
            },
            udpmessage::Message::Close => self.peers.lock().expect("Lock poisoned").remove(&peer)
        }
        Ok(())
    }

    fn run_tapdev(&self) {
        let mut buffer = [0u8; 64*1024];
        let mut tapdev = self.tapdev.lock().expect("Lock poisoned").clone();
        loop {
            match tapdev.read(&mut buffer) {
                Ok(size) => {
                    match ethernet::decode(&mut buffer[..size]).and_then(|frame| self.handle_ethernet_frame(frame)) {
                        Ok(_) => (),
                        Err(e) => error!("Error: {:?}", e)
                    }
                },
                Err(_error) => panic!("Failed to read from tap device")
            }
        }
    }

    fn run_socket(&self) {
        let mut buffer = [0u8; 64*1024];
        let socket = self.socket.lock().expect("Lock poisoned").try_clone().expect("Failed to clone socket");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, src)) => {
                    match udpmessage::decode(&buffer[..size]).and_then(|(token, msg)| self.handle_net_message(src, token, msg)) {
                        Ok(_) => (),
                        Err(e) => error!("Error: {:?}", e)
                    }
                },
                Err(_error) => panic!("Failed to read from network socket")
            }
        }
    }

    pub fn run(&self) {
        let clone = self.clone();
        thread::spawn(move || {
            clone.run_socket()
        });
        let clone = self.clone();
        thread::spawn(move || {
            clone.run_tapdev()
        });
        loop {
            match self.housekeep() {
                Ok(_) => (),
                Err(e) => error!("Error: {:?}", e)
            }
            thread::sleep(StdDuration::new(1, 0));
        }
    }
}
