use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    os::unix::io::{AsRawFd, RawFd},
    sync::atomic::{AtomicBool, Ordering}
};

use super::util::{MockTimeSource, Time, TimeSource};

use net2::UdpBuilder;


pub trait Socket: AsRawFd + Sized {
    fn listen_v4(host: &str, port: u16) -> Result<Self, io::Error>;
    fn listen_v6(host: &str, port: u16) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
}

impl Socket for UdpSocket {
    fn listen_v4(host: &str, port: u16) -> Result<Self, io::Error> {
        UdpBuilder::new_v4().expect("Failed to obtain ipv4 socket builder").bind((host, port))
    }
    fn listen_v6(host: &str, port: u16) -> Result<Self, io::Error> {
        UdpBuilder::new_v6()
            .expect("Failed to obtain ipv4 socket builder")
            .only_v6(true)
            .expect("Failed to set only_v6")
            .bind((host, port))
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        self.recv_from(buffer)
    }
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.send_to(data, addr)
    }
    fn address(&self) -> Result<SocketAddr, io::Error> {
        self.local_addr()
    }
}

thread_local! {
    static MOCK_SOCKET_NAT: AtomicBool = AtomicBool::new(false);
}

pub struct MockSocket {
    nat: bool,
    nat_peers: HashMap<SocketAddr, Time>,
    address: SocketAddr,
    outbound: VecDeque<(SocketAddr, Vec<u8>)>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>
}

impl MockSocket {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            nat: Self::get_nat(),
            nat_peers: HashMap::new(),
            address,
            outbound: VecDeque::new(),
            inbound: VecDeque::new()
        }
    }

    pub fn set_nat(nat: bool) {
        MOCK_SOCKET_NAT.with(|t| t.store(nat, Ordering::SeqCst))
    }

    pub fn get_nat() -> bool {
        MOCK_SOCKET_NAT.with(|t| t.load(Ordering::SeqCst))
    }

    pub fn put_inbound(&mut self, from: SocketAddr, data: Vec<u8>) -> bool {
        if !self.nat {
            self.inbound.push_back((from, data));
            return true
        }
        if let Some(timeout) = self.nat_peers.get(&from) {
            if *timeout >= MockTimeSource::now() {
                self.inbound.push_back((from, data));
                return true
            }
        }
        warn!("Sender {:?} is filtered out by NAT", from);
        false
    }

    pub fn pop_outbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.outbound.pop_front()
    }
}

impl AsRawFd for MockSocket {
    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

impl Socket for MockSocket {
    fn listen_v4(host: &str, port: u16) -> Result<Self, io::Error> {
        let ip = try_fail!(host.parse(), "Failed to parse IPv4 address: {}");
        Ok(Self::new(SocketAddr::V4(SocketAddrV4::new(ip, port))))
    }
    fn listen_v6(host: &str, port: u16) -> Result<Self, io::Error> {
        let ip = try_fail!(host.parse(), "Failed to parse IPv6 address: {}");
        Ok(Self::new(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        if let Some((addr, data)) = self.inbound.pop_front() {
            buffer[0..data.len()].copy_from_slice(&data);
            Ok((data.len(), addr))
        } else {
            Err(io::Error::new(ErrorKind::Other, "nothing in queue"))
        }
    }
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.outbound.push_back((addr, data.to_owned()));
        if self.nat {
            self.nat_peers.insert(addr, MockTimeSource::now() + 300);
        }
        Ok(data.len())
    }
    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.address)
    }
}
