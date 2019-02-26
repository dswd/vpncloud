use std::os::unix::io::{RawFd, AsRawFd};
use std::net::{UdpSocket, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, ErrorKind};
use std::collections::VecDeque;

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
        UdpBuilder::new_v4().expect("Failed to obtain ipv4 socket builder")
            .reuse_address(true).expect("Failed to set so_reuseaddr").bind((host, port))
    }
    fn listen_v6(host: &str, port: u16) -> Result<Self, io::Error> {
        UdpBuilder::new_v6().expect("Failed to obtain ipv4 socket builder")
            .only_v6(true).expect("Failed to set only_v6")
            .reuse_address(true).expect("Failed to set so_reuseaddr").bind((host, port))
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


pub struct MockSocket {
    address: SocketAddr,
    outbound: VecDeque<(SocketAddr, Vec<u8>)>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>
}

impl MockSocket {
    pub fn new(address: SocketAddr) -> Self {
        Self { address, outbound: VecDeque::new(), inbound: VecDeque::new() }
    }

    pub fn put_inbound(&mut self, from: SocketAddr, data: Vec<u8>) {
        self.inbound.push_back((from, data))
    }

    pub fn pop_outbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.outbound.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.inbound.is_empty() && self.outbound.is_empty()
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
            Err(io::Error::from(ErrorKind::UnexpectedEof))
        }
    }
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.outbound.push_back((addr, data.to_owned()));
        Ok(data.len())
    }
    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.address)
    }
}