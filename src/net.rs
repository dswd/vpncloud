// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::config::DEFAULT_PORT;
use crate::port_forwarding::PortForwarding;
use crate::util::{MockTimeSource, MsgBuffer, Time, TimeSource};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::net::UdpSocket as AsyncUdpSocket;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{UdpSocket, IpAddr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub fn mapped_addr(addr: SocketAddr) -> SocketAddr {
    // HOT PATH
    match addr {
        SocketAddr::V4(addr4) => SocketAddr::new(IpAddr::V6(addr4.ip().to_ipv6_mapped()), addr4.port()),
        _ => addr,
    }
}

pub fn get_ip() -> IpAddr {
    let s = std::net::UdpSocket::bind("[::]:0").unwrap();
    s.connect("8.8.8.8:0").unwrap();
    s.local_addr().unwrap().ip()
}

#[async_trait]
pub trait Socket: Sized + Clone + Send + Sync + 'static {
    async fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    async fn address(&self) -> Result<SocketAddr, io::Error>;
    async fn create_port_forwarding(&self) -> Option<PortForwarding>;
}

pub fn parse_listen(addr: &str, default_port: u16) -> SocketAddr {
    if let Some(addr) = addr.strip_prefix("*:") {
        let port = try_fail!(addr.parse::<u16>(), "Invalid port: {}");
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else if addr.contains(':') {
        try_fail!(addr.parse::<SocketAddr>(), "Invalid address: {}: {}", addr)
    } else if let Ok(port) = addr.parse::<u16>() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        let ip = try_fail!(addr.parse::<IpAddr>(), "Invalid addr: {}");
        SocketAddr::new(ip, default_port)
    }
}

pub fn listen_udp(addr: &str) -> Result<UdpSocket, io::Error> {
    let addr = parse_listen(addr, DEFAULT_PORT);
    UdpSocket::bind(addr)
}

pub struct AsyncNetSocket(Arc<AsyncUdpSocket>);

impl Clone for AsyncNetSocket {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl AsyncNetSocket {
    pub fn from_socket(sock: UdpSocket) -> Result<Self, io::Error> {
        Ok(Self(Arc::new(AsyncUdpSocket::from_std(sock)?)))
    }
}


#[async_trait]
impl Socket for AsyncNetSocket {
    async fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let (size, addr) = self.0.recv_from(buffer.buffer()).await?;
        buffer.set_length(size);
        Ok(addr)
    }

    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.0.send_to(data, addr).await
    }

    async fn address(&self) -> Result<SocketAddr, io::Error> {
        let mut addr = self.0.local_addr()?;
        addr.set_ip(get_ip());
        Ok(addr)
    }

    async fn create_port_forwarding(&self) -> Option<PortForwarding> {
        PortForwarding::new(self.address().await.unwrap().port())
    }
}

thread_local! {
    static MOCK_SOCKET_NAT: AtomicBool = AtomicBool::new(false);
}

#[derive(Clone)]
pub struct MockSocket {
    nat: bool,
    nat_peers: Arc<Mutex<HashMap<SocketAddr, Time>>>,
    address: SocketAddr,
    outbound: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
    inbound: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
}

impl MockSocket {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            nat: Self::get_nat(),
            nat_peers: Default::default(),
            address,
            outbound: Arc::new(Mutex::new(VecDeque::with_capacity(10))),
            inbound: Arc::new(Mutex::new(VecDeque::with_capacity(10))),
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
            self.inbound.lock().push_back((from, data));
            return true;
        }
        if let Some(timeout) = self.nat_peers.lock().get(&from) {
            if *timeout >= MockTimeSource::now() {
                self.inbound.lock().push_back((from, data));
                return true;
            }
        }
        warn!("Sender {:?} is filtered out by NAT", from);
        false
    }

    pub fn pop_outbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.outbound.lock().pop_front()
    }
}

#[async_trait]
impl Socket for MockSocket {
    async fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        if let Some((addr, data)) = self.inbound.lock().pop_front() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(addr)
        } else {
            Err(io::Error::new(ErrorKind::Other, "nothing in queue"))
        }
    }

    async fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.outbound.lock().push_back((addr, data.into()));
        if self.nat {
            self.nat_peers.lock().insert(addr, MockTimeSource::now() + 300);
        }
        Ok(data.len())
    }

    async fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.address)
    }

    async fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }
}

#[cfg(feature = "bench")]
mod bench {
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use test::Bencher;

    #[bench]
    fn udp_send(b: &mut Bencher) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let data = [0; 1400];
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1);
        b.iter(|| sock.send_to(&data, &addr).unwrap());
        b.bytes = 1400;
    }
}
