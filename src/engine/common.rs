use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fs::File, hash::BuildHasherDefault};
use tokio;

use fnv::FnvHasher;

use crate::{
    config::Config,
    crypto::PeerCrypto,
    device::Device,
    engine::{
        device_thread::DeviceThread,
        shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
        socket_thread::{ReconnectEntry, SocketThread},
    },
    error::Error,
    messages::AddrList,
    net::Socket,
    payload::Protocol,
    port_forwarding::PortForwarding,
    types::NodeId,
    util::{resolve, Time, TimeSource},
};

pub type Hash = BuildHasherDefault<FnvHasher>;

pub const STATS_INTERVAL: Time = 60;
pub const SPACE_BEFORE: usize = 100;

pub struct PeerData {
    pub addrs: AddrList,
    #[allow(dead_code)] // TODO: export in status
    pub last_seen: Time,
    pub timeout: Time,
    pub peer_timeout: u16,
    pub node_id: NodeId,
    pub crypto: PeerCrypto,
}

pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    socket_thread: SocketThread<S, D, P, TS>,
    device_thread: DeviceThread<S, D, P, TS>,
    running: Arc<AtomicBool>,
}

impl<D: Device, P: Protocol, S: Socket, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>,
    ) -> Result<Self, Error> {
        let table = SharedTable::<TS>::new(&config);
        let traffic = SharedTraffic::new();
        let peer_crypto = SharedPeerCrypto::new();
        let running = Arc::new(AtomicBool::new(true));
        let device_thread = DeviceThread::<S, D, P, TS>::new(
            config.clone(),
            device.duplicate().await?,
            socket.clone(),
            traffic.clone(),
            peer_crypto.clone(),
            table.clone(),
            running.clone(),
        );
        let mut socket_thread = SocketThread::<S, D, P, TS>::new(
            config.clone(),
            device,
            socket,
            traffic,
            peer_crypto,
            table,
            port_forwarding,
            stats_file,
            running.clone(),
        );
        socket_thread.housekeep().await?;
        Ok(Self { socket_thread, device_thread, running })
    }

    pub fn add_peer(&mut self, addr: String) -> Result<(), Error> {
        let resolved = resolve(addr.clone())?;
        self.socket_thread.reconnect_peers.push(ReconnectEntry {
            address: Some((addr, TS::now())),
            resolved,
            tries: 0,
            timeout: 1,
            next: TS::now(),
            final_timeout: None,
        });
        Ok(())
    }

    pub async fn run(self) {
        debug!("Starting threads");
        let running = self.running.clone();
        let device_thread_handle = tokio::spawn(self.device_thread.run());
        let socket_thread_handle = tokio::spawn(self.socket_thread.run());
        try_fail!(tokio::signal::ctrl_c().await, "Failed to set ctrl-c handler: {}");
        running.store(false, Ordering::SeqCst);
        debug!("Waiting for threads to end");
        let (dev_ret, sock_ret) = join!(device_thread_handle, socket_thread_handle);
        dev_ret.unwrap();
        sock_ret.unwrap();
        debug!("Threads stopped");
    }
}

#[cfg(test)]
use crate::device::MockDevice;
#[cfg(test)]
use crate::net::MockSocket;
#[cfg(test)]
use crate::util::MockTimeSource;
#[cfg(test)]
use std::net::SocketAddr;

#[cfg(test)]
impl<P: Protocol> GenericCloud<MockDevice, P, MockSocket, MockTimeSource> {
    pub fn socket(&mut self) -> &mut MockSocket {
        &mut self.socket_thread.socket
    }

    pub fn device(&mut self) -> &mut MockDevice {
        &mut self.device_thread.device
    }

    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), Error> {
        self.socket_thread.connect(addr).await
    }

    pub async fn trigger_socket_event(&mut self) {
        self.socket_thread.iteration().await
    }

    pub async fn trigger_device_event(&mut self) {
        self.device_thread.iteration().await
    }

    pub async fn trigger_housekeep(&mut self) {
        try_fail!(self.socket_thread.housekeep().await, "Housekeep failed: {}");
        try_fail!(self.device_thread.housekeep().await, "Housekeep failed: {}");
    }

    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.socket_thread.peers.contains_key(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.socket_thread.own_addresses
    }

    pub async fn get_num(&self) -> usize {
        self.socket_thread.socket.address().await.unwrap().port() as usize
    }
}
