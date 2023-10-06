use std::thread;
use std::{fs::File, hash::BuildHasherDefault};

use fnv::FnvHasher;

use crate::util::CtrlC;
use crate::{
    config::Config,
    device::Device,
    engine::{
        coms::Coms,
        device_thread::DeviceThread,
        extras_thread::ExtrasThread,
        housekeep_thread::HousekeepThread,
        shared::SharedConfig,
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
    //pub crypto: PeerCrypto,
}

pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    config: SharedConfig,
    socket_thread: SocketThread<S, D, P, TS>,
    device_thread: DeviceThread<S, D, P, TS>,
    housekeep_thread: HousekeepThread<S, P, TS>,
    extras_thread: ExtrasThread<S, P, TS>,
}

impl<D: Device, P: Protocol, S: Socket, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>,
    ) -> Result<Self, Error> {
        let config = SharedConfig::new(config.clone());
        let coms = Coms::<S, TS, P>::new(
            config.get_config(),
            socket.try_clone().map_err(|e| Error::SocketIo("Failed to clone socket", e))?,
        );
        let device_thread = DeviceThread::<S, D, P, TS>::new(config.clone(), device.duplicate()?, coms.try_clone()?);
        let housekeep_thread = HousekeepThread::<S, P, TS>::new(config.clone(), coms.try_clone()?);
        let extras_thread = ExtrasThread::<S, P, TS>::new(config.clone(), coms.try_clone()?);
        let mut socket_thread =
            SocketThread::<S, D, P, TS>::new(config.clone(), coms, device, port_forwarding, stats_file);
        socket_thread.housekeep()?;
        Ok(Self { socket_thread, device_thread, config, housekeep_thread, extras_thread })
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

    pub fn run(self) {
        debug!("Starting threads");
        let config = self.config;
        let device = self.device_thread;
        let device_thread_handle = thread::spawn(move || device.run());
        let socket = self.socket_thread;
        let socket_thread_handle = thread::spawn(move || socket.run());
        let housekeep = self.housekeep_thread;
        let housekeep_thread_handle = thread::spawn(move || housekeep.run());
        let extras = self.extras_thread;
        let extras_thread_handle = thread::spawn(move || extras.run());
        let ctrlc = CtrlC::new();
        ctrlc.wait();
        config.stop();
        debug!("Waiting for threads to end");
        device_thread_handle.join().unwrap();
        socket_thread_handle.join().unwrap();
        housekeep_thread_handle.join().unwrap();
        extras_thread_handle.join().unwrap();
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
        &mut self.socket_thread.coms.socket
    }

    pub fn device(&mut self) -> &mut MockDevice {
        &mut self.device_thread.device
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), Error> {
        self.socket_thread.connect(addr)
    }

    pub fn trigger_socket_event(&mut self) {
        self.socket_thread.iteration();
    }

    pub fn trigger_device_event(&mut self) {
        self.device_thread.iteration();
    }

    pub fn trigger_housekeep(&mut self) {
        try_fail!(self.socket_thread.housekeep(), "Housekeep failed: {}");
        try_fail!(self.device_thread.housekeep(), "Housekeep failed: {}");
    }

    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.socket_thread.coms.has_peer(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        &self.socket_thread.own_addresses
    }

    pub fn get_num(&self) -> usize {
        self.socket_thread.coms.socket.address().unwrap().port() as usize
    }
}
