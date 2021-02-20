// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

mod device_thread;
mod shared;
mod socket_thread;

use std::{fs::File, hash::BuildHasherDefault, thread};

use fnv::FnvHasher;

use crate::{
    config::Config,
    crypto::PeerCrypto,
    device::Device,
    engine::{
        device_thread::DeviceThread,
        shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
        socket_thread::SocketThread
    },
    error::Error,
    messages::AddrList,
    net::Socket,
    payload::Protocol,
    port_forwarding::PortForwarding,
    types::NodeId,
    util::{addr_nice, resolve, CtrlC, Time, TimeSource}
};

pub type Hash = BuildHasherDefault<FnvHasher>;

pub const STATS_INTERVAL: Time = 60;
const SPACE_BEFORE: usize = 100;

struct PeerData {
    addrs: AddrList,
    #[allow(dead_code)] // TODO: export in status
    last_seen: Time,
    timeout: Time,
    peer_timeout: u16,
    node_id: NodeId,
    crypto: PeerCrypto
}

#[derive(Clone)]
pub struct ReconnectEntry {
    address: Option<(String, Time)>,
    resolved: AddrList,
    tries: u16,
    timeout: u16,
    next: Time,
    final_timeout: Option<Time>
}


pub struct GenericCloud<D: Device, P: Protocol, S: Socket, TS: TimeSource> {
    socket_thread: SocketThread<S, D, P, TS>,
    device_thread: DeviceThread<S, D, P, TS>
}

impl<D: Device, P: Protocol, S: Socket, TS: TimeSource> GenericCloud<D, P, S, TS> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config, socket: S, device: D, port_forwarding: Option<PortForwarding>, stats_file: Option<File>
    ) -> Self {
        let table = SharedTable::<TS>::new(&config);
        let traffic = SharedTraffic::new();
        let peer_crypto = SharedPeerCrypto::new();
        let device_thread = DeviceThread::<S, D, P, TS>::new(
            config.clone(),
            device.clone(),
            socket.clone(),
            traffic.clone(),
            peer_crypto.clone(),
            table.clone()
        );
        let socket_thread = SocketThread::<S, D, P, TS>::new(
            config.clone(),
            device,
            socket,
            traffic,
            peer_crypto,
            table,
            port_forwarding,
            stats_file
        );
        Self { socket_thread, device_thread }
    }

    pub fn add_peer(&mut self, addr: String) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn run(self) {
        // TODO: spawn threads
        let ctrlc = CtrlC::new();
        let device_thread = self.device_thread;
        let device_thread_handle = thread::spawn(move || device_thread.run());
        let socket_thread = self.socket_thread;
        let socket_thread_handle = thread::spawn(move || socket_thread.run());
        // TODO: wait for ctrl-c
        device_thread_handle.join().unwrap();
        socket_thread_handle.join().unwrap();
    }
}


#[cfg(test)] use super::device::MockDevice;
#[cfg(test)] use super::net::MockSocket;
#[cfg(test)] use super::util::{MockTimeSource, MsgBuffer};
#[cfg(test)] use std::net::SocketAddr;

#[cfg(test)]
impl<P: Protocol> GenericCloud<MockDevice, P, MockSocket, MockTimeSource> {
    pub fn socket(&mut self) -> &mut MockSocket {
        unimplemented!()
        //&mut self.socket
    }

    pub fn device(&mut self) -> &mut MockDevice {
        unimplemented!()
        //&mut self.device
    }

    pub fn trigger_socket_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        unimplemented!()
    }

    pub fn trigger_device_event(&mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        unimplemented!()
    }

    pub fn trigger_housekeep(&mut self) {
        unimplemented!()
    }

    pub fn is_connected(&self, addr: &SocketAddr) -> bool {
        unimplemented!()
        // self.peers.contains_key(addr)
    }

    pub fn own_addresses(&self) -> &[SocketAddr] {
        unimplemented!()
        //&self.own_addresses
    }

    pub fn get_num(&self) -> usize {
        unimplemented!()
        // self.socket.address().unwrap().port() as usize
    }
}
