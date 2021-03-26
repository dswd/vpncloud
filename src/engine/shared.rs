use crate::{
    config::Config,
    crypto::CryptoCore,
    engine::common::Hash,
    error::Error,
    table::ClaimTable,
    traffic::{TrafficEntry, TrafficStats},
    types::{Address, RangeList},
    util::{Duration, MsgBuffer, TimeSource},
};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    io::{self, Write},
    net::SocketAddr,
    sync::Arc,
};

use super::common::PeerData;

#[derive(Clone)]
pub struct SharedPeerCrypto {
    peers: Arc<Mutex<HashMap<SocketAddr, Option<Arc<CryptoCore>>, Hash>>>,
}

impl SharedPeerCrypto {
    pub fn new() -> Self {
        SharedPeerCrypto { peers: Arc::new(Mutex::new(HashMap::default())) }
    }

    pub fn encrypt_for(&self, peer: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let mut peers = self.peers.lock();
        match peers.get_mut(&peer) {
            None => Err(Error::InvalidCryptoState("No crypto found for peer")),
            Some(None) => Ok(()),
            Some(Some(crypto)) => {
                crypto.encrypt(data);
                Ok(())
            }
        }
    }

    pub fn store(&self, data: &HashMap<SocketAddr, PeerData, Hash>) {
        let mut peers = self.peers.lock();
        peers.clear();
        peers.extend(data.iter().map(|(k, v)| (*k, v.crypto.get_core())));
    }

    pub fn load(&mut self) {
        // TODO sync if needed
    }

    pub fn get_snapshot(&self) -> HashMap<SocketAddr, Option<Arc<CryptoCore>>, Hash> {
        self.peers.lock().clone()
    }

    pub fn count(&self) -> usize {
        self.peers.lock().len()
    }
}

#[derive(Clone)]
pub struct SharedTraffic {
    traffic: Arc<Mutex<TrafficStats>>,
}

impl SharedTraffic {
    pub fn new() -> Self {
        Self { traffic: Arc::new(Mutex::new(Default::default())) }
    }

    pub fn sync(&mut self) {
        // TODO sync if needed
    }

    pub fn count_out_traffic(&self, peer: SocketAddr, bytes: usize) {
        self.traffic.lock().count_out_traffic(peer, bytes);
    }

    pub fn count_in_traffic(&self, peer: SocketAddr, bytes: usize) {
        self.traffic.lock().count_in_traffic(peer, bytes);
    }

    pub fn count_out_payload(&self, remote: Address, local: Address, bytes: usize) {
        self.traffic.lock().count_out_payload(remote, local, bytes);
    }

    pub fn count_in_payload(&self, remote: Address, local: Address, bytes: usize) {
        self.traffic.lock().count_in_payload(remote, local, bytes);
    }

    pub fn count_dropped_payload(&self, bytes: usize) {
        self.traffic.lock().count_dropped_payload(bytes);
    }

    pub fn count_invalid_protocol(&self, bytes: usize) {
        self.traffic.lock().count_invalid_protocol(bytes);
    }

    pub fn period(&mut self, cleanup_idle: Option<usize>) {
        self.traffic.lock().period(cleanup_idle)
    }

    pub fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        self.traffic.lock().write_out(out)
    }

    pub fn total_peer_traffic(&self) -> TrafficEntry {
        self.traffic.lock().total_peer_traffic()
    }

    pub fn total_payload_traffic(&self) -> TrafficEntry {
        self.traffic.lock().total_payload_traffic()
    }

    pub fn dropped(&self) -> TrafficEntry {
        self.traffic.lock().dropped.clone()
    }
}

#[derive(Clone)]
pub struct SharedTable<TS: TimeSource> {
    table: Arc<Mutex<ClaimTable<TS>>>,
}

impl<TS: TimeSource> SharedTable<TS> {
    pub fn new(config: &Config) -> Self {
        let table = ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration);
        SharedTable { table: Arc::new(Mutex::new(table)) }
    }

    pub fn sync(&mut self) {
        // TODO sync if needed
    }

    pub fn lookup(&mut self, addr: Address) -> Option<SocketAddr> {
        self.table.lock().lookup(addr)
    }

    pub fn set_claims(&mut self, peer: SocketAddr, claims: RangeList) {
        self.table.lock().set_claims(peer, claims)
    }

    pub fn remove_claims(&mut self, peer: SocketAddr) {
        self.table.lock().remove_claims(peer)
    }

    pub fn cache(&mut self, addr: Address, peer: SocketAddr) {
        self.table.lock().cache(addr, peer)
    }

    pub fn housekeep(&mut self) {
        self.table.lock().housekeep()
    }

    pub fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        self.table.lock().write_out(out)
    }

    pub fn cache_len(&self) -> usize {
        self.table.lock().cache_len()
    }

    pub fn claim_len(&self) -> usize {
        self.table.lock().claim_len()
    }
}
