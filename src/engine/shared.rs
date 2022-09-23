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
#[allow(clippy::type_complexity)]
pub struct SharedPeerCrypto {
    peers: Arc<Mutex<HashMap<SocketAddr, Option<Arc<CryptoCore>>, Hash>>>,
    cache: HashMap<SocketAddr, Option<Arc<CryptoCore>>, Hash>, //TODO: local hashmap as cache
}

impl SharedPeerCrypto {
    pub fn new() -> Self {
        SharedPeerCrypto { peers: Arc::new(Mutex::new(HashMap::default())), cache: HashMap::default() }
    }

    pub fn encrypt_for(&mut self, peer: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let crypto = match self.cache.get(&peer) {
            Some(crypto) => crypto,
            None => {
                let peers = self.peers.lock();
                if let Some(crypto) = peers.get(&peer) {
                    self.cache.insert(peer, crypto.clone());
                    self.cache.get(&peer).unwrap()
                } else {
                    return Err(Error::InvalidCryptoState("No crypto found for peer"));
                }
            }
        };
        if let Some(crypto) = crypto {
            crypto.encrypt(data);
        }
        Ok(())
    }

    pub fn store(&mut self, data: &HashMap<SocketAddr, PeerData, Hash>) {
        self.cache.clear();
        self.cache.extend(data.iter().map(|(k, v)| (*k, v.crypto.get_core())));
        let mut peers = self.peers.lock();
        peers.clear();
        peers.extend(self.cache.iter().map(|(k, v)| (*k, v.clone())));
    }

    pub fn load(&mut self) {
        let peers = self.peers.lock();
        self.cache.clear();
        self.cache.extend(peers.iter().map(|(k, v)| (*k, v.clone())));
    }

    pub fn get_snapshot(&mut self) -> &HashMap<SocketAddr, Option<Arc<CryptoCore>>, Hash> {
        &self.cache
    }

    pub fn count(&self) -> usize {
        self.cache.len()
    }
}

pub struct SharedTraffic {
    cache: TrafficStats,
    traffic: Arc<Mutex<TrafficStats>>,
}

impl Clone for SharedTraffic {
    fn clone(&self) -> Self {
        Self { cache: TrafficStats::default(), traffic: self.traffic.clone() }
    }
}

impl SharedTraffic {
    pub fn new() -> Self {
        Self { cache: TrafficStats::default(), traffic: Arc::new(Mutex::new(Default::default())) }
    }

    pub fn sync(&mut self) {
        self.traffic.lock().add(&self.cache);
        self.cache.clear();
    }

    pub fn count_out_traffic(&mut self, peer: SocketAddr, bytes: usize) {
        self.cache.count_out_traffic(peer, bytes);
    }

    pub fn count_in_traffic(&mut self, peer: SocketAddr, bytes: usize) {
        self.cache.count_in_traffic(peer, bytes);
    }

    pub fn count_out_payload(&mut self, remote: Address, local: Address, bytes: usize) {
        self.cache.count_out_payload(remote, local, bytes);
    }

    pub fn count_in_payload(&mut self, remote: Address, local: Address, bytes: usize) {
        self.cache.count_in_payload(remote, local, bytes);
    }

    pub fn count_dropped_payload(&mut self, bytes: usize) {
        self.cache.count_dropped_payload(bytes);
    }

    pub fn count_invalid_protocol(&mut self, bytes: usize) {
        self.cache.count_invalid_protocol(bytes);
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
    cache: HashMap<Address, Option<SocketAddr>, Hash>,
}

impl<TS: TimeSource> SharedTable<TS> {
    pub fn new(config: &Config) -> Self {
        let table = ClaimTable::new(config.switch_timeout as Duration, config.peer_timeout as Duration);
        SharedTable { table: Arc::new(Mutex::new(table)), cache: Default::default() }
    }

    pub fn sync(&mut self) {
        self.cache.clear();
    }

    pub fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        if let Some(val) = self.cache.get(addr) {
            return *val;
        }
        // if not found, use shared table and put into cache
        let val = self.table.lock().lookup(addr);
        self.cache.insert(addr.clone(), val);
        val
    }

    pub fn set_claims(&mut self, peer: SocketAddr, claims: RangeList) {
        self.table.lock().set_claims(peer, claims);
        self.cache.clear();
    }

    pub fn remove_claims(&mut self, peer: SocketAddr) {
        self.table.lock().remove_claims(peer);
        self.cache.clear();
    }

    pub fn cache(&mut self, addr: &Address, peer: SocketAddr) {
        if self.cache.get(addr) != Some(&Some(peer)) {
            self.table.lock().cache(addr.clone(), peer);
            self.cache.insert(addr.clone(), Some(peer));
        }
    }

    pub fn housekeep(&mut self) {
        self.table.lock().housekeep();
        self.cache.clear();
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
