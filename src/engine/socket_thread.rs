use super::{shared::SharedData, SPACE_BEFORE};
use crate::{
    config::DEFAULT_PEER_TIMEOUT,
    crypto::{is_init_message, MessageResult, PeerCrypto},
    engine::{addr_nice, resolve, Hash, PeerData},
    error::Error,
    messages::{AddrList, NodeInfo, PeerInfo},
    net::{mapped_addr, Socket},
    table::ClaimTable,
    traffic::TrafficStats,
    types::{NodeId, RangeList},
    util::{MsgBuffer, Time, TimeSource},
    Config, Crypto, Device, Protocol
};
use rand::{random, seq::SliceRandom, thread_rng};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::HashMap,
    fmt,
    io::Cursor,
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc
};

pub struct SocketThread<S: Socket, D: Device, P: Protocol, TS: TimeSource> {
    // Read-only fields
    node_id: NodeId,
    claims: RangeList,
    config: Config,
    peer_timeout_publish: u16,
    learning: bool,
    _dummy_ts: PhantomData<TS>,
    _dummy_p: PhantomData<P>,
    // Socket-only fields
    socket: S,
    device: D,
    next_housekeep: Time,
    own_addresses: AddrList,
    pending_inits: HashMap<SocketAddr, PeerCrypto<NodeInfo>, Hash>,
    // Shared fields
    shared: Arc<SharedData>,
    traffic: TrafficStats,
    peers: HashMap<SocketAddr, PeerData, Hash>,
    crypto: Crypto,
    table: ClaimTable<TS>
}

impl<S: Socket, D: Device, P: Protocol, TS: TimeSource> SocketThread<S, D, P, TS> {
    #[inline]
    fn send_to(&mut self, addr: SocketAddr, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        self.traffic.count_out_traffic(addr, msg.len());
        match self.socket.send(msg.message(), addr) {
            Ok(written) if written == msg.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e))
        }
    }

    fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let addr = mapped_addr(addr);
        if self.peers.contains_key(&addr)
            || self.own_addresses.contains(&addr)
            || self.pending_inits.contains_key(&addr)
        {
            return Ok(())
        }
        debug!("Connecting to {:?}", addr);
        let payload = self.create_node_info();
        let mut peer_crypto = self.crypto.peer_instance(payload);
        let mut msg = MsgBuffer::new(SPACE_BEFORE);
        peer_crypto.initialize(&mut msg)?;
        self.pending_inits.insert(addr, peer_crypto);
        self.send_to(addr, &mut msg)
    }

    pub fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        let addrs = resolve(&addr)?.into_iter().map(mapped_addr).collect::<SmallVec<[SocketAddr; 3]>>();
        for addr in &addrs {
            if self.own_addresses.contains(addr)
                || self.peers.contains_key(addr)
                || self.pending_inits.contains_key(addr)
            {
                return Ok(())
            }
        }
        // Send a message to each resolved address
        for a in addrs {
            // Ignore error this time
            self.connect_sock(a).ok();
        }
        Ok(())
    }

    fn create_node_info(&self) -> NodeInfo {
        let mut peers = smallvec![];
        for peer in self.peers.values() {
            peers.push(PeerInfo { node_id: Some(peer.node_id), addrs: peer.addrs.clone() })
        }
        if peers.len() > 20 {
            let mut rng = rand::thread_rng();
            peers.partial_shuffle(&mut rng, 20);
            peers.truncate(20);
        }
        NodeInfo {
            node_id: self.node_id,
            peers,
            claims: self.claims.clone(),
            peer_timeout: Some(self.peer_timeout_publish),
            addrs: self.own_addresses.clone()
        }
    }

    fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.last_seen = TS::now();
            peer.timeout = TS::now() + self.config.peer_timeout as Time
        } else {
            error!("Received peer update from non peer {}", addr_nice(addr));
            return Ok(())
        }
        if let Some(info) = info {
            debug!("Adding claims of peer {}: {:?}", addr_nice(addr), info.claims);
            self.table.set_claims(addr, info.claims);
            debug!("Received {} peers from {}: {:?}", info.peers.len(), addr_nice(addr), info.peers);
            self.connect_to_peers(&info.peers)?;
        }
        Ok(())
    }

    fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<(), Error> {
        info!("Added peer {}", addr_nice(addr));
        if let Some(init) = self.pending_inits.remove(&addr) {
            self.peers.insert(addr, PeerData {
                addrs: info.addrs.clone(),
                crypto: init,
                node_id: info.node_id,
                peer_timeout: info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                last_seen: TS::now(),
                timeout: TS::now() + self.config.peer_timeout as Time
            });
            self.update_peer_info(addr, Some(info))?;
        } else {
            error!("No init for new peer {}", addr_nice(addr));
        }
        Ok(())
    }

    fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.peers.contains_key(addr) {
                    continue 'outer
                }
            }
            if let Some(node_id) = peer.node_id {
                if self.node_id == node_id {
                    continue 'outer
                }
                for p in self.peers.values() {
                    if p.node_id == node_id {
                        continue 'outer
                    }
                }
            }
            self.connect(&peer.addrs as &[SocketAddr])?;
        }
        Ok(())
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        if let Some(_peer) = self.peers.remove(&addr) {
            info!("Closing connection to {}", addr_nice(addr));
            self.table.remove_claims(addr);
        }
    }

    fn handle_payload_from(&mut self, peer: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let (src, dst) = P::parse(data.message())?;
        let len = data.len();
        debug!("Writing data to device: {} bytes", len);
        self.traffic.count_in_payload(src, dst, len);
        if let Err(e) = self.device.write(data) {
            error!("Failed to send via device: {}", e);
            return Err(e)
        }
        if self.learning {
            // Learn single address
            self.table.cache(src, peer);
        }
        Ok(())
    }

    fn process_message(
        &mut self, src: SocketAddr, msg_result: MessageResult<NodeInfo>, data: &mut MsgBuffer
    ) -> Result<(), Error> {
        match msg_result {
            MessageResult::Message(type_) => {
                match type_ {
                    MESSAGE_TYPE_DATA => self.handle_payload_from(src, data)?,
                    MESSAGE_TYPE_NODE_INFO => {
                        let info = match NodeInfo::decode(Cursor::new(data.message())) {
                            Ok(val) => val,
                            Err(err) => {
                                self.traffic.count_invalid_protocol(data.len());
                                return Err(err)
                            }
                        };
                        self.update_peer_info(src, Some(info))?
                    }
                    MESSAGE_TYPE_KEEPALIVE => self.update_peer_info(src, None)?,
                    MESSAGE_TYPE_CLOSE => self.remove_peer(src),
                    _ => {
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(Error::Message("Unknown message type"))
                    }
                }
            }
            MessageResult::Initialized(info) => self.add_new_peer(src, info)?,
            MessageResult::InitializedWithReply(info) => {
                self.add_new_peer(src, info)?;
                self.send_to(src, data)?
            }
            MessageResult::Reply => self.send_to(src, data)?,
            MessageResult::None => ()
        }
        Ok(())
    }

    fn handle_message(&mut self, src: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let src = mapped_addr(src);
        debug!("Received {} bytes from {}", data.len(), src);
        let msg_result = if let Some(init) = self.pending_inits.get_mut(&src) {
            init.handle_message(data)
        } else if is_init_message(data.message()) {
            let mut result = None;
            if let Some(peer) = self.peers.get_mut(&src) {
                if peer.crypto.has_init() {
                    result = Some(peer.crypto.handle_message(data))
                }
            }
            if let Some(result) = result {
                result
            } else {
                let mut init = self.crypto.peer_instance(self.create_node_info());
                let msg_result = init.handle_message(data);
                match msg_result {
                    Ok(res) => {
                        self.pending_inits.insert(src, init);
                        Ok(res)
                    }
                    Err(err) => {
                        self.traffic.count_invalid_protocol(data.len());
                        return Err(err)
                    }
                }
            }
        } else if let Some(peer) = self.peers.get_mut(&src) {
            peer.crypto.handle_message(data)
        } else {
            info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
            self.traffic.count_invalid_protocol(data.len());
            return Ok(())
        };
        match msg_result {
            Ok(val) => self.process_message(src, val, data),
            Err(err) => {
                self.traffic.count_invalid_protocol(data.len());
                Err(err)
            }
        }
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        // TODO: sync
        unimplemented!();
    }

    pub fn run(mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        loop {
            let src = try_fail!(self.socket.receive(&mut buffer), "Failed to read from network socket: {}");
            match self.handle_message(src, &mut buffer) {
                Err(e @ Error::CryptoInitFatal(_)) => {
                    debug!("Fatal crypto init error from {}: {}", src, e);
                    info!("Closing pending connection to {} due to error in crypto init", addr_nice(src));
                    self.pending_inits.remove(&src);
                }
                Err(e @ Error::CryptoInit(_)) => {
                    debug!("Recoverable init error from {}: {}", src, e);
                    info!("Ignoring invalid init message from peer {}", addr_nice(src));
                }
                Err(e) => {
                    error!("{}", e);
                }
                Ok(_) => {}
            }
            let now = TS::now();
            if self.next_housekeep < TS::now() {
                if let Err(e) = self.housekeep() {
                    error!("{}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
    }
}
