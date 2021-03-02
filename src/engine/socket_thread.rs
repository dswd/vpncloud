use super::{
    shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
    SPACE_BEFORE,
};

use crate::{
    beacon::BeaconSerializer,
    config::{DEFAULT_PEER_TIMEOUT, DEFAULT_PORT},
    crypto::{is_init_message, InitResult, InitState, MessageResult},
    device::Type,
    engine::{addr_nice, resolve, Hash, PeerData},
    error::Error,
    messages::{
        AddrList, NodeInfo, PeerInfo, MESSAGE_TYPE_CLOSE, MESSAGE_TYPE_DATA, MESSAGE_TYPE_KEEPALIVE,
        MESSAGE_TYPE_NODE_INFO,
    },
    net::{mapped_addr, Socket},
    port_forwarding::PortForwarding,
    types::{Address, NodeId, Range, RangeList},
    util::{MsgBuffer, StatsdMsg, Time, TimeSource},
    Config, Crypto, Device, Protocol,
};
use rand::{random, seq::SliceRandom, thread_rng};
use smallvec::{smallvec, SmallVec};
use std::{
    cmp::{max, min},
    collections::HashMap,
    fmt,
    fs::File,
    io,
    io::{Cursor, Seek, SeekFrom, Write},
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};
use tokio::time::timeout;

const MAX_RECONNECT_INTERVAL: u16 = 3600;
const RESOLVE_INTERVAL: Time = 300;
const OWN_ADDRESS_RESET_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;

#[derive(Clone)]
pub struct ReconnectEntry {
    address: Option<(String, Time)>,
    resolved: AddrList,
    tries: u16,
    timeout: u16,
    next: Time,
    final_timeout: Option<Time>,
}

pub struct SocketThread<S: Socket, D: Device, P: Protocol, TS: TimeSource> {
    // Read-only fields
    node_id: NodeId,
    claims: RangeList,
    config: Config,
    peer_timeout_publish: u16,
    learning: bool,
    update_freq: u16,
    _dummy_ts: PhantomData<TS>,
    _dummy_p: PhantomData<P>,
    // Socket-only fields
    pub socket: S,
    device: D,
    next_housekeep: Time,
    own_addresses: AddrList,
    next_own_address_reset: Time,
    pending_inits: HashMap<SocketAddr, InitState<NodeInfo>, Hash>,
    crypto: Crypto,
    peers: HashMap<SocketAddr, PeerData, Hash>,
    next_peers: Time,
    next_stats_out: Time,
    next_beacon: Time,
    beacon_serializer: BeaconSerializer<TS>,
    stats_file: Option<File>,
    statsd_server: Option<String>,
    reconnect_peers: SmallVec<[ReconnectEntry; 3]>,
    buffer: MsgBuffer,
    broadcast_buffer: MsgBuffer,
    // Shared fields
    peer_crypto: SharedPeerCrypto,
    traffic: SharedTraffic,
    table: SharedTable<TS>,
    // Should not be here
    port_forwarding: Option<PortForwarding>, // TODO: 3rd thread
}

impl<S: Socket, D: Device, P: Protocol, TS: TimeSource> SocketThread<S, D, P, TS> {
    pub fn new(
        config: Config, device: D, socket: S, traffic: SharedTraffic, peer_crypto: SharedPeerCrypto,
        table: SharedTable<TS>, port_forwarding: Option<PortForwarding>, stats_file: Option<File>,
    ) -> Self {
        let mut claims = SmallVec::with_capacity(config.claims.len());
        for s in &config.claims {
            claims.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
        }
        if device.get_type() == Type::Tun && config.auto_claim {
            match device.get_ip() {
                Ok(ip) => {
                    let range = Range { base: Address::from_ipv4(ip), prefix_len: 32 };
                    info!("Auto-claiming {} due to interface address", range);
                    claims.push(range);
                }
                Err(Error::DeviceIo(_, e)) if e.kind() == io::ErrorKind::AddrNotAvailable => {
                    info!("No address set on interface.")
                }
                Err(e) => error!("{}", e),
            }
        }
        let now = TS::now();
        let update_freq = config.get_keepalive() as u16;
        let node_id = random();
        let crypto = Crypto::new(node_id, &config.crypto).unwrap();
        let beacon_key = config.beacon_password.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        Self {
            _dummy_p: PhantomData,
            _dummy_ts: PhantomData,
            node_id,
            claims,
            device,
            socket,
            peer_crypto,
            traffic,
            table,
            learning: config.is_learning(),
            next_housekeep: now,
            next_beacon: now,
            next_peers: now,
            next_stats_out: now + STATS_INTERVAL,
            next_own_address_reset: now + OWN_ADDRESS_RESET_INTERVAL,
            pending_inits: HashMap::default(),
            reconnect_peers: SmallVec::new(),
            own_addresses: SmallVec::new(),
            peers: HashMap::default(),
            peer_timeout_publish: config.peer_timeout as u16,
            beacon_serializer: BeaconSerializer::new(beacon_key),
            port_forwarding,
            stats_file,
            update_freq,
            statsd_server: config.statsd_server.clone(),
            crypto: Crypto::new(node_id, &config.crypto).unwrap(),
            config,
            buffer: MsgBuffer::new(SPACE_BEFORE),
            broadcast_buffer: MsgBuffer::new(SPACE_BEFORE),
        }
    }

    #[inline]
    async fn send_to(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let size = self.buffer.len();
        debug!("Sending msg with {} bytes to {}", size, addr);
        self.traffic.count_out_traffic(addr, size);
        match self.socket.send(self.buffer.message(), addr).await {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e)),
        }
    }

    #[inline]
    async fn broadcast_msg(&mut self, type_: u8) -> Result<(), Error> {
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, self.buffer.len(), self.peers.len());
        for (addr, peer) in &mut self.peers {
            self.broadcast_buffer.set_start(self.buffer.get_start());
            self.broadcast_buffer.set_length(self.buffer.len());
            self.broadcast_buffer.message_mut().clone_from_slice(self.buffer.message());
            self.broadcast_buffer.prepend_byte(type_);
            peer.crypto.encrypt_message(&mut self.broadcast_buffer);
            self.traffic.count_out_traffic(*addr, self.broadcast_buffer.len());
            match self.socket.send(self.broadcast_buffer.message(), *addr).await {
                Ok(written) if written == self.broadcast_buffer.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e)),
            }?
        }
        Ok(())
    }

    async fn connect_sock(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let addr = mapped_addr(addr);
        if self.peers.contains_key(&addr)
            || self.own_addresses.contains(&addr)
            || self.pending_inits.contains_key(&addr)
        {
            return Ok(());
        }
        debug!("Connecting to {:?}", addr);
        let payload = self.create_node_info();
        let mut init = self.crypto.peer_instance(payload);
        init.send_ping(&mut self.buffer);
        self.pending_inits.insert(addr, init);
        self.send_to(addr).await
    }

    pub async fn connect<Addr: ToSocketAddrs + fmt::Debug + Clone>(&mut self, addr: Addr) -> Result<(), Error> {
        let addrs = resolve(&addr)?.into_iter().map(mapped_addr).collect::<SmallVec<[SocketAddr; 3]>>();
        for addr in &addrs {
            if self.own_addresses.contains(addr)
                || self.peers.contains_key(addr)
                || self.pending_inits.contains_key(addr)
            {
                return Ok(());
            }
        }
        // Send a message to each resolved address
        for a in addrs {
            // Ignore error this time
            self.connect_sock(a).await.ok();
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
            addrs: self.own_addresses.clone(),
        }
    }

    async fn update_peer_info(&mut self, addr: SocketAddr, info: Option<NodeInfo>) -> Result<(), Error> {
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.last_seen = TS::now();
            peer.timeout = TS::now() + self.config.peer_timeout as Time
        } else {
            error!("Received peer update from non peer {}", addr_nice(addr));
            return Ok(());
        }
        if let Some(info) = info {
            debug!("Adding claims of peer {}: {:?}", addr_nice(addr), info.claims);
            self.table.set_claims(addr, info.claims);
            debug!("Received {} peers from {}: {:?}", info.peers.len(), addr_nice(addr), info.peers);
            self.connect_to_peers(&info.peers).await?;
        }
        Ok(())
    }

    async fn add_new_peer(&mut self, addr: SocketAddr, info: NodeInfo) -> Result<(), Error> {
        info!("Added peer {}", addr_nice(addr));
        if let Some(init) = self.pending_inits.remove(&addr) {
            self.buffer.clear();
            let crypto = init.finish(&mut self.buffer);
            self.peers.insert(
                addr,
                PeerData {
                    addrs: info.addrs.clone(),
                    crypto,
                    node_id: info.node_id,
                    peer_timeout: info.peer_timeout.unwrap_or(DEFAULT_PEER_TIMEOUT),
                    last_seen: TS::now(),
                    timeout: TS::now() + self.config.peer_timeout as Time,
                },
            );
            self.update_peer_info(addr, Some(info)).await?;
            if !self.buffer.is_empty() {
                self.send_to(addr).await?;
            }
        } else {
            error!("No init for new peer {}", addr_nice(addr));
        }
        Ok(())
    }

    async fn connect_to_peers(&mut self, peers: &[PeerInfo]) -> Result<(), Error> {
        'outer: for peer in peers {
            for addr in &peer.addrs {
                if self.peers.contains_key(addr) {
                    continue 'outer;
                }
            }
            if let Some(node_id) = peer.node_id {
                if self.node_id == node_id {
                    continue 'outer;
                }
                for p in self.peers.values() {
                    if p.node_id == node_id {
                        continue 'outer;
                    }
                }
            }
            self.connect(&peer.addrs as &[SocketAddr]).await?;
        }
        Ok(())
    }

    fn remove_peer(&mut self, addr: SocketAddr) {
        if let Some(_peer) = self.peers.remove(&addr) {
            info!("Closing connection to {}", addr_nice(addr));
            self.table.remove_claims(addr);
        }
    }

    async fn handle_payload_from(&mut self, peer: SocketAddr) -> Result<(), Error> {
        let (src, dst) = P::parse(self.buffer.message())?;
        let len = self.buffer.len();
        debug!("Writing data to device: {} bytes", len);
        self.traffic.count_in_payload(src, dst, len);
        if let Err(e) = self.device.write(&mut self.buffer).await {
            error!("Failed to send via device: {}", e);
            return Err(e);
        }
        if self.learning {
            // Learn single address
            self.table.cache(src, peer);
        }
        Ok(())
    }

    async fn process_message(&mut self, src: SocketAddr, msg_result: MessageResult) -> Result<(), Error> {
        match msg_result {
            MessageResult::Message(type_) => match type_ {
                MESSAGE_TYPE_DATA => self.handle_payload_from(src).await?,
                MESSAGE_TYPE_NODE_INFO => {
                    let info = match NodeInfo::decode(Cursor::new(self.buffer.message())) {
                        Ok(val) => val,
                        Err(err) => {
                            self.traffic.count_invalid_protocol(self.buffer.len());
                            return Err(err);
                        }
                    };
                    self.update_peer_info(src, Some(info)).await?
                }
                MESSAGE_TYPE_KEEPALIVE => self.update_peer_info(src, None).await?,
                MESSAGE_TYPE_CLOSE => self.remove_peer(src),
                _ => {
                    self.traffic.count_invalid_protocol(self.buffer.len());
                    return Err(Error::Message("Unknown message type"));
                }
            },
            MessageResult::Reply => self.send_to(src).await?,
            MessageResult::None => (),
        }
        Ok(())
    }

    async fn handle_message(&mut self, src: SocketAddr) -> Result<(), Error> {
        let src = mapped_addr(src);
        debug!("Received {} bytes from {}", self.buffer.len(), src);
        let buffer = &mut self.buffer;
        if let Some(result) = self.peers.get_mut(&src).map(|peer| peer.crypto.handle_message(buffer)) {
            return self.process_message(src, result?).await;
        }
        let is_init = is_init_message(buffer.message());
        if let Some(result) = self.pending_inits.get_mut(&src).map(|init| {
            if is_init {
                init.handle_init(buffer)
            } else {
                buffer.clear();
                init.repeat_last_message(buffer);
                Ok(InitResult::Continue)
            }
        }) {
            match result? {
                InitResult::Continue => {
                    if !buffer.is_empty() {
                        self.send_to(src).await?
                    }
                }
                InitResult::Success { peer_payload, .. } => self.add_new_peer(src, peer_payload).await?,
            }
            return Ok(());
        }
        if !is_init_message(self.buffer.message()) {
            info!("Ignoring non-init message from unknown peer {}", addr_nice(src));
            self.traffic.count_invalid_protocol(self.buffer.len());
            return Ok(());
        }
        let mut init = self.crypto.peer_instance(self.create_node_info());
        let msg_result = init.handle_init(&mut self.buffer);
        match msg_result {
            Ok(_) => {
                self.pending_inits.insert(src, init);
                self.send_to(src).await
            }
            Err(err) => {
                self.traffic.count_invalid_protocol(self.buffer.len());
                Err(err)
            }
        }
    }

    pub async fn housekeep(&mut self) -> Result<(), Error> {
        let now = TS::now();
        let mut del: SmallVec<[SocketAddr; 3]> = SmallVec::new();
        for (&addr, ref data) in &self.peers {
            if data.timeout < now {
                del.push(addr);
            }
        }
        for addr in del {
            info!("Forgot peer {} due to timeout", addr_nice(addr));
            self.peers.remove(&addr);
            self.table.remove_claims(addr);
            self.connect_sock(addr).await?; // Try to reconnect
        }
        self.table.housekeep();
        self.crypto_housekeep().await?;
        // Periodically extend the port-forwarding
        if let Some(ref mut pfw) = self.port_forwarding {
            pfw.check_extend();
        }
        let now = TS::now();
        // Periodically reset own peers
        if self.next_own_address_reset <= now {
            self.reset_own_addresses().await.map_err(|err| Error::SocketIo("Failed to get own addresses", err))?;
            self.next_own_address_reset = now + OWN_ADDRESS_RESET_INTERVAL;
        }
        // Periodically send peer list to peers
        if self.next_peers <= now {
            debug!("Send peer list to all peers");
            let info = self.create_node_info();
            info.encode(&mut self.buffer);
            self.broadcast_msg(MESSAGE_TYPE_NODE_INFO).await?;
            // Reschedule for next update
            let min_peer_timeout = self.peers.iter().map(|p| p.1.peer_timeout).min().unwrap_or(DEFAULT_PEER_TIMEOUT);
            let interval = min(self.update_freq as u16, max(min_peer_timeout / 2 - 60, 1));
            self.next_peers = now + Time::from(interval);
        }
        self.reconnect_to_peers().await?;
        if self.next_stats_out < now {
            // Write out the statistics
            self.write_out_stats().map_err(|err| Error::FileIo("Failed to write stats file", err))?;
            self.send_stats_to_statsd().await?;
            self.next_stats_out = now + STATS_INTERVAL;
            self.traffic.period(Some(5));
        }
        if let Some(peers) = self.beacon_serializer.get_cmd_results() {
            debug!("Loaded beacon with peers: {:?}", peers);
            for peer in peers {
                self.connect_sock(peer).await?;
            }
        }
        if self.next_beacon < now {
            self.store_beacon()?;
            self.load_beacon().await?;
            self.next_beacon = now + Time::from(self.config.beacon_interval);
        }
        // TODO: sync peer_crypto
        self.table.sync();
        self.traffic.sync();
        unimplemented!();
    }

    async fn crypto_housekeep(&mut self) -> Result<(), Error> {
        let mut del: SmallVec<[SocketAddr; 4]> = smallvec![];
        for addr in self.pending_inits.keys().copied().collect::<SmallVec<[SocketAddr; 4]>>() {
            self.buffer.clear();
            if self.pending_inits.get_mut(&addr).unwrap().every_second(&mut self.buffer).is_err() {
                del.push(addr)
            } else if !self.buffer.is_empty() {
                self.send_to(addr).await?
            }
        }
        for addr in self.peers.keys().copied().collect::<SmallVec<[SocketAddr; 16]>>() {
            self.buffer.clear();
            self.peers.get_mut(&addr).unwrap().crypto.every_second(&mut self.buffer);
            if !self.buffer.is_empty() {
                self.send_to(addr).await?
            }
        }
        for addr in del {
            self.pending_inits.remove(&addr);
            if self.peers.remove(&addr).is_some() {
                self.connect_sock(addr).await?;
            }
        }
        Ok(())
    }

    async fn reset_own_addresses(&mut self) -> io::Result<()> {
        self.own_addresses.clear();
        self.own_addresses.push(self.socket.address().await.map(mapped_addr)?);
        if let Some(ref pfw) = self.port_forwarding {
            self.own_addresses.push(pfw.get_internal_ip().into());
            self.own_addresses.push(pfw.get_external_ip().into());
        }
        debug!("Own addresses: {:?}", self.own_addresses);
        // TODO: detect address changes and call event
        Ok(())
    }

    /// Stores the beacon
    fn store_beacon(&mut self) -> Result<(), Error> {
        if let Some(ref path) = self.config.beacon_store {
            let peers: SmallVec<[SocketAddr; 3]> =
                self.own_addresses.choose_multiple(&mut thread_rng(), 3).cloned().collect();
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .write_to_cmd(&peers, path)
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
            } else {
                self.beacon_serializer
                    .write_to_file(&peers, &path)
                    .map_err(|e| Error::BeaconIo("Failed to write beacon to file", e))?;
            }
        }
        Ok(())
    }

    /// Loads the beacon
    async fn load_beacon(&mut self) -> Result<(), Error> {
        let peers;
        if let Some(ref path) = self.config.beacon_load {
            if let Some(path) = path.strip_prefix('|') {
                self.beacon_serializer
                    .read_from_cmd(path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to call beacon command", e))?;
                return Ok(());
            } else {
                peers = self
                    .beacon_serializer
                    .read_from_file(&path, Some(50))
                    .map_err(|e| Error::BeaconIo("Failed to read beacon from file", e))?;
            }
        } else {
            return Ok(());
        }
        debug!("Loaded beacon with peers: {:?}", peers);
        for peer in peers {
            self.connect_sock(peer).await?;
        }
        Ok(())
    }

    /// Writes out the statistics to a file
    fn write_out_stats(&mut self) -> Result<(), io::Error> {
        if let Some(ref mut f) = self.stats_file {
            debug!("Writing out stats");
            f.seek(SeekFrom::Start(0))?;
            f.set_len(0)?;
            writeln!(f, "peers:")?;
            let now = TS::now();
            for (addr, data) in &self.peers {
                writeln!(
                    f,
                    "  - \"{}\": {{ ttl_secs: {}, crypto: {} }}",
                    addr_nice(*addr),
                    data.timeout - now,
                    data.crypto.algorithm_name()
                )?;
            }
            writeln!(f)?;
            self.table.write_out(f)?;
            writeln!(f)?;
            self.traffic.write_out(f)?;
            writeln!(f)?;
        }
        Ok(())
    }

    /// Sends the statistics to a statsd endpoint
    async fn send_stats_to_statsd(&mut self) -> Result<(), Error> {
        if let Some(ref endpoint) = self.statsd_server {
            let peer_traffic = self.traffic.total_peer_traffic();
            let payload_traffic = self.traffic.total_payload_traffic();
            let dropped = &self.traffic.dropped();
            let prefix = self.config.statsd_prefix.as_ref().map(|s| s as &str).unwrap_or("vpncloud");
            let msg = StatsdMsg::new()
                .with_ns(prefix, |msg| {
                    msg.add("peer_count", self.peers.len(), "g");
                    msg.add("table_cache_entries", self.table.cache_len(), "g");
                    msg.add("table_claims", self.table.claim_len(), "g");
                    msg.with_ns("traffic", |msg| {
                        msg.with_ns("protocol", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", peer_traffic.in_bytes, "c");
                                msg.add("packets", peer_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", peer_traffic.out_bytes, "c");
                                msg.add("packets", peer_traffic.out_packets, "c");
                            });
                        });
                        msg.with_ns("payload", |msg| {
                            msg.with_ns("inbound", |msg| {
                                msg.add("bytes", payload_traffic.in_bytes, "c");
                                msg.add("packets", payload_traffic.in_packets, "c");
                            });
                            msg.with_ns("outbound", |msg| {
                                msg.add("bytes", payload_traffic.out_bytes, "c");
                                msg.add("packets", payload_traffic.out_packets, "c");
                            });
                        });
                    });
                    msg.with_ns("invalid_protocol_traffic", |msg| {
                        msg.add("bytes", dropped.in_bytes, "c");
                        msg.add("packets", dropped.in_packets, "c");
                    });
                    msg.with_ns("dropped_payload", |msg| {
                        msg.add("bytes", dropped.out_bytes, "c");
                        msg.add("packets", dropped.out_packets, "c");
                    });
                })
                .build();
            let msg_data = msg.as_bytes();
            let addrs = resolve(endpoint)?;
            if let Some(addr) = addrs.first() {
                match self.socket.send(msg_data, *addr).await {
                    Ok(written) if written == msg_data.len() => Ok(()),
                    Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                    Err(e) => Err(Error::SocketIo("IOError when sending", e)),
                }?
            } else {
                error!("Failed to resolve statsd server {}", endpoint);
            }
        }
        Ok(())
    }

    async fn reconnect_to_peers(&mut self) -> Result<(), Error> {
        let now = TS::now();
        // Connect to those reconnect_peers that are due
        for entry in self.reconnect_peers.clone() {
            if entry.next > now {
                continue;
            }
            self.connect(&entry.resolved as &[SocketAddr]).await?;
        }
        for entry in &mut self.reconnect_peers {
            // Schedule for next second if node is connected
            for addr in &entry.resolved {
                if self.peers.contains_key(&addr) {
                    entry.tries = 0;
                    entry.timeout = 1;
                    entry.next = now + 1;
                    continue;
                }
            }
            // Resolve entries anew
            if let Some((ref address, ref mut next_resolve)) = entry.address {
                if *next_resolve <= now {
                    match resolve(address as &str) {
                        Ok(addrs) => entry.resolved = addrs,
                        Err(_) => match resolve(&format!("{}:{}", address, DEFAULT_PORT)) {
                            Ok(addrs) => entry.resolved = addrs,
                            Err(err) => warn!("Failed to resolve {}: {}", address, err),
                        },
                    }
                    *next_resolve = now + RESOLVE_INTERVAL;
                }
            }
            // Ignore if next attempt is already in the future
            if entry.next > now {
                continue;
            }
            // Exponential back-off: every 10 tries, the interval doubles
            entry.tries += 1;
            if entry.tries > 10 {
                entry.tries = 0;
                entry.timeout *= 2;
            }
            // Maximum interval is one hour
            if entry.timeout > MAX_RECONNECT_INTERVAL {
                entry.timeout = MAX_RECONNECT_INTERVAL;
            }
            // Schedule next connection attempt
            entry.next = now + Time::from(entry.timeout);
        }
        self.reconnect_peers.retain(|e| e.final_timeout.unwrap_or(now) >= now);
        Ok(())
    }

    pub async fn iteration(&mut self) {
        if let Ok(result) = timeout(std::time::Duration::from_millis(1000), self.socket.receive(&mut self.buffer)).await {
            let src = try_fail!(result, "Failed to read from network socket: {}");
            match self.handle_message(src).await {
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
        }
        let now = TS::now();
        if self.next_housekeep < now {
            if let Err(e) = self.housekeep().await {
                error!("{}", e)
            }
            self.next_housekeep = now + 1
        }
    }

    pub async fn run(mut self) {
        loop {
            self.iteration().await
        }
    }
}
