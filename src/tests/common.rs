// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::{HashMap, VecDeque},
    io::Write,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Once,
    },
};

pub use crate::{
    cloud::GenericCloud,
    config::{Config, CryptoConfig},
    device::{MockDevice, Type},
    net::MockSocket,
    payload::{Frame, Packet, Protocol},
    types::Range,
    util::{MockTimeSource, Time, TimeSource},
};

static INIT_LOGGER: Once = Once::new();

pub fn init_debug_logger() {
    INIT_LOGGER.call_once(|| {
        log::set_boxed_logger(Box::new(DebugLogger)).unwrap();
        log::set_max_level(log::LevelFilter::Debug);
    })
}

static CURRENT_NODE: AtomicUsize = AtomicUsize::new(0);

struct DebugLogger;

impl DebugLogger {
    pub fn set_node(node: usize) {
        CURRENT_NODE.store(node, Ordering::SeqCst);
    }
}

impl log::Log for DebugLogger {
    #[inline]
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        log::max_level() > metadata.level()
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("Node {} - {} - {}", CURRENT_NODE.load(Ordering::SeqCst), record.level(), record.args());
        }
    }

    #[inline]
    fn flush(&self) {
        std::io::stderr().flush().expect("Failed to flush")
    }
}

type TestNode<P> = GenericCloud<MockDevice, P, MockSocket, MockTimeSource>;

pub struct Simulator<P: Protocol> {
    next_port: u16,
    nodes: HashMap<SocketAddr, TestNode<P>>,
    messages: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
}

pub type TapSimulator = Simulator<Frame>;
#[allow(dead_code)]
pub type TunSimulator = Simulator<Packet>;

impl<P: Protocol> Simulator<P> {
    pub fn new() -> Self {
        init_debug_logger();
        MockTimeSource::set_time(0);
        Self { next_port: 1, nodes: HashMap::default(), messages: VecDeque::with_capacity(10) }
    }

    pub fn add_node(&mut self, nat: bool, config: &Config) -> SocketAddr {
        let mut config = config.clone();
        MockSocket::set_nat(nat);
        config.listen = format!("[::]:{}", self.next_port);
        let addr = config.listen.parse::<SocketAddr>().unwrap();
        if config.crypto.password.is_none() && config.crypto.private_key.is_none() {
            config.crypto.password = Some("test123".to_string())
        }
        DebugLogger::set_node(self.next_port as usize);
        self.next_port += 1;
        let node = TestNode::new(&config, MockSocket::new(addr), MockDevice::new(), None, None);
        DebugLogger::set_node(0);
        self.nodes.insert(addr, node);
        addr
    }

    #[allow(dead_code)]
    pub fn get_node(&mut self, addr: SocketAddr) -> &mut TestNode<P> {
        let node = self.nodes.get_mut(&addr).unwrap();
        DebugLogger::set_node(node.get_num());
        node
    }

    pub fn simulate_next_message(&mut self) {
        if let Some((src, dst, data)) = self.messages.pop_front() {
            if let Some(node) = self.nodes.get_mut(&dst) {
                if node.socket().put_inbound(src, data) {
                    DebugLogger::set_node(node.get_num());
                    node.trigger_socket_event();
                    DebugLogger::set_node(0);
                    let sock = node.socket();
                    let src = dst;
                    while let Some((dst, data)) = sock.pop_outbound() {
                        self.messages.push_back((src, dst, data));
                    }
                }
            } else {
                warn!("Message to unknown node {}", dst);
            }
        }
    }

    pub fn simulate_all_messages(&mut self) {
        while !self.messages.is_empty() {
            self.simulate_next_message()
        }
    }

    pub fn trigger_node_housekeep(&mut self, addr: SocketAddr) {
        let node = self.nodes.get_mut(&addr).unwrap();
        DebugLogger::set_node(node.get_num());
        node.trigger_housekeep();
        DebugLogger::set_node(0);
        let sock = node.socket();
        while let Some((dst, data)) = sock.pop_outbound() {
            self.messages.push_back((addr, dst, data));
        }
    }

    pub fn trigger_housekeep(&mut self) {
        for (src, node) in &mut self.nodes {
            DebugLogger::set_node(node.get_num());
            node.trigger_housekeep();
            DebugLogger::set_node(0);
            let sock = node.socket();
            while let Some((dst, data)) = sock.pop_outbound() {
                self.messages.push_back((*src, dst, data));
            }
        }
    }

    pub fn set_time(&mut self, time: Time) {
        MockTimeSource::set_time(time);
    }

    pub fn simulate_time(&mut self, time: Time) {
        let mut t = MockTimeSource::now();
        while t < time {
            t += 1;
            self.set_time(t);
            self.trigger_housekeep();
            self.simulate_all_messages();
        }
    }

    pub fn connect(&mut self, src: SocketAddr, dst: SocketAddr) {
        let node = self.nodes.get_mut(&src).unwrap();
        DebugLogger::set_node(node.get_num());
        node.connect(dst).unwrap();
        DebugLogger::set_node(0);
        let sock = node.socket();
        while let Some((dst, data)) = sock.pop_outbound() {
            self.messages.push_back((src, dst, data));
        }
    }

    pub fn is_connected(&self, src: SocketAddr, dst: SocketAddr) -> bool {
        self.nodes.get(&src).unwrap().is_connected(&dst)
    }

    #[allow(dead_code)]
    pub fn node_addresses(&self) -> Vec<SocketAddr> {
        self.nodes.keys().copied().collect()
    }

    #[allow(dead_code)]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub fn put_payload(&mut self, addr: SocketAddr, data: Vec<u8>) {
        let node = self.nodes.get_mut(&addr).unwrap();
        node.device().put_inbound(data);
        DebugLogger::set_node(node.get_num());
        node.trigger_device_event();
        DebugLogger::set_node(0);
        let sock = node.socket();
        while let Some((dst, data)) = sock.pop_outbound() {
            self.messages.push_back((addr, dst, data));
        }
    }

    pub fn pop_payload(&mut self, node: SocketAddr) -> Option<Vec<u8>> {
        self.nodes.get_mut(&node).unwrap().device().pop_outbound()
    }

    pub fn drop_message(&mut self) {
        self.messages.pop_front();
    }
}
