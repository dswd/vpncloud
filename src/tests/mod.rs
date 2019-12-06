// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[macro_use]
mod helper;
mod nat;
mod payload;
mod peers;

pub use std::net::SocketAddr;
use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Once
    }
};

pub use super::{
    cloud::GenericCloud,
    config::Config,
    crypto::Crypto,
    device::MockDevice,
    ethernet::{self, SwitchTable},
    ip::{self, RoutingTable},
    net::MockSocket,
    types::{Protocol, Range, Table},
    udpmessage::Message,
    util::MockTimeSource
};


static INIT_LOGGER: Once = Once::new();

pub fn init_debug_logger() {
    INIT_LOGGER.call_once(|| {
        log::set_boxed_logger(Box::new(DebugLogger)).unwrap();
        log::set_max_level(log::LevelFilter::Debug);
    })
}

struct DebugLogger;

impl log::Log for DebugLogger {
    #[inline]
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{} - {}", record.level(), record.args());
        }
    }

    #[inline]
    fn flush(&self) {
        std::io::stderr().flush().expect("Failed to flush")
    }
}


type TestNode<P, T> = GenericCloud<MockDevice, P, T, MockSocket, MockTimeSource>;

type TapTestNode = TestNode<ethernet::Frame, SwitchTable<MockTimeSource>>;
#[allow(dead_code)]
type TunTestNode = TestNode<ip::Packet, RoutingTable>;


thread_local! {
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(1);
}

fn create_tap_node(nat: bool) -> TapTestNode {
    create_tap_node_with_config(nat, Config::default())
}

fn create_tap_node_with_config(nat: bool, mut config: Config) -> TapTestNode {
    MockSocket::set_nat(nat);
    config.port = NEXT_PORT.with(|p| p.fetch_add(1, Ordering::Relaxed)) as u16;
    TestNode::new(&config, MockDevice::new(), SwitchTable::new(1800, 10), true, true, vec![], Crypto::None, None, None)
}

#[allow(dead_code)]
fn create_tun_node(nat: bool, addresses: Vec<Range>) -> TunTestNode {
    MockSocket::set_nat(nat);
    TestNode::new(
        &Config { port: NEXT_PORT.with(|p| p.fetch_add(1, Ordering::Relaxed)) as u16, ..Config::default() },
        MockDevice::new(),
        RoutingTable::new(),
        false,
        false,
        addresses,
        Crypto::None,
        None,
        None
    )
}


fn msg4_get<P: Protocol, T: Table>(node: &mut TestNode<P, T>) -> (SocketAddr, Vec<u8>) {
    let msg = node.socket4().pop_outbound();
    assert!(msg.is_some());
    msg.unwrap()
}

#[allow(dead_code)]
fn msg6_get<P: Protocol, T: Table>(node: &mut TestNode<P, T>) -> (SocketAddr, Vec<u8>) {
    let msg = node.socket6().pop_outbound();
    assert!(msg.is_some());
    msg.unwrap()
}

fn msg4_put<P: Protocol, T: Table>(node: &mut TestNode<P, T>, from: SocketAddr, msg: Vec<u8>) {
    if node.socket4().put_inbound(from, msg) {
        node.trigger_socket_v4_event();
    }
}

fn msg6_put<P: Protocol, T: Table>(node: &mut TestNode<P, T>, from: SocketAddr, msg: Vec<u8>) {
    if node.socket6().put_inbound(from, msg) {
        node.trigger_socket_v6_event();
    }
}

fn simulate<P: Protocol, T: Table>(nodes: &mut [(&mut TestNode<P, T>, SocketAddr)]) {
    for (ref mut node, ref _from_addr) in nodes.iter_mut() {
        while node.device().has_inbound() {
            node.trigger_device_event();
        }
    }
    let mut clean = false;
    while !clean {
        clean = true;
        let mut msgs = Vec::new();
        for (ref mut node, ref from_addr) in nodes.iter_mut() {
            while let Some((to_addr, msg)) = node.socket4().pop_outbound() {
                msgs.push((msg, *from_addr, to_addr));
            }
        }
        clean &= msgs.is_empty();
        for (msg, from_addr, to_addr) in msgs {
            for (ref mut node, ref addr) in nodes.iter_mut() {
                if *addr == to_addr {
                    msg4_put(node, from_addr, msg);
                    break
                }
            }
        }
        let mut msgs = Vec::new();
        for (ref mut node, ref from_addr) in nodes.iter_mut() {
            while let Some((to_addr, msg)) = node.socket6().pop_outbound() {
                msgs.push((msg, *from_addr, to_addr));
            }
        }
        clean &= msgs.is_empty();
        for (msg, from_addr, to_addr) in msgs {
            for (ref mut node, ref addr) in nodes.iter_mut() {
                if *addr == to_addr {
                    msg6_put(node, from_addr, msg);
                    break
                }
            }
        }
    }
}
