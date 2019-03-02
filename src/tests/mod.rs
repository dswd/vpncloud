// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[macro_use] mod helper;
mod peers;
mod payload;

pub use std::net::SocketAddr;
use std::sync::atomic::{Ordering, AtomicUsize};

pub use super::ethernet::{self, SwitchTable};
pub use super::util::MockTimeSource;
pub use super::net::MockSocket;
pub use super::device::MockDevice;
pub use super::udpmessage::Message;
pub use super::config::Config;
pub use super::crypto::Crypto;
pub use super::cloud::GenericCloud;
pub use super::types::{Protocol, Table, Range};
pub use super::ip::{self, RoutingTable};


type TestNode<P, T> = GenericCloud<MockDevice, P, T, MockSocket, MockTimeSource>;

type TapTestNode = TestNode<ethernet::Frame, SwitchTable<MockTimeSource>>;
#[allow(dead_code)]
type TunTestNode = TestNode<ip::Packet, RoutingTable>;


thread_local! {
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(1);
}

fn create_tap_node() -> TapTestNode {
    TestNode::new(
        &Config { port: NEXT_PORT.with(|p| p.fetch_add(1, Ordering::Relaxed)) as u16, ..Config::default() },
        MockDevice::new(),
        SwitchTable::new(1800, 10),
        true, true, vec![], Crypto::None, None
    )
}

#[allow(dead_code)]
fn create_tun_node(addresses: Vec<Range>) -> TunTestNode {
    TestNode::new(
        &Config { port: NEXT_PORT.with(|p| p.fetch_add(1, Ordering::Relaxed)) as u16, ..Config::default() },
        MockDevice::new(),
        RoutingTable::new(),
        false, false, addresses, Crypto::None, None
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
    node.socket4().put_inbound(from, msg);
    node.trigger_socket_v4_event();
}

fn msg6_put<P: Protocol, T: Table>(node: &mut TestNode<P, T>, from: SocketAddr, msg: Vec<u8>) {
    node.socket6().put_inbound(from, msg);
    node.trigger_socket_v6_event();
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