// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::*;

#[test]
fn connect_nat_2_peers() {
    init_debug_logger();
    MockTimeSource::set_time(0);
    let mut node1 = create_tap_node(true);
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node(false);
    let node2_addr = addr!("2.3.4.5:6789");

    node2.connect("1.2.3.4:5678").unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));


    node1.connect("2.3.4.5:6789").unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_connected!(node1, node2);
}

#[test]
fn connect_nat_3_peers() {
    init_debug_logger();
    MockTimeSource::set_time(0);
    let mut node1 = create_tap_node(true);
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node(false);
    let node2_addr = addr!("2.3.4.5:6789");
    let mut node3 = create_tap_node(false);
    let node3_addr = addr!("3.4.5.6:7890");
    node2.connect("1.2.3.4:5678").unwrap();
    node3.connect("1.2.3.4:5678").unwrap();
    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));
    assert!(!node3.peers().contains_node(&node1.node_id()));
    assert!(!node3.peers().contains_node(&node2.node_id()));
    assert!(!node1.peers().contains_node(&node3.node_id()));
    assert!(!node2.peers().contains_node(&node3.node_id()));

    node1.connect("3.4.5.6:7890").unwrap();
    node2.connect("3.4.5.6:7890").unwrap();

    simulate_time!(1000, node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert_connected!(node1, node3);
    assert_connected!(node2, node3);
    assert_connected!(node1, node2);
}

#[test]
fn nat_keepalive() {
    init_debug_logger();
    MockTimeSource::set_time(0);
    let mut node1 = create_tap_node(true);
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node(false);
    let node2_addr = addr!("2.3.4.5:6789");
    let mut node3 = create_tap_node(false);
    let node3_addr = addr!("3.4.5.6:7890");
    node1.connect("3.4.5.6:7890").unwrap();
    node2.connect("3.4.5.6:7890").unwrap();

    simulate_time!(1000, node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert_connected!(node1, node3);
    assert_connected!(node2, node3);
    assert_connected!(node1, node2);

    simulate_time!(10000, node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert_connected!(node1, node3);
    assert_connected!(node2, node3);
    assert_connected!(node1, node2);
}
