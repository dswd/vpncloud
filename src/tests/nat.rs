// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

#[test]
fn connect_nat_2_peers() {
    let config = Config { port_forwarding: false, ..Default::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config);
    let node2 = sim.add_node(true, &config);

    sim.connect(node1, node2);
    sim.connect(node2, node1);

    sim.simulate_time(60);

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn connect_nat_3_peers() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config);
    let node2 = sim.add_node(true, &config);
    let node3 = sim.add_node(true, &config);

    sim.connect(node1, node2);
    sim.connect(node2, node1);
    sim.connect(node1, node3);
    sim.connect(node3, node1);

    sim.simulate_time(300);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}

#[test]
fn nat_keepalive() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config);
    let node2 = sim.add_node(true, &config);
    let node3 = sim.add_node(true, &config);

    sim.connect(node1, node2);
    sim.connect(node2, node1);
    sim.connect(node1, node3);
    sim.connect(node3, node1);

    sim.simulate_time(1000);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    sim.simulate_time(10000);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}
