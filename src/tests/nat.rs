// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

#[test]
async fn connect_nat_2_peers() {
    let config = Config { port_forwarding: false, ..Default::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config).await;
    let node2 = sim.add_node(true, &config).await;

    sim.connect(node1, node2).await;
    sim.connect(node2, node1).await;

    sim.simulate_time(60).await;

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn connect_nat_3_peers() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config).await;
    let node2 = sim.add_node(true, &config).await;
    let node3 = sim.add_node(true, &config).await;

    sim.connect(node1, node2).await;
    sim.connect(node2, node1).await;
    sim.connect(node1, node3).await;
    sim.connect(node3, node1).await;

    sim.simulate_time(300).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}

#[test]
async fn nat_keepalive() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(true, &config).await;
    let node2 = sim.add_node(true, &config).await;
    let node3 = sim.add_node(true, &config).await;

    sim.connect(node1, node2).await;
    sim.connect(node2, node1).await;
    sim.connect(node1, node3).await;
    sim.connect(node3, node1).await;

    sim.simulate_time(1000).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    sim.simulate_time(10000).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}
