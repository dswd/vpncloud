// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

#[test]
fn direct_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn direct_connect_unencrypted() {
    let config = Config {
        crypto: CryptoConfig { algorithms: vec!["plain".to_string()], ..CryptoConfig::default() },
        ..Config::default()
    };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn cross_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    let node3 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.simulate_all_messages();

    sim.simulate_time(120);

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}

#[test]
fn connect_via_beacons() {
    let mut sim = TapSimulator::new();
    let beacon_path = "target/.vpncloud_test";
    let config1 = Config { beacon_store: Some(beacon_path.to_string()), ..Default::default() };
    let node1 = sim.add_node(false, &config1);
    let config2 = Config { beacon_load: Some(beacon_path.to_string()), ..Default::default() };
    let node2 = sim.add_node(false, &config2);

    sim.set_time(100);
    sim.trigger_node_housekeep(node1);
    sim.trigger_node_housekeep(node2);
    sim.simulate_all_messages();

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn reconnect_after_timeout() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    sim.set_time(5000);
    sim.trigger_housekeep();
    assert!(!sim.is_connected(node1, node2));
    assert!(!sim.is_connected(node2, node1));

    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_ping() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.drop_message(); // drop init ping

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_pong() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_next_message(); // init ping
    sim.drop_message(); // drop init pong

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
fn lost_init_peng() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_next_message(); // init ping
    sim.simulate_next_message(); // init pong
    sim.drop_message(); // drop init peng

    sim.simulate_time(120);
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
#[ignore]
fn peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn lost_peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn remove_dead_peers() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn update_primary_address() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
fn automatic_peer_timeout() {
    // TODO Test
    unimplemented!()
}
