// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

#[test]
async fn direct_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn direct_connect_unencrypted() {
    let config = Config {
        crypto: CryptoConfig { algorithms: vec!["plain".to_string()], ..CryptoConfig::default() },
        ..Config::default()
    };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn cross_connect() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;
    let node3 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.simulate_all_messages().await;

    sim.simulate_time(120).await;

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));
}

#[test]
async fn connect_via_beacons() {
    let mut sim = TapSimulator::new();
    let beacon_path = "target/.vpncloud_test";
    let config1 = Config { beacon_store: Some(beacon_path.to_string()), ..Default::default() };
    let node1 = sim.add_node(false, &config1).await;
    let config2 = Config { beacon_load: Some(beacon_path.to_string()), ..Default::default() };
    let node2 = sim.add_node(false, &config2).await;

    sim.set_time(100);
    sim.trigger_node_housekeep(node1).await;
    sim.trigger_node_housekeep(node2).await;
    sim.simulate_all_messages().await;

    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn reconnect_after_timeout() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    sim.set_time(5000);
    sim.trigger_housekeep().await;
    assert!(!sim.is_connected(node1, node2));
    assert!(!sim.is_connected(node2, node1));

    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn lost_init_ping() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.drop_message(); // drop init ping

    sim.simulate_time(120).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn lost_init_pong() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.simulate_next_message().await; // init ping
    sim.drop_message(); // drop init pong

    sim.simulate_time(120).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
async fn lost_init_peng() {
    let config = Config::default();
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2);
    sim.simulate_next_message().await; // init ping
    sim.simulate_next_message().await; // init pong
    sim.drop_message(); // drop init peng

    sim.simulate_time(120).await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
}

#[test]
#[ignore]
async fn peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
async fn lost_peer_exchange() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
async fn remove_dead_peers() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
async fn update_primary_address() {
    // TODO Test
    unimplemented!()
}

#[test]
#[ignore]
async fn automatic_peer_timeout() {
    // TODO Test
    unimplemented!()
}
