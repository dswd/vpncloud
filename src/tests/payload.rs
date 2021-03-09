// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::common::*;

#[test]
async fn switch_delivers() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;

    sim.connect(node1, node2).await;
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    sim.put_payload(node1, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
async fn switch_learns() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;
    let node3 = sim.add_node(false, &config).await;

    sim.connect(node1, node2).await;
    sim.connect(node1, node3).await;
    sim.connect(node2, node3).await;
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    sim.put_payload(node1, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload.clone()), sim.pop_payload(node2));
    assert_eq!(Some(payload), sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    sim.put_payload(node2, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload), sim.pop_payload(node1));
    assert_eq!(None, sim.pop_payload(node3));
}

#[test]
async fn switch_honours_vlans() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config).await;
    let node2 = sim.add_node(false, &config).await;
    let node3 = sim.add_node(false, &config).await;

    sim.connect(node1, node2).await;
    sim.connect(node1, node3).await;
    sim.connect(node2, node3).await;
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 0x81, 0, 0, 0x67, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    sim.put_payload(node1, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload.clone()), sim.pop_payload(node2));
    assert_eq!(Some(payload), sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x81, 0, 0, 0x67, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    sim.put_payload(node2, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload), sim.pop_payload(node1));
    assert_eq!(None, sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x81, 0, 0, 0x68, 5, 4, 3, 2, 1];

    // Different VLANs, node 2 does not learn, still broadcasts

    sim.put_payload(node2, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload.clone()), sim.pop_payload(node1));
    assert_eq!(Some(payload), sim.pop_payload(node3));
}

#[test]
#[ignore]
async fn switch_forgets() {
    // TODO Test
    unimplemented!()
}

#[test]
async fn size() {
    let future = async {
        let config1 = Config {
            device_type: Type::Tun,
            auto_claim: false,
            claims: vec!["1.1.1.1/32".to_string()],
            ..Config::default()
        };
        let config2 = Config {
            device_type: Type::Tun,
            auto_claim: false,
            claims: vec!["2.2.2.2/32".to_string()],
            ..Config::default()
        };
        let mut sim = TunSimulator::new();
        let node1 = sim.add_node(false, &config1).await;
        let node2 = sim.add_node(false, &config2).await;

        sim.connect(node1, node2).await;
        sim.simulate_all_messages().await;
        assert!(sim.is_connected(node1, node2));
        assert!(sim.is_connected(node2, node1));

        let payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];

        sim.put_payload(node1, payload.clone()).await;
        sim.simulate_all_messages().await;

        assert_eq!(Some(payload), sim.pop_payload(node2));
    };
    assert_eq!(std::mem::size_of_val(&future), 100);
    future.await
}

#[test]
async fn router_delivers() {
    let config1 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["1.1.1.1/32".to_string()],
        ..Config::default()
    };
    let config2 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["2.2.2.2/32".to_string()],
        ..Config::default()
    };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config1).await;
    let node2 = sim.add_node(false, &config2).await;

    sim.connect(node1, node2).await;
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];

    sim.put_payload(node1, payload.clone()).await;
    sim.simulate_all_messages().await;

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
async fn router_drops_unknown_dest() {
    let config1 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["1.1.1.1/32".to_string()],
        ..Config::default()
    };
    let config2 = Config {
        device_type: Type::Tun,
        auto_claim: false,
        claims: vec!["2.2.2.2/32".to_string()],
        ..Config::default()
    };
    let mut sim = TunSimulator::new();
    let node1 = sim.add_node(false, &config1).await;
    let node2 = sim.add_node(false, &config2).await;

    sim.connect(node1, node2).await;
    sim.simulate_all_messages().await;
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 3, 3, 3, 3];

    sim.put_payload(node1, payload).await;
    sim.simulate_all_messages().await;

    assert_eq!(None, sim.pop_payload(node2));
}
