// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::*;

#[test]
fn ethernet_delivers() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node2));
}

#[test]
fn switch_learns() {
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();
    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);
    let node3 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.connect(node1, node3);
    sim.connect(node2, node3);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    assert!(sim.is_connected(node1, node3));
    assert!(sim.is_connected(node3, node1));
    assert!(sim.is_connected(node2, node3));
    assert!(sim.is_connected(node3, node2));

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    sim.put_payload(node1, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload.clone()), sim.pop_payload(node2));
    assert_eq!(Some(payload), sim.pop_payload(node3));

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    sim.put_payload(node2, payload.clone());
    sim.simulate_all_messages();

    assert_eq!(Some(payload), sim.pop_payload(node1));
    assert_eq!(None, sim.pop_payload(node3));
}

#[test]
fn switch_honours_vlans() {
    // TODO Test
}

#[test]
fn switch_forgets() {
    // TODO Test
}

#[test]
fn router_delivers() {
    // TODO Test
}

#[test]
fn router_drops_unknown_dest() {
    // TODO Test
}
