// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::*;

#[test]
fn connect_v4() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.3.4.5:6789");
    assert_clean!(node1, node2);
    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));

    node1.connect("2.3.4.5:6789").unwrap();

    // Node 1 -> Node 2: Init 0
    assert_message4!(node1, node1_addr, node2, node2_addr, Message::Init(0, node1.node_id(), vec![]));
    assert_clean!(node1);
    assert!(node2.peers().contains_node(&node1.node_id()));

    // Node 2 -> Node 1: Init 1 | Node 2 -> Node 1: Peers
    assert_message4!(node2, node2_addr, node1, node1_addr, Message::Init(1, node2.node_id(), vec![]));
    assert!(node1.peers().contains_node(&node2.node_id()));
    assert_message4!(node2, node2_addr, node1, node1_addr, Message::Peers(vec![node1_addr]));
    assert_clean!(node2);

    // Node 1 -> Node 2: Peers | Node 1 -> Node 1: Init 0
    assert_message4!(node1, node1_addr, node2, node2_addr, Message::Peers(vec![node2_addr]));
    assert_message4!(node1, node1_addr, node1, node1_addr, Message::Init(0, node1.node_id(), vec![]));
    assert!(node1.own_addresses().contains(&node1_addr));
    assert_clean!(node1);

    // Node 2 -> Node 2: Init 0
    assert_message4!(node2, node2_addr, node2, node2_addr, Message::Init(0, node2.node_id(), vec![]));
    assert_clean!(node2);
    assert!(node2.own_addresses().contains(&node2_addr));

    assert_connected!(node1, node2);
}

#[test]
fn connect_v6() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("[::1]:5678");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("[::2]:6789");

    node1.connect("[::2]:6789").unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_connected!(node1, node2);
}

#[test]
fn cross_connect() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.1.1.1:1111");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.2.2.2:2222");
    let mut node3 = create_tap_node();
    let node3_addr = addr!("3.3.3.3:3333");
    let mut node4 = create_tap_node();
    let node4_addr = addr!("4.4.4.4:4444");

    node1.connect("2.2.2.2:2222").unwrap();
    node3.connect("4.4.4.4:4444").unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr, node4 => node4_addr);

    assert_connected!(node1, node2);
    assert_connected!(node3, node4);

    node1.connect("3.3.3.3:3333").unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr, node4 => node4_addr);

    // existing connections
    assert_connected!(node1, node2);
    assert_connected!(node3, node4);

    // new connection
    assert_connected!(node1, node3);

    // transient connections 1st degree
    assert_connected!(node1, node4);
    assert_connected!(node3, node2);

    // transient connections 2nd degree
    assert_connected!(node2, node4);
}

#[test]
fn connect_via_beacons() {
    MockTimeSource::set_time(0);
    let beacon_path = "target/.vpncloud_test";
    let mut node1 = create_tap_node_with_config(Config { beacon_store: Some(beacon_path.to_string()), ..Config::default()});
    let node1_addr = node1.address().unwrap().0;
    let mut node2 = create_tap_node_with_config(Config { beacon_load: Some(beacon_path.to_string()), ..Config::default()});
    let node2_addr = addr!("2.2.2.2:2222");

    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));

    MockTimeSource::set_time(5000);
    node1.trigger_housekeep();

    MockTimeSource::set_time(10000);
    node2.trigger_housekeep();

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_clean!(node1, node2);
    assert_connected!(node1, node2);
}

#[test]
fn reconnect_after_timeout() {
    MockTimeSource::set_time(0);
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.1.1.1:1111");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.2.2.2:2222");

    node1.add_reconnect_peer("2.2.2.2:2222".to_string());
    node1.connect(node2_addr).unwrap();

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_connected!(node1, node2);

    MockTimeSource::set_time(5000);
    node1.trigger_housekeep();
    node2.trigger_housekeep();

    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_connected!(node1, node2);
}

#[test]
fn lost_init1() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.3.4.5:6789");

    node1.connect("2.3.4.5:6789").unwrap();

    // Node 1 -> Node 2: Init 0
    assert_message4!(node1, node1_addr, node2, node2_addr, Message::Init(0, node1.node_id(), vec![]));
    assert_clean!(node1);

    // Node 2 -> Node 1: Init 1 | Node 2 -> Node 1: Peers
    assert!(node2.socket4().pop_outbound().is_some());
    assert!(!node1.peers().contains_node(&node2.node_id()));

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_connected!(node1, node2);

}

#[test]
fn wrong_magic() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node_with_config(Config { magic: Some("hash:different".to_string()), ..Config::default()});
    let node2_addr = addr!("2.3.4.5:6789");
    node1.connect("2.3.4.5:6789").unwrap();

    assert_message4!(node1, node1_addr, node2, node2_addr, Message::Init(0, node1.node_id(), vec![]));

    assert_clean!(node1, node2);

    assert!(!node1.peers().contains_node(&node2.node_id()));
    assert!(!node2.peers().contains_node(&node1.node_id()));
}

#[test]
fn peer_exchange() {
    //TODO
}

#[test]
fn lost_peer_exchange() {
    //TODO
}

#[test]
fn remove_dead_peers() {
    //TODO
}

#[test]
fn update_primary_address() {
    //TODO
}

