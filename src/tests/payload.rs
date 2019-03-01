// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::*;

#[test]
fn ethernet_delivers() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.3.4.5:6789");

    node1.connect("2.3.4.5:6789").unwrap();
    simulate!(node1 => node1_addr, node2 => node2_addr);
    assert_connected!(node1, node2);

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    node1.device().put_inbound(payload.clone());

    simulate!(node1 => node1_addr, node2 => node2_addr);

    assert_eq!(Some(payload), node2.device().pop_outbound());

    assert_clean!(node1, node2);
}

#[test]
fn switch_learns() {
    let mut node1 = create_tap_node();
    let node1_addr = addr!("1.2.3.4:5678");
    let mut node2 = create_tap_node();
    let node2_addr = addr!("2.3.4.5:6789");
    let mut node3 = create_tap_node();
    let node3_addr = addr!("3.4.5.6:7890");

    node1.connect("2.3.4.5:6789").unwrap();
    node1.connect("3.4.5.6:7890").unwrap();
    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);
    assert_connected!(node1, node2, node3);

    let payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];

    // Nothing learnt so far, node1 broadcasts

    node1.device().put_inbound(payload.clone());

    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert_eq!(Some(&payload), node2.device().pop_outbound().as_ref());
    assert_eq!(Some(&payload), node3.device().pop_outbound().as_ref());

    let payload = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 5, 4, 3, 2, 1];

    // Node 2 learned the address by receiving it, does not broadcast

    node2.device().put_inbound(payload.clone());

    simulate!(node1 => node1_addr, node2 => node2_addr, node3 => node3_addr);

    assert_eq!(Some(&payload), node1.device().pop_outbound().as_ref());
    assert_clean!(node3);

    assert_clean!(node1, node2, node3);
}

#[test]
fn switch_honours_vlans() {
    //TODO
}

#[test]
fn switch_forgets() {
    //TODO
}

#[test]
fn router_delivers() {
    //TODO
}

#[test]
fn router_drops_unknown_dest() {
    //TODO
}