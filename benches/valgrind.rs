#![allow(dead_code, unused_macros, unused_imports)]
#[macro_use]
extern crate serde;
#[macro_use]
extern crate log;

use iai::{black_box, main};

use ring::aead;
use smallvec::smallvec;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::str::FromStr;

include!(".code.rs");

use config::Config;
use crypto::core::{create_dummy_pair, EXTRA_LEN};
use device::Type;
pub use error::Error;
use payload::{Frame, Packet, Protocol};
use table::ClaimTable;
use tests::common::{TapSimulator, TunSimulator};
use types::{Address, Range};
use util::{MockTimeSource, MsgBuffer};

fn udp_send() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let data = [0; 1400];
    let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1);
    sock.send_to(&data, &black_box(addr)).unwrap();
}

fn decode_ipv4() {
    let data = [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2];
    Packet::parse(&black_box(data)).unwrap();
}

fn decode_ipv6() {
    let data = [
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1,
    ];
    Packet::parse(&black_box(data)).unwrap();
}

fn decode_ethernet() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8];
    Frame::parse(&black_box(data)).unwrap();
}

fn decode_ethernet_with_vlan() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 0x81, 0, 4, 210, 1, 2, 3, 4, 5, 6, 7, 8];
    Frame::parse(&black_box(data)).unwrap();
}

fn lookup_warm() {
    let mut table = ClaimTable::<MockTimeSource>::new(60, 60);
    let addr = Address::from_str("1.2.3.4").unwrap();
    table.cache(addr.clone(), SocketAddr::from_str("1.2.3.4:3210").unwrap());
    for _ in 0..1000 {
        table.lookup(black_box(&addr));
    }
}

fn lookup_cold() {
    let mut table = ClaimTable::<MockTimeSource>::new(60, 60);
    let addr = Address::from_str("1.2.3.4").unwrap();
    table.set_claims(SocketAddr::from_str("1.2.3.4:3210").unwrap(), smallvec![Range::from_str("1.2.3.4/32").unwrap()]);
    for _ in 0..1000 {
        table.clear_cache();
        table.lookup(black_box(&addr));
    }
}

fn crypto_bench(algo: &'static aead::Algorithm) {
    let mut buffer = MsgBuffer::new(EXTRA_LEN);
    buffer.set_length(1400);
    let (sender, receiver) = create_dummy_pair(algo);
    for _ in 0..1000 {
        sender.encrypt(black_box(&mut buffer));
        receiver.decrypt(&mut buffer).unwrap();
    }
}

fn crypto_chacha20() {
    crypto_bench(&aead::CHACHA20_POLY1305)
}

fn crypto_aes128() {
    crypto_bench(&aead::AES_128_GCM)
}

fn crypto_aes256() {
    crypto_bench(&aead::AES_256_GCM)
}

fn full_communication_tun_router() {
    log::set_max_level(log::LevelFilter::Error);
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
    let node1 = sim.add_node(false, &config1);
    let node2 = sim.add_node(false, &config2);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];
    payload.append(&mut vec![0; 1400]);
    for _ in 0..10000 {
        sim.put_payload(node1, payload.clone());
        sim.simulate_all_messages();
        assert_eq!(Some(&payload), black_box(sim.pop_payload(node2).as_ref()));
    }
}

fn tun_router_send() {
    log::set_max_level(log::LevelFilter::Error);
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
    let node1 = sim.add_node(false, &config1);
    let node2 = sim.add_node(false, &config2);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];
    payload.append(&mut vec![0; 1400]);
    let node = sim.get_node(node1);
    for _ in 0..10000 {
        node.device().put_inbound(black_box(payload.clone()));
        node.trigger_device_event();
        assert!(node.socket().pop_outbound().is_some());
    }
}

fn tun_router_receive() {
    log::set_max_level(log::LevelFilter::Error);
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
    let node1 = sim.add_node(false, &config1);
    let node2 = sim.add_node(false, &config2);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2];
    payload.append(&mut vec![0; 1400]);
    let node = sim.get_node(node1);
    node.device().put_inbound(payload.clone());
    node.trigger_device_event();
    let msg = node.socket().pop_outbound().unwrap().1;
    let node = sim.get_node(node2);
    for _ in 0..10000 {
        node.socket().put_inbound(node1, black_box(msg.clone()));
        node.trigger_socket_event();
        assert!(node.device().pop_outbound().is_some());
    }
}

fn full_communication_tap_switch() {
    log::set_max_level(log::LevelFilter::Error);
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();

    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];
    payload.append(&mut vec![0; 1400]);
    for _ in 0..10000 {
        sim.put_payload(node1, payload.clone());
        sim.simulate_all_messages();
        assert_eq!(Some(&payload), black_box(sim.pop_payload(node2).as_ref()));
    }
}

fn tap_switch_send() {
    log::set_max_level(log::LevelFilter::Error);
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();

    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];
    payload.append(&mut vec![0; 1400]);
    let node = sim.get_node(node1);
    for _ in 0..10000 {
        node.device().put_inbound(black_box(payload.clone()));
        node.trigger_device_event();
        assert!(node.socket().pop_outbound().is_some());
    }
}

fn tap_switch_receive() {
    log::set_max_level(log::LevelFilter::Error);
    let config = Config { device_type: Type::Tap, ..Config::default() };
    let mut sim = TapSimulator::new();

    let node1 = sim.add_node(false, &config);
    let node2 = sim.add_node(false, &config);

    sim.connect(node1, node2);
    sim.simulate_all_messages();
    assert!(sim.is_connected(node1, node2));
    assert!(sim.is_connected(node2, node1));
    sim.trigger_housekeep();

    let mut payload = vec![2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 5];
    payload.append(&mut vec![0; 1400]);
    let node = sim.get_node(node1);
    node.device().put_inbound(payload.clone());
    node.trigger_device_event();
    let msg = node.socket().pop_outbound().unwrap().1;
    let node = sim.get_node(node2);
    for _ in 0..10000 {
        node.socket().put_inbound(node1, black_box(msg.clone()));
        node.trigger_socket_event();
        assert!(node.device().pop_outbound().is_some());
    }
}

iai::main!(
    udp_send,
    decode_ipv4,
    decode_ipv6,
    decode_ethernet,
    decode_ethernet_with_vlan,
    lookup_cold,
    lookup_warm,
    crypto_chacha20,
    crypto_aes128,
    crypto_aes256,
    tun_router_send,
    tun_router_receive,
    full_communication_tun_router,
    tap_switch_send,
    tap_switch_receive,
    full_communication_tap_switch
);
