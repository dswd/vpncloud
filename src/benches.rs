// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use test::Bencher;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket},
    str::FromStr
};

use super::{
    cloud::GenericCloud,
    config::Config,
    crypto::{Crypto, CryptoMethod},
    device::{TunTapDevice, Type},
    ethernet::{self, SwitchTable},
    ip::Packet,
    net::MockSocket,
    poll::WaitImpl,
    types::{Address, Protocol, Table},
    udpmessage::{decode, encode, Message},
    util::{MockTimeSource, SystemTimeSource, TimeSource},
    MAGIC
};

#[bench]
fn crypto_chacha20(b: &mut Bencher) {
    let mut crypto = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    let mut payload = [0; 1500];
    let header = [0; 8];
    let mut nonce_bytes = [0; 12];
    b.iter(|| {
        let len = crypto.encrypt(&mut payload, 1400, &mut nonce_bytes, &header);
        assert!(crypto.decrypt(&mut payload[..len], &nonce_bytes, &header).is_ok())
    });
    b.bytes = 1400;
}

#[bench]
fn crypto_aes256(b: &mut Bencher) {
    let mut crypto = Crypto::from_shared_key(CryptoMethod::AES256, "test");
    let mut payload = [0; 1500];
    let header = [0; 8];
    let mut nonce_bytes = [0; 12];
    b.iter(|| {
        let len = crypto.encrypt(&mut payload, 1400, &mut nonce_bytes, &header);
        assert!(crypto.decrypt(&mut payload[..len], &nonce_bytes, &header).is_ok());
    });
    b.bytes = 1400;
}

#[bench]
fn message_encode(b: &mut Bencher) {
    let mut crypto = Crypto::None;
    let mut payload = [0; 1600];
    let mut msg = Message::Data(&mut payload, 64, 1464);
    let mut buf = [0; 1600];
    b.iter(|| {
        encode(&mut msg, &mut buf[..], MAGIC, &mut crypto);
    });
    b.bytes = 1400;
}

#[bench]
fn message_decode(b: &mut Bencher) {
    let mut crypto = Crypto::None;
    let mut payload = [0; 1600];
    let mut msg = Message::Data(&mut payload, 64, 1464);
    let mut buf = [0; 1600];
    let mut res = encode(&mut msg, &mut buf[..], MAGIC, &mut crypto);
    b.iter(|| {
        decode(&mut res, MAGIC, &mut crypto).unwrap();
    });
    b.bytes = 1400;
}

#[bench]
fn switch_learn(b: &mut Bencher) {
    let mut table = SwitchTable::<SystemTimeSource>::new(10, 0);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    b.iter(|| {
        table.learn(addr.clone(), None, peer);
    });
    b.bytes = 1400;
}

#[bench]
fn switch_lookup(b: &mut Bencher) {
    let mut table = SwitchTable::<SystemTimeSource>::new(10, 0);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    table.learn(addr.clone(), None, peer);
    b.iter(|| {
        table.lookup(&addr);
    });
    b.bytes = 1400;
}

#[bench]
fn ethernet_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[5] = 45;
    b.iter(|| ethernet::Frame::parse(&data).unwrap());
    b.bytes = 1400;
}

#[bench]
fn ipv4_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[0] = 4 * 16;
    b.iter(|| Packet::parse(&data).unwrap());
    b.bytes = 1400;
}

#[bench]
fn ipv6_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[0] = 6 * 16;
    b.iter(|| Packet::parse(&data).unwrap());
    b.bytes = 1400;
}

#[bench]
fn now(b: &mut Bencher) {
    b.iter(|| SystemTimeSource::now());
    b.bytes = 1400;
}

#[bench]
fn epoll_wait(b: &mut Bencher) {
    let socket = UdpSocket::bind("[::]:0").unwrap();
    let device = TunTapDevice::dummy("dummy", "/dev/zero", Type::Dummy).unwrap();
    let mut waiter = WaitImpl::testing(&socket, &device, 1000).unwrap();
    b.iter(|| assert!(waiter.next().is_some()));
    b.bytes = 1400;
}

type TestNode = GenericCloud<TunTapDevice, ethernet::Frame, SwitchTable<MockTimeSource>, MockSocket, MockTimeSource>;

fn create_test_node() -> TestNode {
    TestNode::new(
        &Config::default(),
        TunTapDevice::dummy("dummy", "/dev/null", Type::Tap).unwrap(),
        SwitchTable::new(1800, 10),
        true,
        true,
        vec![],
        Crypto::None,
        None,
        None
    )
}

#[bench]
fn handle_interface_data(b: &mut Bencher) {
    let mut node = create_test_node();
    let mut data = [0; 1500];
    data[105] = 45;
    b.iter(|| node.handle_interface_data(&mut data, 100, 1400).unwrap());
    b.bytes = 1400;
}

#[bench]
fn handle_net_message(b: &mut Bencher) {
    let mut node = create_test_node();
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1));
    let mut data = [0; 1500];
    data[105] = 45;
    b.iter(|| node.handle_net_message(addr.clone(), Message::Data(&mut data, 0, 1400)).unwrap());
    b.bytes = 1400;
}

#[bench]
fn udp_send(b: &mut Bencher) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let data = [0; 1400];
    let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1);
    b.iter(|| sock.send_to(&data, &addr).unwrap());
    b.bytes = 1400;
}
