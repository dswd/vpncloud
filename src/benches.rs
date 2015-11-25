use test::Bencher;

use time::Duration;

use std::str::FromStr;
use std::net::ToSocketAddrs;

use super::udpmessage::{Options, Message, encode, decode};
use super::crypto::Crypto;
use super::ethernet::{Frame, SwitchTable};
use super::types::{Address, Table, Protocol};
use super::ip::Packet;


#[bench]
fn message_encode(b: &mut Bencher) {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let payload = [0; 1400];
    let msg = Message::Data(&payload);
    let mut buf = [0; 1500];
    b.iter(|| {
        encode(&mut options, &msg, &mut buf[..], &mut crypto);
    });
}

#[bench]
fn message_decode(b: &mut Bencher) {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let payload = [0; 1400];
    let msg = Message::Data(&payload);
    let mut buf = [0; 1500];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    b.iter(|| {
        decode(&mut buf[..size], &mut crypto).unwrap();
    });
}

#[bench]
fn switch_learn(b: &mut Bencher) {
    let mut table = SwitchTable::new(Duration::seconds(10));
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    b.iter(|| {
        table.learn(addr.clone(), None, peer);
    })
}

#[bench]
fn switch_lookup(b: &mut Bencher) {
    let mut table = SwitchTable::new(Duration::seconds(10));
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    table.learn(addr.clone(), None, peer);
    b.iter(|| {
        table.lookup(&addr);
    })

}

#[bench]
fn ethernet_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[5] = 45;
    b.iter(|| {
        Frame::parse(&data).unwrap()
    })
}

#[bench]
fn ipv4_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[0] = 4*16;
    b.iter(|| {
        Packet::parse(&data).unwrap()
    })
}

#[bench]
fn ipv6_parse(b: &mut Bencher) {
    let mut data = [0; 1500];
    data[0] = 6*16;
    b.iter(|| {
        Packet::parse(&data).unwrap()
    })
}
