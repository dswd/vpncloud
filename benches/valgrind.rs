#![allow(dead_code, unused_macros, unused_imports)]
#[macro_use] extern crate serde;
#[macro_use] extern crate log;

use iai::{black_box, main};

use smallvec::smallvec;
use ring::aead;

use std::str::FromStr;
use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4, UdpSocket};

mod util {
    include!("../src/util.rs");
}
mod error {
    include!("../src/error.rs");
}
mod payload {
    include!("../src/payload.rs");
}
mod types {
    include!("../src/types.rs");
}
mod table {
    include!("../src/table.rs");
}
mod crypto_core {
    include!("../src/crypto/core.rs");
}

pub use error::Error;
use util::{MockTimeSource, MsgBuffer};
use types::{Address, Range};
use table::{ClaimTable};
use payload::{Packet, Frame, Protocol};
use crypto_core::{create_dummy_pair, EXTRA_LEN};

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
        4, 3, 2, 1
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
    table.cache(addr, SocketAddr::from_str("1.2.3.4:3210").unwrap());
    for _ in 0..1000 {
        table.lookup(black_box(addr));
    }
}

fn lookup_cold() {
    let mut table = ClaimTable::<MockTimeSource>::new(60, 60);
    let addr = Address::from_str("1.2.3.4").unwrap();
    table.set_claims(SocketAddr::from_str("1.2.3.4:3210").unwrap(), smallvec![Range::from_str("1.2.3.4/32").unwrap()]);
    for _ in 0..1000 {
        table.clear_cache();
        table.lookup(black_box(addr));
    }
}

fn crypto_bench(algo: &'static aead::Algorithm) {
    let mut buffer = MsgBuffer::new(EXTRA_LEN);
    buffer.set_length(1400);
    let (mut sender, mut receiver) = create_dummy_pair(algo);
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

iai::main!(udp_send, decode_ipv4, decode_ipv6, decode_ethernet, decode_ethernet_with_vlan, lookup_cold, lookup_warm, crypto_chacha20, crypto_aes128, crypto_aes256);