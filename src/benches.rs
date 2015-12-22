use test::Bencher;

use std::str::FromStr;
use std::net::ToSocketAddrs;

use super::udpmessage::{Options, Message, encode, decode};
use super::crypto::{Crypto, CryptoMethod};
use super::ethernet::{Frame, SwitchTable};
use super::types::{Address, Table, Protocol};
use super::ip::Packet;

#[bench]
fn crypto_salsa20(b: &mut Bencher) {
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
    if !Crypto::aes256_available() {
        return
    }
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
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let mut payload = [0; 1600];
    let mut msg = Message::Data(&mut payload, 64, 1464);
    let mut buf = [0; 1600];
    b.iter(|| {
        encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
    });
}

#[bench]
fn message_decode(b: &mut Bencher) {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let mut payload = [0; 1600];
    let mut msg = Message::Data(&mut payload, 64, 1464);
    let mut buf = [0; 1600];
    let mut res = encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
    b.iter(|| {
        decode(&mut res, &mut crypto).unwrap();
    });
}

#[bench]
fn switch_learn(b: &mut Bencher) {
    let mut table = SwitchTable::new(10);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    b.iter(|| {
        table.learn(addr.clone(), None, peer);
    })
}

#[bench]
fn switch_lookup(b: &mut Bencher) {
    let mut table = SwitchTable::new(10);
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
