// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2017  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{ToSocketAddrs, SocketAddr};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use serde_yaml;

use super::MAGIC;
use super::ethernet::{Frame, SwitchTable};
use super::ip::{RoutingTable, Packet};
use super::device::Type;
use super::types::{Protocol, Address, Range, Table, Mode};
use super::udpmessage::{Message, decode, encode};
use super::crypto::{Crypto, CryptoMethod};
use super::config::{Config, ConfigFile};
use super::Args;


impl<'a> PartialEq for Message<'a> {
    fn eq(&self, other: &Message) -> bool {
        match self {
            &Message::Data(ref data1, start1, end1) => if let &Message::Data(ref data2, start2, end2) = other {
                data1[start1..end1] == data2[start2..end2]
            } else { false },
            &Message::Peers(ref peers1) => if let &Message::Peers(ref peers2) = other {
                peers1 == peers2
            } else { false },
            &Message::Init(step1, node_id1, ref ranges1) => if let &Message::Init(step2, node_id2, ref ranges2) = other {
                step1 == step2 && node_id1 == node_id2 && ranges1 == ranges2
            } else { false },
            &Message::Close => if let &Message::Close = other {
                true
            } else { false }
        }
    }
}

#[test]
#[allow(unused_assignments)]
fn udpmessage_packet() {
    let mut crypto = Crypto::None;
    let mut payload = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       1,2,3,4,5,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let mut msg = Message::Data(&mut payload, 64, 69);
    let mut buf = [0; 1024];
    let mut len = 0;
    {
        let res = encode(&mut msg, &mut [], MAGIC, &mut crypto);
        assert_eq!(res.len(), 13);
        assert_eq!(&res[..8], &[118,112,110,1,0,0,0,0]);
        for i in 0..res.len() {
            buf[i] = res[i];
        }
        len = res.len();
    }
    let msg2 = decode(&mut buf[..len], MAGIC, &mut crypto).unwrap();
    assert_eq!(msg, msg2);
}

#[test]
#[allow(unused_assignments)]
fn udpmessage_encrypted() {
    let mut crypto = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    let mut payload = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       1,2,3,4,5,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let mut orig_payload = [0; 133];
    for i in 0..payload.len() {
        orig_payload[i] = payload[i];
    }
    let orig_msg = Message::Data(&mut orig_payload, 64, 69);
    let mut msg = Message::Data(&mut payload, 64, 69);
    let mut buf = [0; 1024];
    let mut len = 0;
    {
        let res = encode(&mut msg, &mut [], MAGIC, &mut crypto);
        assert_eq!(res.len(), 41);
        assert_eq!(&res[..8], &[118,112,110,1,1,0,0,0]);
        for i in 0..res.len() {
            buf[i] = res[i];
        }
        len = res.len();
    }
    let msg2 = decode(&mut buf[..len], MAGIC, &mut crypto).unwrap();
    assert_eq!(orig_msg, msg2);
}

#[test]
fn udpmessage_peers() {
    use std::str::FromStr;
    let mut crypto = Crypto::None;
    let mut msg = Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(), SocketAddr::from_str("5.6.7.8:12345").unwrap(), SocketAddr::from_str("[0001:0203:0405:0607:0809:0a0b:0c0d:0e0f]:6789").unwrap()]);
    let mut should = [118,112,110,1,0,0,0,1,2,1,2,3,4,0,123,5,6,7,8,48,57,1,0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15,26,133];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut msg, &mut buf[..], MAGIC, &mut crypto);
        assert_eq!(res.len(), 40);
        for i in 0..res.len() {
            assert_eq!(res[i], should[i]);
        }
    }
    let msg2 = decode(&mut should, MAGIC, &mut crypto).unwrap();
    assert_eq!(msg, msg2);
    // Missing IPv4 count
    assert!(decode(&mut[118,112,110,1,0,0,0,1], MAGIC, &mut crypto).is_err());
    // Truncated IPv4
    assert!(decode(&mut[118,112,110,1,0,0,0,1,1], MAGIC, &mut crypto).is_err());
    // Missing IPv6 count
    assert!(decode(&mut[118,112,110,1,0,0,0,1,1,1,2,3,4,0,0], MAGIC, &mut crypto).is_err());
    // Truncated IPv6
    assert!(decode(&mut[118,112,110,1,0,0,0,1,1,1,2,3,4,0,0,1], MAGIC, &mut crypto).is_err());
}

#[test]
fn udpmessage_init() {
    use super::types::Address;
    let mut crypto = Crypto::None;
    let addrs = vec![Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24},
        Range{base: Address{data: [0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], len: 6}, prefix_len: 16}];
    let node_id = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    let mut msg = Message::Init(0, node_id, addrs);
    let mut should = [118,112,110,1,0,0,0,2,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,2,4,0,1,2,3,24,6,0,1,2,3,4,5,16];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut msg, &mut buf[..], MAGIC, &mut crypto);
        assert_eq!(res.len(), 40);
        for i in 0..res.len() {
            assert_eq!(res[i], should[i]);
        }
    }
    let msg2 = decode(&mut should, MAGIC, &mut crypto).unwrap();
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_close() {
    let mut crypto = Crypto::None;
    let mut msg = Message::Close;
    let mut should = [118,112,110,1,0,0,0,3];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut msg, &mut buf[..], MAGIC, &mut crypto);
        assert_eq!(res.len(), 8);
        assert_eq!(&res, &should);
    }
    let msg2 = decode(&mut should, MAGIC, &mut crypto).unwrap();
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_invalid() {
    let mut crypto = Crypto::None;
    assert!(decode(&mut [0x76,0x70,0x6e,1,0,0,0,0], MAGIC, &mut crypto).is_ok());
    // too short
    assert!(decode(&mut [], MAGIC, &mut crypto).is_err());
    // invalid protocol
    assert!(decode(&mut [0,1,2,0,0,0,0,0], MAGIC, &mut crypto).is_err());
    // invalid version
    assert!(decode(&mut [0x76,0x70,0x6e,0xaa,0,0,0,0], MAGIC, &mut crypto).is_err());
    // invalid crypto
    assert!(decode(&mut [0x76,0x70,0x6e,1,0xaa,0,0,0], MAGIC, &mut crypto).is_err());
    // invalid msg type
    assert!(decode(&mut [0x76,0x70,0x6e,1,0,0,0,0xaa], MAGIC, &mut crypto).is_err());
}

#[test]
fn udpmessage_invalid_crypto() {
    let mut crypto = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    // truncated crypto
    assert!(decode(&mut [0x76,0x70,0x6e,1,1,0,0,0], MAGIC, &mut crypto).is_err());
}


#[test]
fn decode_frame_without_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address{data: [1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0], len: 6});
    assert_eq!(dst, Address{data: [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], len: 6});
}

#[test]
fn decode_frame_with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address{data: [4,210,1,2,3,4,5,6,0,0,0,0,0,0,0,0], len: 8});
    assert_eq!(dst, Address{data: [4,210,6,5,4,3,2,1,0,0,0,0,0,0,0,0], len: 8});
}

#[test]
fn decode_invalid_frame() {
    assert!(Frame::parse(&[6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8]).is_ok());
    // truncated frame
    assert!(Frame::parse(&[]).is_err());
    // truncated vlan frame
    assert!(Frame::parse(&[6,5,4,3,2,1,1,2,3,4,5,6,0x81,0x00]).is_err());
}


#[test]
fn decode_ipv4_packet() {
    let data = [0x40,0,0,0,0,0,0,0,0,0,0,0,192,168,1,1,192,168,1,2];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address{data: [192,168,1,1,0,0,0,0,0,0,0,0,0,0,0,0], len: 4});
    assert_eq!(dst, Address{data: [192,168,1,2,0,0,0,0,0,0,0,0,0,0,0,0], len: 4});
}

#[test]
fn decode_ipv6_packet() {
    let data = [0x60,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,0,9,8,7,6,5,4,3,2,1,6,5,4,3,2,1];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address{data: [1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6], len: 16});
    assert_eq!(dst, Address{data: [0,9,8,7,6,5,4,3,2,1,6,5,4,3,2,1], len: 16});
}

#[test]
fn decode_invalid_packet() {
    assert!(Packet::parse(&[0x40,0,0,0,0,0,0,0,0,0,0,0,192,168,1,1,192,168,1,2]).is_ok());
    assert!(Packet::parse(&[0x60,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,0,9,8,7,6,5,4,3,2,1,6,5,4,3,2,1]).is_ok());
    // no data
    assert!(Packet::parse(&[]).is_err());
    // wrong version
    assert!(Packet::parse(&[0x20]).is_err());
    // truncated ipv4
    assert!(Packet::parse(&[0x40,0,0,0,0,0,0,0,0,0,0,0,192,168,1,1,192,168,1]).is_err());
    // truncated ipv6
    assert!(Packet::parse(&[0x60,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,0,9,8,7,6,5,4,3,2,1,6,5,4,3,2]).is_err());
}


#[test]
fn switch() {
    let mut table = SwitchTable::new(10, 1);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "1.2.3.5:7890".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&addr).is_none());
    table.learn(addr.clone(), None, peer.clone());
    assert_eq!(table.lookup(&addr), Some(peer));
    // Do not override within 1 seconds
    table.learn(addr.clone(), None, peer2.clone());
    assert_eq!(table.lookup(&addr), Some(peer));
    thread::sleep(Duration::from_secs(1));
    table.learn(addr.clone(), None, peer2.clone());
    assert_eq!(table.lookup(&addr), Some(peer2));
}

#[test]
fn routing_table_ipv4() {
    let mut table = RoutingTable::new();
    let peer1 = "1.2.3.4:1".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "1.2.3.4:2".to_socket_addrs().unwrap().next().unwrap();
    let peer3 = "1.2.3.4:3".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&Address::from_str("192.168.1.1").unwrap()).is_none());
    table.learn(Address::from_str("192.168.1.1").unwrap(), Some(32), peer1.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    table.learn(Address::from_str("192.168.1.2").unwrap(), None, peer2.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    table.learn(Address::from_str("192.168.1.0").unwrap(), Some(24), peer3.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    table.learn(Address::from_str("192.168.0.0").unwrap(), Some(16), peer1.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    table.learn(Address::from_str("0.0.0.0").unwrap(), Some(0), peer2.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("1.2.3.4").unwrap()), Some(peer2));
    table.learn(Address::from_str("192.168.2.0").unwrap(), Some(27), peer3.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.2.31").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("192.168.2.32").unwrap()), Some(peer1));
    table.learn(Address::from_str("192.168.2.0").unwrap(), Some(28), peer3.clone());
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer3));
}

#[test]
fn routing_table_ipv6() {
    let mut table = RoutingTable::new();
    let peer1 = "::1:1".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "::1:2".to_socket_addrs().unwrap().next().unwrap();
    let peer3 = "::1:3".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&Address::from_str("::1").unwrap()).is_none());
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap(), Some(128), peer1.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap(), None, peer2.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    table.learn(Address::from_str("dead:beef:dead:beef::").unwrap(), Some(64), peer3.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    table.learn(Address::from_str("dead:beef:dead:be00::").unwrap(), Some(56), peer1.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:1::").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:be01::").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    table.learn(Address::from_str("::").unwrap(), Some(0), peer2.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:1::").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:be01::").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("::1").unwrap()), Some(peer2));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:be00").unwrap(), Some(123), peer2.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be1f").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be20").unwrap()), Some(peer3));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:be00").unwrap(), Some(124), peer3.clone());
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be01").unwrap()), Some(peer3));
}

#[test]
fn address_parse_fmt() {
    assert_eq!(format!("{}", Address::from_str("120.45.22.5").unwrap()), "120.45.22.5");
    assert_eq!(format!("{}", Address::from_str("78:2d:16:05:01:02").unwrap()), "78:2d:16:05:01:02");
    assert_eq!(format!("{}", Address{data: [3,56,120,45,22,5,1,2,0,0,0,0,0,0,0,0], len: 8}), "vlan824/78:2d:16:05:01:02");
    assert_eq!(format!("{}", Address::from_str("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f").unwrap()), "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
    assert_eq!(format!("{:?}", Address{data: [1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2}), "0102");
    assert!(Address::from_str("").is_err()); // Failed to parse address
}

#[test]
fn address_decode_encode() {
    let mut buf = [0; 32];
    let addr = Address::from_str("120.45.22.5").unwrap();
    assert_eq!(addr.write_to(&mut buf), 5);
    assert_eq!(&buf[0..5], &[4, 120, 45, 22, 5]);
    assert_eq!((addr, 5), Address::read_from(&buf).unwrap());
    assert_eq!(addr, Address::read_from_fixed(&buf[1..], 4).unwrap());
    let addr = Address::from_str("78:2d:16:05:01:02").unwrap();
    assert_eq!(addr.write_to(&mut buf), 7);
    assert_eq!(&buf[0..7], &[6, 0x78, 0x2d, 0x16, 0x05, 0x01, 0x02]);
    assert_eq!((addr, 7), Address::read_from(&buf).unwrap());
    assert_eq!(addr, Address::read_from_fixed(&buf[1..], 6).unwrap());
    assert!(Address::read_from(&buf[0..0]).is_err()); // Address too short
    buf[0] = 100;
    assert!(Address::read_from(&buf).is_err()); // Invalid address, too long
    buf[0] = 5;
    assert!(Address::read_from(&buf[0..4]).is_err()); // Address too short
}

#[test]
fn address_eq() {
    assert!(Address::read_from_fixed(&[1,2,3,4], 4).unwrap() == Address::read_from_fixed(&[1,2,3,4], 4).unwrap());
    assert!(Address::read_from_fixed(&[1,2,3,4], 4).unwrap() != Address::read_from_fixed(&[1,2,3,5], 4).unwrap());
    assert!(Address::read_from_fixed(&[1,2,3,4], 3).unwrap() == Address::read_from_fixed(&[1,2,3,5], 3).unwrap());
    assert!(Address::read_from_fixed(&[1,2,3,4], 3).unwrap() != Address::read_from_fixed(&[1,2,3,4], 4).unwrap());
}

#[test]
fn address_range_decode_encode() {
    let mut buf = [0; 32];
    let range = Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24};
    assert_eq!(range.write_to(&mut buf), 6);
    assert_eq!(&buf[0..6], &[4, 0, 1, 2, 3, 24]);
    assert_eq!((range, 6), Range::read_from(&buf).unwrap());
    assert!(Range::read_from(&buf[..5]).is_err()); // Missing prefix length
    buf[0] = 17;
    assert!(Range::read_from(&buf).is_err());
}

#[test]
fn message_fmt() {
    assert_eq!(format!("{:?}", Message::Data(&mut [1,2,3,4,5], 0, 5)), "Data(5 bytes)");
    assert_eq!(format!("{:?}", Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(),
        SocketAddr::from_str("5.6.7.8:12345").unwrap(),
        SocketAddr::from_str("[0001:0203:0405:0607:0809:0a0b:0c0d:0e0f]:6789").unwrap()])),
        "Peers [1.2.3.4:123, 5.6.7.8:12345, [1:203:405:607:809:a0b:c0d:e0f]:6789]");
    assert_eq!(format!("{:?}", Message::Init(0, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], vec![
        Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24},
        Range{base: Address{data: [0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], len: 6}, prefix_len: 16}
        ])), "Init(stage=0, node_id=000102030405060708090a0b0c0d0e0f, [0.1.2.3/24, 00:01:02:03:04:05/16])");
    assert_eq!(format!("{:?}", Message::Close), "Close");
}

#[test]
fn encrypt_decrypt_chacha20poly1305() {
    let mut sender = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    let receiver = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    let msg = "HelloWorld0123456789";
    let msg_bytes = msg.as_bytes();
    let mut buffer = [0u8; 1024];
    let header = [0u8; 8];
    for i in 0..msg_bytes.len() {
        buffer[i] = msg_bytes[i];
    }
    let mut nonce1 = [0u8; 12];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce1, &header);
    assert_eq!(size, msg_bytes.len() + sender.additional_bytes());
    assert!(msg_bytes != &buffer[..msg_bytes.len()] as &[u8]);
    receiver.decrypt(&mut buffer[..size], &nonce1, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
    let mut nonce2 = [0u8; 12];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce2, &header);
    assert!(nonce1 != nonce2);
    receiver.decrypt(&mut buffer[..size], &nonce2, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
}

#[test]
fn encrypt_decrypt_aes256() {
    Crypto::init();
    if ! Crypto::aes256_available() {
        return
    }
    let mut sender = Crypto::from_shared_key(CryptoMethod::AES256, "test");
    let receiver = Crypto::from_shared_key(CryptoMethod::AES256, "test");
    let msg = "HelloWorld0123456789";
    let msg_bytes = msg.as_bytes();
    let mut buffer = [0u8; 1024];
    let header = [0u8; 8];
    for i in 0..msg_bytes.len() {
        buffer[i] = msg_bytes[i];
    }
    let mut nonce1 = [0u8; 12];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce1, &header);
    assert_eq!(size, msg_bytes.len() + sender.additional_bytes());
    assert!(msg_bytes != &buffer[..msg_bytes.len()] as &[u8]);
    receiver.decrypt(&mut buffer[..size], &nonce1, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
    let mut nonce2 = [0u8; 12];
    let size = sender.encrypt(&mut buffer, msg_bytes.len(), &mut nonce2, &header);
    assert!(nonce1 != nonce2);
    receiver.decrypt(&mut buffer[..size], &nonce2, &header).unwrap();
    assert_eq!(msg_bytes, &buffer[..msg_bytes.len()] as &[u8]);
}

#[test]
fn config_file() {
    let config_file = "
device_type: tun
device_name: vpncloud%d
magic: 0123ABCD
ifup: ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up
ifdown: 'true'
crypto: aes256
shared_key: mysecret
port: 3210
peers:
  - remote.machine.foo:3210
  - remote.machine.bar:3210
peer_timeout: 1800
keepalive: 840
dst_timeout: 300
mode: normal
subnets:
  - 10.0.1.0/24
port_forwarding: true
user: nobody
group: nogroup
pid_file: /run/vpncloud.run
stats_file: /var/log/vpncloud.stats
    ";
    assert_eq!(serde_yaml::from_str::<ConfigFile>(config_file).unwrap(), ConfigFile{
        device_type: Some(Type::Tun),
        device_name: Some("vpncloud%d".to_string()),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        crypto: Some(CryptoMethod::AES256),
        shared_key: Some("mysecret".to_string()),
        magic: Some("0123ABCD".to_string()),
        port: Some(3210),
        peers: Some(vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()]),
        peer_timeout: Some(1800),
        keepalive: Some(840),
        mode: Some(Mode::Normal),
        dst_timeout: Some(300),
        subnets: Some(vec!["10.0.1.0/24".to_string()]),
        port_forwarding: Some(true),
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string())
    })
}

#[test]
fn config_merge() {
    let mut config = Config::default();
    config.merge_file(ConfigFile{
        device_type: Some(Type::Tun),
        device_name: Some("vpncloud%d".to_string()),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        crypto: Some(CryptoMethod::AES256),
        shared_key: Some("mysecret".to_string()),
        magic: Some("0123ABCD".to_string()),
        port: Some(3210),
        peers: Some(vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()]),
        peer_timeout: Some(1800),
        keepalive: Some(840),
        mode: Some(Mode::Normal),
        dst_timeout: Some(300),
        subnets: Some(vec!["10.0.1.0/24".to_string()]),
        port_forwarding: Some(true),
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string())
    });
    assert_eq!(config, Config{
        device_type: Type::Tun,
        device_name: "vpncloud%d".to_string(),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        magic: Some("0123ABCD".to_string()),
        crypto: CryptoMethod::AES256,
        shared_key: Some("mysecret".to_string()),
        port: 3210,
        peers: vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()],
        peer_timeout: 1800,
        keepalive: Some(840),
        dst_timeout: 300,
        mode: Mode::Normal,
        port_forwarding: true,
        subnets: vec!["10.0.1.0/24".to_string()],
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string()),
        ..Default::default()
    });
    config.merge_args(Args{
        flag_type: Some(Type::Tap),
        flag_device: Some("vpncloud0".to_string()),
        flag_ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
        flag_ifdown: Some("ifconfig $IFNAME down".to_string()),
        flag_crypto: Some(CryptoMethod::ChaCha20),
        flag_shared_key: Some("anothersecret".to_string()),
        flag_magic: Some("hash:mynet".to_string()),
        flag_listen: Some(3211),
        flag_peer_timeout: Some(1801),
        flag_keepalive: Some(850),
        flag_dst_timeout: Some(301),
        flag_mode: Some(Mode::Switch),
        flag_subnet: vec![],
        flag_connect: vec!["another:3210".to_string()],
        flag_no_port_forwarding: true,
        flag_daemon: true,
        flag_pid_file: Some("/run/vpncloud-mynet.run".to_string()),
        flag_stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
        flag_user: Some("root".to_string()),
        flag_group: Some("root".to_string()),
        ..Default::default()
    });
    assert_eq!(config, Config{
        device_type: Type::Tap,
        device_name: "vpncloud0".to_string(),
        ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
        ifdown: Some("ifconfig $IFNAME down".to_string()),
        magic: Some("hash:mynet".to_string()),
        crypto: CryptoMethod::ChaCha20,
        shared_key: Some("anothersecret".to_string()),
        port: 3211,
        peers: vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string(), "another:3210".to_string()],
        peer_timeout: 1801,
        keepalive: Some(850),
        dst_timeout: 301,
        mode: Mode::Switch,
        port_forwarding: false,
        subnets: vec!["10.0.1.0/24".to_string()],
        user: Some("root".to_string()),
        group: Some("root".to_string()),
        pid_file: Some("/run/vpncloud-mynet.run".to_string()),
        stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
        daemonize: true,
        ..Default::default()
    });
}
