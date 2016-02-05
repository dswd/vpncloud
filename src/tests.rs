// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{ToSocketAddrs, SocketAddr};
use std::str::FromStr;

use super::ethernet::{Frame, SwitchTable};
use super::ip::{RoutingTable, Packet};
use super::types::{Error, Protocol, Address, Range, Table};
use super::udpmessage::{Options, Message, decode, encode};
use super::crypto::{Crypto, CryptoMethod};


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
    let mut options = Options::default();
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
        let res = encode(&mut options, &mut msg, &mut [], &mut crypto);
        assert_eq!(res.len(), 13);
        assert_eq!(&res[..8], &[118,112,110,1,0,0,0,0]);
        for i in 0..res.len() {
            buf[i] = res[i];
        }
        len = res.len();
    }
    let (options2, msg2) = decode(&mut buf[..len], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
#[allow(unused_assignments)]
fn udpmessage_encrypted() {
    let mut options = Options::default();
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
        let res = encode(&mut options, &mut msg, &mut [], &mut crypto);
        assert_eq!(res.len(), 41);
        assert_eq!(&res[..8], &[118,112,110,1,1,0,0,0]);
        for i in 0..res.len() {
            buf[i] = res[i];
        }
        len = res.len();
    }
    let (options2, msg2) = decode(&mut buf[..len], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(orig_msg, msg2);
}

#[test]
fn udpmessage_peers() {
    use std::str::FromStr;
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let mut msg = Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(), SocketAddr::from_str("5.6.7.8:12345").unwrap(), SocketAddr::from_str("[0001:0203:0405:0607:0809:0a0b:0c0d:0e0f]:6789").unwrap()]);
    let mut should = [118,112,110,1,0,0,0,1,2,1,2,3,4,0,123,5,6,7,8,48,57,1,0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15,26,133];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
        assert_eq!(res.len(), 40);
        for i in 0..res.len() {
            assert_eq!(res[i], should[i]);
        }
    }
    let (options2, msg2) = decode(&mut should, &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_option_network_id() {
    let mut options = Options::default();
    options.network_id = Some(134);
    let mut crypto = Crypto::None;
    let mut msg = Message::Close;
    let mut should = [118,112,110,1,0,0,1,3,0,0,0,0,0,0,0,134];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
        assert_eq!(res.len(), 16);
        assert_eq!(&res, &should);
    }
    let (options2, msg2) = decode(&mut should, &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_init() {
    use super::types::Address;
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let addrs = vec![Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24},
        Range{base: Address{data: [0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], len: 6}, prefix_len: 16}];
    let node_id = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    let mut msg = Message::Init(0, node_id, addrs);
    let mut should = [118,112,110,1,0,0,0,2,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,2,4,0,1,2,3,24,6,0,1,2,3,4,5,16];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
        assert_eq!(res.len(), 40);
        for i in 0..res.len() {
            assert_eq!(res[i], should[i]);
        }
    }
    let (options2, msg2) = decode(&mut should, &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_close() {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let mut msg = Message::Close;
    let mut should = [118,112,110,1,0,0,0,3];
    {
        let mut buf = [0; 1024];
        let res = encode(&mut options, &mut msg, &mut buf[..], &mut crypto);
        assert_eq!(res.len(), 8);
        assert_eq!(&res, &should);
    }
    let (options2, msg2) = decode(&mut should, &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn udpmessage_invalid() {
    let mut crypto = Crypto::None;
    assert!(decode(&mut [0x76,0x70,0x6e,1,0,0,0,0], &mut crypto).is_ok());
    // too short
    assert!(decode(&mut [], &mut crypto).is_err());
    // invalid protocol
    assert!(decode(&mut [0,1,2,0,0,0,0,0], &mut crypto).is_err());
    // invalid version
    assert!(decode(&mut [0x76,0x70,0x6e,0xaa,0,0,0,0], &mut crypto).is_err());
    // invalid crypto
    assert!(decode(&mut [0x76,0x70,0x6e,1,0xaa,0,0,0], &mut crypto).is_err());
    // invalid msg type
    assert!(decode(&mut [0x76,0x70,0x6e,1,0,0,0,0xaa], &mut crypto).is_err());
    // truncated options
    assert!(decode(&mut [0x76,0x70,0x6e,1,0,0,1,0], &mut crypto).is_err());
}

#[test]
fn udpmessage_invalid_crypto() {
    let mut crypto = Crypto::from_shared_key(CryptoMethod::ChaCha20, "test");
    // truncated crypto
    assert!(decode(&mut [0x76,0x70,0x6e,1,1,0,0,0], &mut crypto).is_err());
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
    let mut table = SwitchTable::new(10);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&addr).is_none());
    table.learn(addr.clone(), None, peer.clone());
    assert_eq!(table.lookup(&addr), Some(peer));
}

#[test]
fn routing_table() {
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
}

#[test]
fn address_parse_fmt() {
    assert_eq!(format!("{}", Address::from_str("120.45.22.5").unwrap()), "120.45.22.5");
    assert_eq!(format!("{}", Address::from_str("78:2d:16:05:01:02").unwrap()), "78:2d:16:05:01:02");
    assert_eq!(format!("{}", Address{data: [3,56,120,45,22,5,1,2,0,0,0,0,0,0,0,0], len: 8}), "vlan824/78:2d:16:05:01:02");
    assert_eq!(format!("{}", Address::from_str("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f").unwrap()), "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
    assert_eq!(format!("{:?}", Address{data: [1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2}), "0102");
    assert_eq!(Address::from_str(""), Err(Error::ParseError("Failed to parse address")));
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
    assert_eq!(Address::read_from(&buf[0..0]), Err(Error::ParseError("Address too short")));
    buf[0] = 100;
    assert_eq!(Address::read_from(&buf), Err(Error::ParseError("Invalid address, too long")));
    buf[0] = 5;
    assert_eq!(Address::read_from(&buf[0..4]), Err(Error::ParseError("Address too short")));
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
