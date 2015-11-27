use std::net::{ToSocketAddrs, SocketAddr};
use std::str::FromStr;

use super::ethernet::{Frame, SwitchTable};
use super::ip::{RoutingTable, Packet};
use super::types::{Protocol, Address, Range, Table};
use super::udpmessage::{Options, Message, decode, encode};
use super::crypto::Crypto;


#[test]
fn encode_message_packet() {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let payload = [1,2,3,4,5];
    let msg = Message::Data(&payload);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 13);
    assert_eq!(&buf[..8], &[118,112,110,1,0,0,0,0]);
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[cfg(feature = "crypto")]
#[test]
fn encode_message_encrypted() {
    let mut options = Options::default();
    let mut crypto = Crypto::from_shared_key("test");
    let payload = [1,2,3,4,5];
    let msg = Message::Data(&payload);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 37);
    assert_eq!(&buf[..8], &[118,112,110,1,1,0,0,0]);
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_peers() {
    use std::str::FromStr;
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let msg = Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(), SocketAddr::from_str("5.6.7.8:12345").unwrap(), SocketAddr::from_str("[0001:0203:0405:0607:0809:0a0b:0c0d:0e0f]:6789").unwrap()]);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 40);
    let should = [118,112,110,1,0,0,0,1,2,1,2,3,4,0,123,5,6,7,8,48,57,1,0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15,26,133];
    for i in 0..size {
        assert_eq!(buf[i], should[i]);
    }
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_option_network_id() {
    let mut options = Options::default();
    options.network_id = Some(134);
    let mut crypto = Crypto::None;
    let msg = Message::Close;
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 16);
    assert_eq!(&buf[..size], &[118,112,110,1,0,0,1,3,0,0,0,0,0,0,0,134]);
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_init() {
    use super::types::Address;
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let addrs = vec![Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24},
        Range{base: Address{data: [0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], len: 6}, prefix_len: 16}];
    let msg = Message::Init(0, addrs);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 24);
    assert_eq!(&buf[..size], &[118,112,110,1,0,0,0,2,0,2,4,0,1,2,3,24,6,0,1,2,3,4,5,16]);
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_close() {
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let msg = Message::Close;
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 8);
    assert_eq!(&buf[..size], &[118,112,110,1,0,0,0,3]);
    let (options2, msg2) = decode(&mut buf[..size], &mut crypto).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
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
}

#[test]
fn message_fmt() {
    assert_eq!(format!("{:?}", Message::Data(&[1,2,3,4,5])), "Data(5 bytes)");
    assert_eq!(format!("{:?}", Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(),
        SocketAddr::from_str("5.6.7.8:12345").unwrap(),
        SocketAddr::from_str("[0001:0203:0405:0607:0809:0a0b:0c0d:0e0f]:6789").unwrap()])),
        "Peers [1.2.3.4:123, 5.6.7.8:12345, [1:203:405:607:809:a0b:c0d:e0f]:6789]");
    assert_eq!(format!("{:?}", Message::Init(0, vec![
        Range{base: Address{data: [0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], len: 4}, prefix_len: 24},
        Range{base: Address{data: [0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], len: 6}, prefix_len: 16}
        ])), "Init(stage=0, [0.1.2.3/24, 00:01:02:03:04:05/16])");
    assert_eq!(format!("{:?}", Message::Close), "Close");
}
