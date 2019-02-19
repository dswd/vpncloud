// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, SocketAddrV6, Ipv6Addr};

use super::types::{NodeId, HeaderMagic, Error, Range, NODE_ID_BYTES};
use super::util::{bytes_to_hex, Encoder};
use super::crypto::Crypto;

#[derive(Clone, Copy, Default)]
#[repr(packed)]
struct TopHeader {
    magic: HeaderMagic,
    crypto_method : u8,
    _reserved1: u8,
    _reserved2: u8,
    msgtype: u8
}

impl TopHeader {
    #[inline]
    pub fn size() -> usize {
        8
    }

    pub fn read_from(data: &[u8]) -> Result<(TopHeader, usize), Error> {
        if data.len() < TopHeader::size() {
            return Err(Error::Parse("Empty message"));
        }
        let mut header = TopHeader::default();
        header.magic.copy_from_slice(&data[0..4]);
        header.crypto_method = data[4];
        header.msgtype = data[7];
        Ok((header, TopHeader::size()))
    }

    #[allow(unknown_lints,clippy::trivially_copy_pass_by_ref)]
    pub fn write_to(&self, data: &mut [u8]) -> usize {
        assert!(data.len() >= 8);
        data[0..4].copy_from_slice(&self.magic);
        data[4] = self.crypto_method;
        data[5] = 0;
        data[6] = 0;
        data[7] = self.msgtype;
        TopHeader::size()
    }
}

pub enum Message<'a> {
    Data(&'a mut[u8], usize, usize), // data, start, end
    Peers(Vec<SocketAddr>), // peers
    Init(u8, NodeId, Vec<Range>), // step, node_id, ranges
    Close,
}

impl<'a> fmt::Debug for Message<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Message::Data(_, start, end) => write!(formatter, "Data({} bytes)", end-start),
            Message::Peers(ref peers) => {
                try!(write!(formatter, "Peers ["));
                let mut first = true;
                for p in peers {
                    if !first {
                        try!(write!(formatter, ", "));
                    }
                    first = false;
                    try!(write!(formatter, "{}", p));
                }
                write!(formatter, "]")
            },
            Message::Init(stage, ref node_id, ref peers) => write!(formatter, "Init(stage={}, node_id={}, {:?})", stage, bytes_to_hex(node_id), peers),
            Message::Close => write!(formatter, "Close"),
        }
    }
}

#[allow(unknown_lints,clippy::needless_range_loop)]
pub fn decode<'a>(data: &'a mut [u8], magic: HeaderMagic, crypto: &mut Crypto) -> Result<Message<'a>, Error> {
    let mut end = data.len();
    let (header, mut pos) = try!(TopHeader::read_from(&data[..end]));
    if header.magic != magic {
        return Err(Error::WrongHeaderMagic(header.magic));
    }
    if header.crypto_method != crypto.method() {
        return Err(Error::Crypto("Wrong crypto method"));
    }
    if crypto.method() > 0 {
        let len = crypto.nonce_bytes();
        if end < pos + len {
            return Err(Error::Parse("Truncated crypto header"));
        }
        {
            let (before, after) = data.split_at_mut(pos);
            let (nonce, crypto_data) = after.split_at_mut(len);
            pos += len;
            end = try!(crypto.decrypt(crypto_data, nonce, &before[..TopHeader::size()])) + pos;
        }
        assert_eq!(end, data.len()-crypto.additional_bytes());
    }
    let msg = match header.msgtype {
        0 => Message::Data(data, pos, end),
        1 => {
            if end < pos + 1 {
                return Err(Error::Parse("Missing IPv4 count"));
            }
            let mut peers = Vec::new();
            let count = data[pos];
            pos += 1;
            let len = count as usize * 6;
            if end < pos + len {
                return Err(Error::Parse("IPv4 peer data too short"));
            }
            for _ in 0..count {
                let ip = &data[pos..];
                assert!(ip.len() >= 4);
                pos += 4;
                let port = Encoder::read_u16(&data[pos..]);
                pos += 2;
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port));
                peers.push(addr);
            }
            if end < pos + 1 {
                return Err(Error::Parse("Missing IPv6 count"));
            }
            let count = data[pos];
            pos += 1;
            let len = count as usize * 18;
            if end < pos + len {
                return Err(Error::Parse("IPv6 peer data too short"));
            }
            for _ in 0..count {
                let mut ip = [0u16; 8];
                for i in 0..8 {
                    ip[i] = Encoder::read_u16(&data[pos..]);
                    pos += 2;
                }
                let port = Encoder::read_u16(&data[pos..]);
                pos += 2;
                let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(ip[0], ip[1], ip[2],
                    ip[3], ip[4], ip[5], ip[6], ip[7]), port, 0, 0));
                peers.push(addr);
            }
            Message::Peers(peers)
        },
        2 => {
            if end < pos + 2 + NODE_ID_BYTES {
                return Err(Error::Parse("Init data too short"));
            }
            let stage = data[pos];
            pos += 1;
            let mut node_id = [0; NODE_ID_BYTES];
            node_id.copy_from_slice(&data[pos..pos+NODE_ID_BYTES]);
            pos += NODE_ID_BYTES;
            let count = data[pos] as usize;
            pos += 1;
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                let (range, read) = try!(Range::read_from(&data[pos..end]));
                pos += read;
                addrs.push(range);
            }
            Message::Init(stage, node_id, addrs)
        },
        3 => Message::Close,
        _ => return Err(Error::Parse("Unknown message type"))
    };
    Ok(msg)
}

#[allow(unknown_lints,clippy::needless_range_loop)]
pub fn encode<'a>(msg: &'a mut Message, mut buf: &'a mut [u8], magic: HeaderMagic, crypto: &mut Crypto) -> &'a mut [u8] {
    let mut start = 64;
    let mut end = 64;
    match *msg {
        Message::Data(ref mut data, data_start, data_end) => {
            buf = data;
            start = data_start;
            end = data_end;
        },
        Message::Peers(ref peers) => {
            let mut v4addrs = Vec::new();
            let mut v6addrs = Vec::new();
            for p in peers {
                match *p {
                    SocketAddr::V4(addr) => v4addrs.push(addr),
                    SocketAddr::V6(addr) => v6addrs.push(addr)
                }
            }
            assert!(v4addrs.len() <= 255);
            assert!(v6addrs.len() <= 255);
            let mut pos = start;
            assert!(buf.len() >= pos + 2 + v4addrs.len() * 6 + v6addrs.len() * 18);
            buf[pos] = v4addrs.len() as u8;
            pos += 1;
            for addr in v4addrs {
                let ip = addr.ip().octets();
                buf[pos..pos+4].copy_from_slice(&ip);
                pos += 4;
                Encoder::write_u16(addr.port(), &mut buf[pos..]);
                pos += 2;
            };
            buf[pos] = v6addrs.len() as u8;
            pos += 1;
            for addr in v6addrs {
                let ip = addr.ip().segments();
                for i in 0..8 {
                    Encoder::write_u16(ip[i], &mut buf[pos..]);
                    pos += 2;
                }
                Encoder::write_u16(addr.port(), &mut buf[pos..]);
                pos += 2;
            };
            end = pos;
        },
        Message::Init(stage, ref node_id, ref ranges) => {
            let mut pos = start;
            assert!(buf.len() >= pos + 2 + NODE_ID_BYTES);
            buf[pos] = stage;
            pos += 1;
            buf[pos..pos+NODE_ID_BYTES].copy_from_slice(node_id);
            pos += NODE_ID_BYTES;
            assert!(ranges.len() <= 255);
            buf[pos] = ranges.len() as u8;
            pos += 1;
            for range in ranges {
                pos += range.write_to(&mut buf[pos..]);
            }
            end = pos;
        },
        Message::Close => {
        }
    }
    assert!(start >= 64);
    assert!(buf.len() >= end + 64);
    let crypto_start = start;
    start -= crypto.nonce_bytes();
    let mut header = TopHeader::default();
    header.magic = magic;
    header.msgtype = match *msg {
        Message::Data(_, _, _) => 0,
        Message::Peers(_) => 1,
        Message::Init(_, _, _) => 2,
        Message::Close => 3
    };
    header.crypto_method = crypto.method();
    start -= TopHeader::size();
    header.write_to(&mut buf[start..]);
    if crypto.method() > 0 {
        let (junk_before, rest) = buf.split_at_mut(start);
        let (header, rest) = rest.split_at_mut(TopHeader::size());
        let (nonce, rest) = rest.split_at_mut(crypto.nonce_bytes());
        debug_assert_eq!(junk_before.len() + header.len() + crypto.nonce_bytes(), crypto_start);
        assert!(rest.len() >= end - crypto_start + crypto.additional_bytes());
        end = crypto.encrypt(rest, end-crypto_start, nonce, header) + crypto_start;
    }
    &mut buf[start..end]
}


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


#[cfg(test)] use std::str::FromStr;
#[cfg(test)] use super::MAGIC;
#[cfg(test)] use super::types::Address;
#[cfg(test)] use super::crypto::CryptoMethod;

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
