use std::{mem, ptr, fmt};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, SocketAddrV6, Ipv6Addr};
use std::u16;

use super::types::{Error, NetworkId, Range, Address};
use super::util::{as_obj, as_bytes};
use super::crypto::Crypto;

const MAGIC: [u8; 3] = [0x76, 0x70, 0x6e];
pub const VERSION: u8 = 1;

const NETWORK_ID_BYTES: usize = 8;

#[derive(Clone)]
#[repr(packed)]
struct TopHeader {
    magic: [u8; 3],
    version: u8,
    crypto_method : u8,
    _reserved: u8,
    flags: u8,
    msgtype: u8
}

impl Default for TopHeader {
    fn default() -> Self {
        TopHeader{magic: MAGIC, version: VERSION, crypto_method: 0, _reserved: 0, flags: 0, msgtype: 0}
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Options {
    pub network_id: Option<NetworkId>,
}


#[derive(PartialEq)]
pub enum Message<'a> {
    Data(&'a[u8]),
    Peers(Vec<SocketAddr>),
    Init(Vec<Range>),
    Close,
}

impl<'a> fmt::Debug for Message<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Message::Data(ref data) => write!(formatter, "Data(data: {} bytes)", data.len()),
            &Message::Peers(ref peers) => {
                try!(write!(formatter, "Peers ["));
                let mut first = true;
                for p in peers {
                    if !first {
                        try!(write!(formatter, ", "));
                    }
                    first = false;
                    try!(p.fmt(formatter));
                }
                write!(formatter, "]")
            },
            &Message::Init(ref data) => write!(formatter, "Init{:?}", data),
            &Message::Close => write!(formatter, "Close"),
        }
    }
}

pub fn decode<'a>(data: &'a mut [u8], crypto: &mut Crypto) -> Result<(Options, Message<'a>), Error> {
    let mut end = data.len();
    if end < mem::size_of::<TopHeader>() {
        return Err(Error::ParseError("Empty message"));
    }
    let mut pos = 0;
    let header = unsafe { as_obj::<TopHeader>(&data[pos..]) }.clone();
    pos += mem::size_of::<TopHeader>();
    if header.magic != MAGIC {
        return Err(Error::ParseError("Wrong protocol"));
    }
    if header.version != VERSION {
        return Err(Error::ParseError("Wrong version"));
    }
    if header.crypto_method != crypto.method() {
        return Err(Error::CryptoError("Wrong crypto method"));
    }
    if crypto.method() > 0 {
        let len = crypto.nonce_bytes();
        if end < pos + len {
            return Err(Error::ParseError("Truncated crypto header"));
        }
        {
            let (before, after) = data.split_at_mut(pos);
            let (nonce, crypto_data) = after.split_at_mut(len);
            pos += len;
            end = try!(crypto.decrypt(crypto_data, nonce, &before[..mem::size_of::<TopHeader>()])) + pos;
        }
        assert_eq!(end, data.len()-crypto.additional_bytes());
    }
    let mut options = Options::default();
    if header.flags & 0x01 > 0 {
        if end < pos + NETWORK_ID_BYTES {
            return Err(Error::ParseError("Truncated options"));
        }
        let id = u64::from_be(*unsafe { as_obj::<u64>(&data[pos..pos+NETWORK_ID_BYTES]) });
        options.network_id = Some(id);
        pos += NETWORK_ID_BYTES;
    }
    let msg = match header.msgtype {
        0 => Message::Data(&data[pos..end]),
        1 => {
            if end < pos + 1 {
                return Err(Error::ParseError("Empty peers"));
            }
            let mut peers = Vec::new();
            let count = data[pos];
            pos += 1;
            let len = count as usize * 6;
            if end < pos + len {
                return Err(Error::ParseError("Peer data too short"));
            }
            for _ in 0..count {
                let (ip, port) = unsafe {
                    let ip = as_obj::<[u8; 4]>(&data[pos..]);
                    pos += 4;
                    let port = *as_obj::<u16>(&data[pos..]);
                    let port = u16::from_be(port);
                    pos += 2;
                    (ip, port)
                };
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port));
                peers.push(addr);
            }
            let count = data[pos];
            pos += 1;
            let len = count as usize * 18;
            if end < pos + len {
                return Err(Error::ParseError("Peer data too short"));
            }
            for _ in 0..count {
                let (ip, port) = unsafe {
                    let ip = as_obj::<[u16; 8]>(&data[pos..]);
                    pos += 16;
                    let port = *as_obj::<u16>(&data[pos..]);
                    let port = u16::from_be(port);
                    pos += 2;
                    (ip, port)
                };
                let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(u16::from_be(ip[0]),
                    u16::from_be(ip[1]), u16::from_be(ip[2]), u16::from_be(ip[3]), u16::from_be(ip[4]),
                    u16::from_be(ip[5]), u16::from_be(ip[6]), u16::from_be(ip[7])), port, 0, 0));
                peers.push(addr);
            }
            Message::Peers(peers)
        },
        2 => {
            if end < pos + 1 {
                return Err(Error::ParseError("Init data too short"));
            }
            let count = data[pos] as usize;
            pos += 1;
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                if end < pos + 1 {
                    return Err(Error::ParseError("Init data too short"));
                }
                let len = data[pos] as usize;
                pos += 1;
                if end < pos + len + 1 {
                    return Err(Error::ParseError("Init data too short"));
                }
                let mut addr = [0; 16];
                unsafe { ptr::copy_nonoverlapping(data[pos..].as_ptr(), addr.as_mut_ptr(), len) };
                let base = Address(addr, len as u8);
                let prefix_len = data[pos+len];
                pos += len + 1;
                addrs.push(Range{base: base, prefix_len: prefix_len});
            }
            Message::Init(addrs)
        },
        3 => Message::Close,
        _ => return Err(Error::ParseError("Unknown message type"))
    };
    Ok((options, msg))
}

pub fn encode(options: &Options, msg: &Message, buf: &mut [u8], crypto: &mut Crypto) -> usize {
    assert!(buf.len() >= mem::size_of::<TopHeader>());
    let mut pos = 0;
    let mut header = TopHeader::default();
    header.msgtype = match msg {
        &Message::Data(_) => 0,
        &Message::Peers(_) => 1,
        &Message::Init(_) => 2,
        &Message::Close => 3
    };
    header.crypto_method = crypto.method();
    if options.network_id.is_some() {
        header.flags |= 0x01;
    }
    let header_dat = unsafe { as_bytes(&header) };
    unsafe { ptr::copy_nonoverlapping(header_dat.as_ptr(), buf[pos..].as_mut_ptr(), header_dat.len()) };
    pos += header_dat.len();
    pos += crypto.nonce_bytes();
    if let Some(id) = options.network_id {
        assert!(buf.len() >= pos + NETWORK_ID_BYTES);
        unsafe {
            let id_dat = mem::transmute::<u64, [u8; NETWORK_ID_BYTES]>(id.to_be());
            ptr::copy_nonoverlapping(id_dat.as_ptr(), buf[pos..pos+NETWORK_ID_BYTES].as_mut_ptr(), id_dat.len());
        }
        pos += NETWORK_ID_BYTES;
    }
    match msg {
        &Message::Data(ref data) => {
            assert!(buf.len() >= pos + data.len());
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf[pos..].as_mut_ptr(), data.len()) };
            pos += data.len();
        },
        &Message::Peers(ref peers) => {
            let mut v4addrs = Vec::new();
            let mut v6addrs = Vec::new();
            for p in peers {
                match p {
                    &SocketAddr::V4(addr) => v4addrs.push(addr),
                    &SocketAddr::V6(addr) => v6addrs.push(addr)
                }
            };
            assert!(v4addrs.len() <= 255);
            assert!(v6addrs.len() <= 255);
            assert!(buf.len() >= pos + 2 + v4addrs.len() * 6 + v6addrs.len() * 18);
            buf[pos] = v4addrs.len() as u8;
            pos += 1;
            for addr in v4addrs {
                let ip = addr.ip().octets();
                let port = addr.port();
                unsafe {
                    ptr::copy_nonoverlapping(ip.as_ptr(), buf[pos..].as_mut_ptr(), ip.len());
                    pos += ip.len();
                    let port = mem::transmute::<u16, [u8; 2]>(port.to_be());
                    ptr::copy_nonoverlapping(port.as_ptr(), buf[pos..].as_mut_ptr(), port.len());
                    pos += port.len();
                }
            };
            buf[pos] = v6addrs.len() as u8;
            pos += 1;
            for addr in v6addrs {
                let mut ip = addr.ip().segments();
                for i in 0..ip.len() {
                    ip[i] = ip[i].to_be();
                }
                let port = addr.port();
                unsafe {
                    ptr::copy_nonoverlapping(ip.as_ptr() as *const u8, buf[pos..].as_mut_ptr(), 16);
                    pos += ip.len();
                    let port = mem::transmute::<u16, [u8; 2]>(port.to_be());
                    ptr::copy_nonoverlapping(port.as_ptr(), buf[pos..].as_mut_ptr(), port.len());
                    pos += port.len();
                }
            };
        },
        &Message::Init(ref ranges) => {
            assert!(buf.len() >= pos + 1);
            assert!(ranges.len() <= 255);
            buf[pos] = ranges.len() as u8;
            pos += 1;
            for range in ranges {
                let base = &range.base;
                let len = base.1 as usize;
                assert!(buf.len() >= pos + 1 + len + 1);
                buf[pos] = len as u8;
                pos += 1;
                unsafe { ptr::copy_nonoverlapping(base.0.as_ptr(), buf[pos..].as_mut_ptr(), len) };
                pos += len;
                buf[pos] = range.prefix_len;
                pos += 1;
            }
        },
        &Message::Close => {
        }
    }
    if crypto.method() > 0 {
        let (header, rest) = buf.split_at_mut(mem::size_of::<TopHeader>());
        let (nonce, rest) = rest.split_at_mut(crypto.nonce_bytes());
        let crypto_start = header.len() + nonce.len();
        assert!(rest.len() >= pos - crypto_start + crypto.additional_bytes());
        pos = crypto.encrypt(rest, pos-crypto_start, nonce, header) + crypto_start;
    }
    pos
}


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
    let msg = Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(), SocketAddr::from_str("5.6.7.8:12345").unwrap()]);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 22);
    assert_eq!(&buf[..size], &[118,112,110,1,0,0,0,1,2,1,2,3,4,0,123,5,6,7,8,48,57,0]);
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
    let mut options = Options::default();
    let mut crypto = Crypto::None;
    let addrs = vec![Range{base: Address([0,1,2,3,0,0,0,0,0,0,0,0,0,0,0,0], 4), prefix_len: 24},
        Range{base: Address([0,1,2,3,4,5,0,0,0,0,0,0,0,0,0,0], 6), prefix_len: 16}];
    let msg = Message::Init(addrs);
    let mut buf = [0; 1024];
    let size = encode(&mut options, &msg, &mut buf[..], &mut crypto);
    assert_eq!(size, 23);
    assert_eq!(&buf[..size], &[118,112,110,1,0,0,0,2,2,4,0,1,2,3,24,6,0,1,2,3,4,5,16]);
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
