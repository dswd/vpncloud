use std::{mem, ptr, fmt};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::u16;

use super::types::{Error, NetworkId, Range, Address};
use super::util::{as_obj, as_bytes, to_vec};
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
    if data.len() < mem::size_of::<TopHeader>() {
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
        let len = crypto.nonce_bytes() + crypto.auth_bytes();
        if data.len() < pos + len {
            return Err(Error::ParseError("Truncated crypto header"));
        }
        let (crypto_header, crypto_data) = data[pos..].split_at_mut(len);
        pos += len;
        let (nonce, hash) = crypto_header.split_at(crypto.nonce_bytes());
        try!(crypto.decrypt(crypto_data, nonce, hash));
    }
    let mut options = Options::default();
    if header.flags & 0x01 > 0 {
        if data.len() < pos + NETWORK_ID_BYTES {
            return Err(Error::ParseError("Truncated options"));
        }
        let id = u64::from_be(*unsafe { as_obj::<u64>(&data[pos..pos+NETWORK_ID_BYTES]) });
        options.network_id = Some(id);
        pos += NETWORK_ID_BYTES;
    }
    let msg = match header.msgtype {
        0 => Message::Data(&data[pos..]),
        1 => {
            if data.len() < pos + 1 {
                return Err(Error::ParseError("Empty peers"));
            }
            let count = data[pos];
            pos += 1;
            let len = count as usize * 6;
            if data.len() < pos + len {
                return Err(Error::ParseError("Peer data too short"));
            }
            let mut peers = Vec::with_capacity(count as usize);
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
            Message::Peers(peers)
        },
        2 => {
            if data.len() < pos + 1 {
                return Err(Error::ParseError("Init data too short"));
            }
            let count = data[pos] as usize;
            pos += 1;
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                if data.len() < pos + 1 {
                    return Err(Error::ParseError("Init data too short"));
                }
                let len = data[pos] as usize;
                pos += 1;
                if data.len() < pos + len {
                    return Err(Error::ParseError("Init data too short"));
                }
                let base = Address(to_vec(&data[pos..pos+len]));
                pos += len;
                if data.len() < pos + 1 {
                    return Err(Error::ParseError("Init data too short"));
                }
                let prefix_len = data[pos];
                pos += 1;
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
    let nonce_pos = pos;
    pos += crypto.nonce_bytes();
    let hash_pos = pos;
    pos += crypto.auth_bytes();
    let crypto_pos = pos;
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
            let count_pos = pos;
            pos += 1;
            assert!(buf.len() >= 2 + peers.len() * mem::size_of::<SocketAddrV4>());
            let mut count = 0;
            for p in peers {
                match p {
                    &SocketAddr::V4(addr) => {
                        let ip = addr.ip().octets();
                        let port = addr.port();
                        unsafe {
                            ptr::copy_nonoverlapping(ip.as_ptr(), buf[pos..].as_mut_ptr(), ip.len());
                            pos += ip.len();
                            let port = mem::transmute::<u16, [u8; 2]>(port.to_be());
                            ptr::copy_nonoverlapping(port.as_ptr(), buf[pos..].as_mut_ptr(), port.len());
                            pos += port.len();
                        }
                        count += 1;
                    },
                    &SocketAddr::V6(_addr) => unimplemented!()
                }
            };
            buf[count_pos] = count;
            buf[pos] = 0;
            pos += 1;
        },
        &Message::Init(ref ranges) => {
            assert!(buf.len() >= pos + 1);
            assert!(ranges.len() <= 255);
            buf[pos] = ranges.len() as u8;
            pos += 1;
            for range in ranges {
                let base = &range.base;
                let len = base.0.len();
                assert!(len <= 255);
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
        let (nonce, hash) = crypto.encrypt(&mut buf[crypto_pos..pos]);
        assert_eq!(nonce.len(), crypto.nonce_bytes());
        assert_eq!(hash.len(), crypto.auth_bytes());
        unsafe {
            ptr::copy_nonoverlapping(nonce.as_ptr(), buf[nonce_pos..].as_mut_ptr(), crypto.nonce_bytes());
            ptr::copy_nonoverlapping(hash.as_ptr(), buf[hash_pos..].as_mut_ptr(), crypto.auth_bytes());
        }
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
    assert_eq!(size, 53);
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
    let addrs = vec![Range{base: Address(vec![0,1,2,3]), prefix_len: 24},
        Range{base: Address(vec![0,1,2,3,4,5]), prefix_len: 16}];
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
