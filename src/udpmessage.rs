use std::{mem, ptr, fmt};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::u16;

use super::ethcloud::{Error, NetworkId};
use super::ethernet;
use super::util::{as_obj, as_bytes};

const MAGIC: [u8; 3] = [0x76, 0x70, 0x6e];
const VERSION: u8 = 0;

#[repr(packed)]
struct TopHeader {
    magic: [u8; 3],
    version: u8,
    _reserved: [u8; 2],
    flags: u8,
    msgtype: u8
}

impl Default for TopHeader {
    fn default() -> Self {
        TopHeader{magic: MAGIC, version: VERSION, _reserved: [0; 2], flags: 0, msgtype: 0}
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Options {
    pub network_id: Option<NetworkId>
}


#[derive(PartialEq)]
pub enum Message<'a> {
    Frame(ethernet::Frame<'a>),
    Peers(Vec<SocketAddr>),
    GetPeers,
    Close,
}

impl<'a> fmt::Debug for Message<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Message::Frame(ref frame) => write!(formatter, "Frame({:?})", frame),
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
            &Message::GetPeers => write!(formatter, "GetPeers"),
            &Message::Close => write!(formatter, "Close"),
        }
    }
}

pub fn decode(data: &[u8]) -> Result<(Options, Message), Error> {
    if data.len() < mem::size_of::<TopHeader>() {
        return Err(Error::ParseError("Empty message"));
    }
    let mut pos = 0;
    let header = unsafe { as_obj::<TopHeader>(&data[pos..]) };
    pos += mem::size_of::<TopHeader>();
    if header.magic != MAGIC {
        return Err(Error::ParseError("Wrong protocol"));
    }
    if header.version != VERSION {
        return Err(Error::ParseError("Wrong version"));
    }
    let mut options = Options::default();
    if header.flags & 0x01 > 0 {
        if data.len() < pos + 8 {
            return Err(Error::ParseError("Truncated options"));
        }
        let id = u64::from_be(*unsafe { as_obj::<u64>(&data[pos..]) });
        options.network_id = Some(id);
        pos += 8;
    }
    let msg = match header.msgtype {
        0 => Message::Frame(try!(ethernet::decode(&data[pos..]))),
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
        2 => Message::GetPeers,
        3 => Message::Close,
        _ => return Err(Error::ParseError("Unknown message type"))
    };
    Ok((options, msg))
}

pub fn encode(options: &Options, msg: &Message, buf: &mut [u8]) -> usize {
    assert!(buf.len() >= mem::size_of::<TopHeader>());
    let mut pos = 0;
    let mut header = TopHeader::default();
    header.msgtype = match msg {
        &Message::Frame(_) => 0,
        &Message::Peers(_) => 1,
        &Message::GetPeers => 2,
        &Message::Close => 3
    };
    if options.network_id.is_some() {
        header.flags |= 0x01;
    }
    let header_dat = unsafe { as_bytes(&header) };
    unsafe { ptr::copy_nonoverlapping(header_dat.as_ptr(), buf[pos..].as_mut_ptr(), header_dat.len()) };
    pos += header_dat.len();
    if let Some(id) = options.network_id {
        assert!(buf.len() >= pos + 8);
        unsafe {
            let id_dat = mem::transmute::<u64, [u8; 8]>(id.to_be());
            ptr::copy_nonoverlapping(id_dat.as_ptr(), buf[pos..].as_mut_ptr(), id_dat.len());
        }
        pos += 8;
    }
    match msg {
        &Message::Frame(ref frame) => {
            pos += ethernet::encode(&frame, &mut buf[pos..])
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
        &Message::GetPeers => {
        },
        &Message::Close => {
        }
    }
    pos
}


#[test]
fn encode_message_packet() {
    use super::ethcloud::Mac;
    let options = Options::default();
    let src = Mac([1,2,3,4,5,6]);
    let dst = Mac([7,8,9,10,11,12]);
    let payload = [1,2,3,4,5];
    let msg = Message::Frame(ethernet::Frame{src: &src, dst: &dst, vlan: 0, payload: &payload});
    let mut buf = [0; 1024];
    let size = encode(&options, &msg, &mut buf[..]);
    assert_eq!(size, 25);
    assert_eq!(&buf[..8], &[118,112,110,0,0,0,0,0]);
    let (options2, msg2) = decode(&buf[..size]).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_peers() {
    use std::str::FromStr;
    let options = Options::default();
    let msg = Message::Peers(vec![SocketAddr::from_str("1.2.3.4:123").unwrap(), SocketAddr::from_str("5.6.7.8:12345").unwrap()]);
    let mut buf = [0; 1024];
    let size = encode(&options, &msg, &mut buf[..]);
    assert_eq!(size, 22);
    assert_eq!(&buf[..size], &[118,112,110,0,0,0,0,1,2,1,2,3,4,0,123,5,6,7,8,48,57,0]);
    let (options2, msg2) = decode(&buf[..size]).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_option_network_id() {
    let mut options = Options::default();
    options.network_id = Some(134);
    let msg = Message::GetPeers;
    let mut buf = [0; 1024];
    let size = encode(&options, &msg, &mut buf[..]);
    assert_eq!(size, 18);
    assert_eq!(&buf[..size], &[118,112,110,0,0,0,1,2,0,8,0,0,0,0,0,0,0,134]);
    let (options2, msg2) = decode(&buf[..size]).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_getpeers() {
    let options = Options::default();
    let msg = Message::GetPeers;
    let mut buf = [0; 1024];
    let size = encode(&options, &msg, &mut buf[..]);
    assert_eq!(size, 8);
    assert_eq!(&buf[..size], &[118,112,110,0,0,0,0,2]);
    let (options2, msg2) = decode(&buf[..size]).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}

#[test]
fn encode_message_close() {
    let options = Options::default();
    let msg = Message::Close;
    let mut buf = [0; 1024];
    let size = encode(&options, &msg, &mut buf[..]);
    assert_eq!(size, 8);
    assert_eq!(&buf[..size], &[118,112,110,0,0,0,0,3]);
    let (options2, msg2) = decode(&buf[..size]).unwrap();
    assert_eq!(options, options2);
    assert_eq!(msg, msg2);
}
