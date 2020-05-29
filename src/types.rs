// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    fmt,
    hash::{Hash, Hasher},
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr
};

use super::util::{bytes_to_hex, Encoder};

pub const NODE_ID_BYTES: usize = 16;

pub type HeaderMagic = [u8; 4];
pub type NodeId = [u8; NODE_ID_BYTES];


#[derive(Eq, Clone, Copy)]
pub struct Address {
    pub data: [u8; 16],
    pub len: u8
}

impl Address {
    #[inline]
    pub fn read_from(data: &[u8]) -> Result<(Address, usize), Error> {
        if data.is_empty() {
            return Err(Error::Parse("Address too short"))
        }
        let len = data[0] as usize;
        let addr = Address::read_from_fixed(&data[1..], len)?;
        Ok((addr, len + 1))
    }

    #[inline]
    pub fn read_from_fixed(data: &[u8], len: usize) -> Result<Address, Error> {
        if len > 16 {
            return Err(Error::Parse("Invalid address, too long"))
        }
        if data.len() < len {
            return Err(Error::Parse("Address too short"))
        }
        let mut bytes = [0; 16];
        bytes[0..len].copy_from_slice(&data[0..len]);
        Ok(Address { data: bytes, len: len as u8 })
    }

    #[inline]
    pub fn write_to(&self, data: &mut [u8]) -> usize {
        assert!(data.len() > self.len as usize);
        data[0] = self.len;
        let len = self.len as usize;
        data[1..=len].copy_from_slice(&self.data[0..len]);
        self.len as usize + 1
    }
}


impl PartialEq for Address {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.len == rhs.len && self.data[..self.len as usize] == rhs.data[..self.len as usize]
    }
}


impl Hash for Address {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        hasher.write(&self.data[0..self.len as usize])
    }
}


impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let d = &self.data;
        match self.len {
            4 => write!(formatter, "{}.{}.{}.{}", d[0], d[1], d[2], d[3]),
            6 => write!(formatter, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                d[0], d[1], d[2], d[3], d[4], d[5]),
            8 => {
                let vlan = Encoder::read_u16(&d[0..2]);
                write!(formatter, "vlan{}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    vlan, d[2], d[3], d[4], d[5], d[6], d[7])
            },
            16 => write!(formatter, "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]),
            _ => write!(formatter, "{}", bytes_to_hex(&d[0..self.len as usize]))
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self)
    }
}

impl FromStr for Address {
    type Err = Error;

    #[allow(unknown_lints, clippy::needless_range_loop)]
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = Ipv4Addr::from_str(text) {
            let ip = addr.octets();
            let mut res = [0; 16];
            res[0..4].copy_from_slice(&ip);
            return Ok(Address { data: res, len: 4 })
        }
        if let Ok(addr) = Ipv6Addr::from_str(text) {
            let segments = addr.segments();
            let mut res = [0; 16];
            for i in 0..8 {
                Encoder::write_u16(segments[i], &mut res[2 * i..]);
            }
            return Ok(Address { data: res, len: 16 })
        }
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() == 6 {
            let mut bytes = [0; 16];
            for i in 0..6 {
                bytes[i] = u8::from_str_radix(parts[i], 16).map_err(|_| Error::Parse("Failed to parse mac"))?;
            }
            return Ok(Address { data: bytes, len: 6 })
        }
        Err(Error::Parse("Failed to parse address"))
    }
}


#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Range {
    pub base: Address,
    pub prefix_len: u8
}

impl Range {
    #[inline]
    pub fn read_from(data: &[u8]) -> Result<(Range, usize), Error> {
        let (address, read) = Address::read_from(data)?;
        if data.len() < read + 1 {
            return Err(Error::Parse("Range too short"))
        }
        let prefix_len = data[read];
        Ok((Range { base: address, prefix_len }, read + 1))
    }

    #[inline]
    pub fn write_to(&self, data: &mut [u8]) -> usize {
        let pos = self.base.write_to(data);
        assert!(data.len() > pos);
        data[pos] = self.prefix_len;
        pos + 1
    }
}

impl FromStr for Range {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let pos = match text.find('/') {
            Some(pos) => pos,
            None => return Err(Error::Parse("Invalid range format"))
        };
        let prefix_len = u8::from_str(&text[pos + 1..]).map_err(|_| Error::Parse("Failed to parse prefix length"))?;
        let base = Address::from_str(&text[..pos])?;
        Ok(Range { base, prefix_len })
    }
}

impl fmt::Display for Range {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{}/{}", self.base, self.prefix_len)
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self)
    }
}


#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    #[serde(rename = "normal")]
    Normal,
    #[serde(rename = "hub")]
    Hub,
    #[serde(rename = "switch")]
    Switch,
    #[serde(rename = "router")]
    Router
}
impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Mode::Normal => write!(formatter, "normal"),
            Mode::Hub => write!(formatter, "hub"),
            Mode::Switch => write!(formatter, "switch"),
            Mode::Router => write!(formatter, "router")
        }
    }
}
impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "normal" => Self::Normal,
            "hub" => Self::Hub,
            "switch" => Self::Switch,
            "router" => Self::Router,
            _ => return Err("Unknown mode")
        })
    }
}

pub trait Table {
    fn learn(&mut self, _: Address, _: Option<u8>, _: SocketAddr);
    fn lookup(&mut self, _: &Address) -> Option<SocketAddr>;
    fn housekeep(&mut self);
    fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error>;
    fn remove(&mut self, _: &Address) -> bool;
    fn remove_all(&mut self, _: &SocketAddr);
}

pub trait Protocol: Sized {
    fn parse(_: &[u8]) -> Result<(Address, Address), Error>;
}

#[derive(Debug)]
pub enum Error {
    Parse(&'static str),
    WrongHeaderMagic(HeaderMagic),
    Socket(&'static str, io::Error),
    Name(String),
    TunTapDev(&'static str, io::Error),
    Crypto(&'static str),
    File(&'static str, io::Error),
    Beacon(&'static str, io::Error)
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Parse(msg) => write!(formatter, "{}", msg),
            Error::Socket(msg, ref err) => write!(formatter, "{}: {:?}", msg, err),
            Error::TunTapDev(msg, ref err) => write!(formatter, "{}: {:?}", msg, err),
            Error::Crypto(msg) => write!(formatter, "{}", msg),
            Error::Name(ref name) => write!(formatter, "failed to resolve name '{}'", name),
            Error::WrongHeaderMagic(net) => write!(formatter, "wrong header magic: {}", bytes_to_hex(&net)),
            Error::File(msg, ref err) => write!(formatter, "{}: {:?}", msg, err),
            Error::Beacon(msg, ref err) => write!(formatter, "{}: {:?}", msg, err)
        }
    }
}


#[test]
fn address_parse_fmt() {
    assert_eq!(format!("{}", Address::from_str("120.45.22.5").unwrap()), "120.45.22.5");
    assert_eq!(format!("{}", Address::from_str("78:2d:16:05:01:02").unwrap()), "78:2d:16:05:01:02");
    assert_eq!(
        format!("{}", Address { data: [3, 56, 120, 45, 22, 5, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0], len: 8 }),
        "vlan824/78:2d:16:05:01:02"
    );
    assert_eq!(
        format!("{}", Address::from_str("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f").unwrap()),
        "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f"
    );
    assert_eq!(format!("{:?}", Address { data: [1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 2 }), "0102");
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
    assert_eq!(
        Address::read_from_fixed(&[1, 2, 3, 4], 4).unwrap(),
        Address::read_from_fixed(&[1, 2, 3, 4], 4).unwrap()
    );
    assert_ne!(
        Address::read_from_fixed(&[1, 2, 3, 4], 4).unwrap(),
        Address::read_from_fixed(&[1, 2, 3, 5], 4).unwrap()
    );
    assert_eq!(
        Address::read_from_fixed(&[1, 2, 3, 4], 3).unwrap(),
        Address::read_from_fixed(&[1, 2, 3, 5], 3).unwrap()
    );
    assert_ne!(
        Address::read_from_fixed(&[1, 2, 3, 4], 3).unwrap(),
        Address::read_from_fixed(&[1, 2, 3, 4], 4).unwrap()
    );
}

#[test]
fn address_range_decode_encode() {
    let mut buf = [0; 32];
    let range =
        Range { base: Address { data: [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 }, prefix_len: 24 };
    assert_eq!(range.write_to(&mut buf), 6);
    assert_eq!(&buf[0..6], &[4, 0, 1, 2, 3, 24]);
    assert_eq!((range, 6), Range::read_from(&buf).unwrap());
    assert!(Range::read_from(&buf[..5]).is_err()); // Missing prefix length
    buf[0] = 17;
    assert!(Range::read_from(&buf).is_err());
}
