// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::fmt;
use std::str::FromStr;
use std::hash::{Hash, Hasher};
use std::io;

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
        if data.len() < 1 {
            return Err(Error::Parse("Address too short"));
        }
        let len = data[0] as usize;
        let addr = try!(Address::read_from_fixed(&data[1..], len));
        Ok((addr, len + 1))
    }

    #[inline]
    pub fn read_from_fixed(data: &[u8], len: usize) -> Result<Address, Error> {
        if len > 16 {
            return Err(Error::Parse("Invalid address, too long"));
        }
        if data.len() < len {
            return Err(Error::Parse("Address too short"));
        }
        let mut bytes = [0; 16];
        bytes[0..len].copy_from_slice(&data[0..len]);
        Ok(Address{data: bytes, len: len as u8})
    }

    #[inline]
    pub fn write_to(&self, data: &mut[u8]) -> usize {
        assert!(data.len() >= self.len as usize + 1);
        data[0] = self.len;
        let len = self.len as usize;
        data[1..len+1].copy_from_slice(&self.data[0..len]);
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
    type Err=Error;

    #[allow(unknown_lints)]
    #[allow(needless_range_loop)]
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = Ipv4Addr::from_str(text) {
            let ip = addr.octets();
            let mut res = [0; 16];
            res[0..4].copy_from_slice(&ip);
            return Ok(Address{data: res, len: 4});
        }
        if let Ok(addr) = Ipv6Addr::from_str(text) {
            let segments = addr.segments();
            let mut res = [0; 16];
            for i in 0..8 {
                Encoder::write_u16(segments[i], &mut res[2*i..]);
            }
            return Ok(Address{data: res, len: 16});
        }
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() == 6 {
            let mut bytes = [0; 16];
            for i in 0..6 {
                bytes[i] = try!(u8::from_str_radix(&parts[i], 16).map_err(|_| Error::Parse("Failed to parse mac")));
            }
            return Ok(Address{data: bytes, len: 6});
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
        let (address, read) = try!(Address::read_from(data));
        if data.len() < read + 1 {
            return Err(Error::Parse("Range too short"));
        }
        let prefix_len = data[read];
        Ok((Range{base: address, prefix_len: prefix_len}, read + 1))
    }

    #[inline]
    pub fn write_to(&self, data: &mut[u8]) -> usize {
        let pos = self.base.write_to(data);
        assert!(data.len() >= pos + 1);
        data[pos] = self.prefix_len;
        pos + 1
    }
}

impl FromStr for Range {
    type Err=Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let pos = match text.find('/') {
            Some(pos) => pos,
            None => return Err(Error::Parse("Invalid range format"))
        };
        let prefix_len = try!(u8::from_str(&text[pos+1..])
            .map_err(|_| Error::Parse("Failed to parse prefix length")));
        let base = try!(Address::from_str(&text[..pos]));
        Ok(Range{base: base, prefix_len: prefix_len})
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


#[derive(RustcDecodable, Debug, Clone, Copy)]
pub enum Mode {
    Normal, Hub, Switch, Router
}
impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Mode::Normal => write!(formatter, "normal"),
            Mode::Hub => write!(formatter, "hub"),
            Mode::Switch => write!(formatter, "switch"),
            Mode::Router => write!(formatter, "router"),
        }
    }
}

pub trait Table {
    fn learn(&mut self, Address, Option<u8>, SocketAddr);
    fn lookup(&mut self, &Address) -> Option<SocketAddr>;
    fn housekeep(&mut self);
    fn remove(&mut self, &Address) -> bool;
    fn remove_all(&mut self, &SocketAddr);
}

pub trait Protocol: Sized {
    fn parse(&[u8]) -> Result<(Address, Address), Error>;
}

#[derive(Debug)]
pub enum Error {
    Parse(&'static str),
    WrongHeaderMagic(HeaderMagic),
    Socket(&'static str, io::Error),
    Name(String),
    TunTapDev(&'static str, io::Error),
    Crypto(&'static str)
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Parse(ref msg) => write!(formatter, "{}", msg),
            Error::Socket(ref msg, ref err) => write!(formatter, "{}: {:?}", msg, err),
            Error::TunTapDev(ref msg, ref err) => write!(formatter, "{}: {:?}", msg, err),
            Error::Crypto(ref msg) => write!(formatter, "{}", msg),
            Error::Name(ref name) => write!(formatter, "failed to resolve name '{}'", name),
            Error::WrongHeaderMagic(net) => write!(formatter, "wrong header magic: {}", bytes_to_hex(&net)),
        }
    }
}
