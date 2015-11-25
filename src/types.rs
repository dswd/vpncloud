use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::hash::Hasher;
use std::{fmt, ptr};
use std::str::FromStr;

use super::util::{as_bytes, as_obj};

pub type NetworkId = u64;

#[derive(PartialOrd, Eq, Ord, Clone, Hash)]
pub struct Address(pub [u8; 16], pub u8);

impl PartialEq for Address {
    fn eq(&self, rhs: &Self) -> bool {
        if self.1 != rhs.1 {
            return false;
        }
        for i in 0..self.1 as usize {
            if self.0[i] != rhs.0[i] {
                return false;
            }
        }
        true
    }
}


impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.1 {
            4 => write!(formatter, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3]),
            6 => write!(formatter, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]),
            8 => {
                let vlan = u16::from_be( *unsafe { as_obj(&self.0[0..2]) });
                write!(formatter, "vlan{}/{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    vlan, self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7])
            },
            16 => write!(formatter, "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7],
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15]
            ),
            _ => self.0.fmt(formatter)
        }
    }
}

impl FromStr for Address {
    type Err=Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = Ipv4Addr::from_str(text) {
            let ip = addr.octets();
            let mut res = [0; 16];
            unsafe {
                ptr::copy_nonoverlapping(ip.as_ptr(), res.as_mut_ptr(), ip.len());
            }
            return Ok(Address(res, 4));
        }
        if let Ok(addr) = Ipv6Addr::from_str(text) {
            let mut segments = addr.segments();
            for i in 0..8 {
                segments[i] = segments[i].to_be();
            }
            let bytes = unsafe { as_bytes(&segments) };
            let mut res = [0; 16];
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), res.as_mut_ptr(), bytes.len());
            }
            return Ok(Address(res, 16));
        }
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() == 6 {
            let mut bytes = [0; 16];
            for i in 0..6 {
                bytes[i] = try!(u8::from_str_radix(&parts[i], 16).map_err(|_| Error::ParseError("Failed to parse mac")));
            }
            return Ok(Address(bytes, 6));
        }
        return Err(Error::ParseError("Failed to parse address"))
    }
}


#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Clone)]
pub struct Range {
    pub base: Address,
    pub prefix_len: u8
}

impl FromStr for Range {
    type Err=Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let pos = match text.find("/") {
            Some(pos) => pos,
            None => return Err(Error::ParseError("Invalid range format"))
        };
        let prefix_len = try!(u8::from_str(&text[pos+1..])
            .map_err(|_| Error::ParseError("Failed to parse prefix length")));
        let base = try!(Address::from_str(&text[..pos]));
        Ok(Range{base: base, prefix_len: prefix_len})
    }
}


#[derive(RustcDecodable, Debug, Clone, Copy)]
pub enum Type {
    Tun, Tap
}
impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Type::Tun => write!(formatter, "tun"),
            &Type::Tap => write!(formatter, "tap"),
        }
    }
}


#[derive(RustcDecodable, Debug)]
pub enum Mode {
    Normal, Hub, Switch, Router
}
impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Mode::Normal => write!(formatter, "normal"),
            &Mode::Hub => write!(formatter, "hub"),
            &Mode::Switch => write!(formatter, "switch"),
            &Mode::Router => write!(formatter, "router"),
        }
    }
}

pub trait Table {
    fn learn(&mut self, Address, Option<u8>, SocketAddr);
    fn lookup(&mut self, &Address) -> Option<SocketAddr>;
    fn housekeep(&mut self);
    fn remove_all(&mut self, SocketAddr);
}

pub trait Protocol: Sized {
    fn parse(&[u8]) -> Result<(Address, Address), Error>;
}

#[derive(Debug)]
pub enum Error {
    ParseError(&'static str),
    WrongNetwork(Option<NetworkId>),
    SocketError(&'static str),
    TunTapDevError(&'static str),
    CryptoError(&'static str)
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            &Error::ParseError(ref msg) => write!(formatter, "{}", msg),
            &Error::SocketError(ref msg) => write!(formatter, "{}", msg),
            &Error::TunTapDevError(ref msg) => write!(formatter, "{}", msg),
            &Error::CryptoError(ref msg) => write!(formatter, "{}", msg),
            &Error::WrongNetwork(Some(net)) => write!(formatter, "wrong network id: {}", net),
            &Error::WrongNetwork(None) => write!(formatter, "wrong network id: none"),
        }
    }
}

#[test]
fn address_fmt() {
    assert_eq!(format!("{:?}", Address([120,45,22,5,0,0,0,0,0,0,0,0,0,0,0,0], 4)), "120.45.22.5");
    assert_eq!(format!("{:?}", Address([120,45,22,5,1,2,0,0,0,0,0,0,0,0,0,0], 6)), "78:2d:16:05:01:02");
    assert_eq!(format!("{:?}", Address([3,56,120,45,22,5,1,2,0,0,0,0,0,0,0,0], 8)), "vlan824/78:2d:16:05:01:02");
    assert_eq!(format!("{:?}", Address([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], 16)), "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
}
