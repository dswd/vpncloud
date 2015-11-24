use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::hash::Hasher;
use std::{fmt, ptr};
use std::str::FromStr;

use super::util::{as_bytes, as_obj};

pub type NetworkId = u64;

#[derive(PartialEq, PartialOrd, Eq, Ord, Hash, Clone)]
pub struct Address(pub Vec<u8>);

impl fmt::Debug for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self.0.len() {
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
            let mut res = Vec::with_capacity(4);
            unsafe {
                res.set_len(4);
                ptr::copy_nonoverlapping(ip.as_ptr(), res.as_mut_ptr(), ip.len());
            }
            return Ok(Address(res));
        }
        if let Ok(addr) = Ipv6Addr::from_str(text) {
            let mut segments = addr.segments();
            for i in 0..8 {
                segments[i] = segments[i].to_be();
            }
            let bytes = unsafe { as_bytes(&segments) };
            let mut res = Vec::with_capacity(16);
            unsafe {
                res.set_len(16);
                ptr::copy_nonoverlapping(bytes.as_ptr(), res.as_mut_ptr(), bytes.len());
            }
            return Ok(Address(res));
        }
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() == 6 {
            let mut bytes = Vec::with_capacity(6);
            for i in 0..6 {
                bytes.push(try!(u8::from_str_radix(&parts[i], 16).map_err(|_| Error::ParseError("Failed to parse mac"))));
            }
            return Ok(Address(bytes));
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

#[derive(RustcDecodable, Debug)]
pub enum Mode {
    Normal, Hub, Switch, Router
}

pub trait Table {
    fn learn(&mut self, Address, Option<u8>, SocketAddr);
    fn lookup(&self, &Address) -> Option<SocketAddr>;
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


#[test]
fn address_fmt() {
    assert_eq!(format!("{:?}", Address(vec![120,45,22,5])), "120.45.22.5");
    assert_eq!(format!("{:?}", Address(vec![120,45,22,5,1,2])), "78:2d:16:05:01:02");
    assert_eq!(format!("{:?}", Address(vec![3,56,120,45,22,5,1,2])), "vlan824/78:2d:16:05:01:02");
    assert_eq!(format!("{:?}", Address(vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])), "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
}
