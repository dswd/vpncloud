use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, AddrParseError, ToSocketAddrs};
use std::collections::{hash_map, HashMap};
use std::ptr;
use std::path::Path;
use std::fs::File;
use std::io::{Result as IoResult, Read, BufRead, BufReader};
use std::str::FromStr;

use regex::Regex;

use super::cloud::{Protocol, Error, Table};
use super::util::{as_obj, as_bytes};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr)
}

impl IpAddress {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            &IpAddress::V4(addr) => {
                let ip = addr.octets();
                let mut res = Vec::with_capacity(4);
                unsafe {
                    res.set_len(4);
                    ptr::copy_nonoverlapping(ip.as_ptr(), res.as_mut_ptr(), ip.len());
                }
                res
            },
            &IpAddress::V6(addr) => {
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
                res
            }
        }
    }

    pub fn from_str(addr: &str) -> Result<Self, AddrParseError> {
        let ipv4 = Ipv4Addr::from_str(addr).map(|addr| IpAddress::V4(addr));
        let ipv6 = Ipv6Addr::from_str(addr).map(|addr| IpAddress::V6(addr));
        ipv4.or(ipv6)
    }
}


pub struct InternetProtocol;

impl Protocol for InternetProtocol {
    type Address = IpAddress;

    fn parse(data: &[u8]) -> Result<(IpAddress, IpAddress), Error> {
        if data.len() < 1 {
            return Err(Error::ParseError("Empty header"));
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::ParseError("Truncated header"));
                }
                let src_data = unsafe { as_obj::<[u8; 4]>(&data[12..]) };
                let src = Ipv4Addr::new(src_data[0], src_data[1], src_data[2], src_data[3]);
                let dst_data = unsafe { as_obj::<[u8; 4]>(&data[16..]) };
                let dst = Ipv4Addr::new(dst_data[0], dst_data[1], dst_data[2], dst_data[3]);
                Ok((IpAddress::V4(src), IpAddress::V4(dst)))
            },
            6 => {
                if data.len() < 40 {
                    return Err(Error::ParseError("Truncated header"));
                }
                let src_data = unsafe { as_obj::<[u16; 8]>(&data[8..]) };
                let src = Ipv6Addr::new(
                    u16::from_be(src_data[0]), u16::from_be(src_data[1]),
                    u16::from_be(src_data[2]), u16::from_be(src_data[3]),
                    u16::from_be(src_data[4]), u16::from_be(src_data[5]),
                    u16::from_be(src_data[6]), u16::from_be(src_data[7]),
                );
                let dst_data = unsafe { as_obj::<[u16; 8]>(&data[24..]) };
                let dst = Ipv6Addr::new(
                    u16::from_be(dst_data[0]), u16::from_be(dst_data[1]),
                    u16::from_be(dst_data[2]), u16::from_be(dst_data[3]),
                    u16::from_be(dst_data[4]), u16::from_be(dst_data[5]),
                    u16::from_be(dst_data[6]), u16::from_be(dst_data[7]),
                );
                Ok((IpAddress::V6(src), IpAddress::V6(dst)))
            },
            _ => Err(Error::ParseError("Invalid version"))
        }
    }
}



struct RoutingEntry {
    address: SocketAddr,
    bytes: Vec<u8>,
    prefix_len: u8
}

pub struct RoutingTable(HashMap<Vec<u8>, Vec<RoutingEntry>>);

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable(HashMap::new())
    }

    pub fn add(&mut self, bytes: Vec<u8>, prefix_len: u8, address: SocketAddr) {
        let group_len = (prefix_len as usize / 16) * 2;
        let group_bytes: Vec<u8> = bytes[..group_len].iter().map(|b| *b).collect();
        let routing_entry = RoutingEntry{address: address, bytes: bytes, prefix_len: prefix_len};
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    pub fn load_from(&mut self, path: &Path) -> IoResult<()> {
        let pattern = Regex::new(r"(?P<base>[^/]+)/(?P<prefix>\d+)\s=>\s(?P<peer>.+)").unwrap();
        let file = try!(File::open(path));
        let mut reader = BufReader::new(file);
        loop {
            let mut s = String::new();
            let res = try!(reader.read_line(&mut s));
            if res == 0 {
                break;
            }
            let captures = match pattern.captures(&s) {
                Some(captures) => captures,
                None => {
                    error!("Failed to parse routing table entry: {}", s);
                    continue
                }
            };
            let base = match IpAddress::from_str(captures.name("base").unwrap()) {
                Ok(addr) => addr.to_bytes(),
                Err(e) => {
                    error!("Failed to parse base address: {}", e);
                    continue
                }
            };
            let prefix_len = match u8::from_str(captures.name("prefix").unwrap()) {
                Ok(num) => num,
                Err(e) => {
                    error!("Failed to parse prefix length: {}", e);
                    continue
                }
            };
            let peer = match captures.name("peer").unwrap().to_socket_addrs().map(|mut r| r.next()) {
                Ok(Some(addr)) => addr,
                _ => {
                    error!("Failed to parse peer address");
                    continue
                }
            };
            self.add(base, prefix_len, peer);
        }
        Ok(())
    }

    pub fn lookup_bytes(&self, bytes: &[u8]) -> Option<SocketAddr> {
        let len = bytes.len()/2 * 2;
        for i in 0..len/2 {
            if let Some(group) = self.0.get(&bytes[0..len-2*i]) {
                for entry in group {
                    if entry.bytes.len() != bytes.len() {
                        continue;
                    }
                    let mut match_len = 0;
                    for i in 0..bytes.len() {
                        let b = bytes[i] ^ entry.bytes[i];
                        if b == 0 {
                            match_len += 8;
                        } else {
                            match_len += b.leading_zeros();
                            break;
                        }
                    }
                    if match_len as u8 >= entry.prefix_len {
                        return Some(entry.address);
                    }
                }
            }
        }
        None
    }
}

impl Table for RoutingTable {
    type Address = IpAddress;

    fn learn(&mut self, _src: Self::Address, _addr: SocketAddr) {
        //nothing to do
    }

    fn lookup(&self, dst: &Self::Address) -> Option<SocketAddr> {
        self.lookup_bytes(&dst.to_bytes())
    }

    fn housekeep(&mut self) {
        //nothin to do
    }
}
