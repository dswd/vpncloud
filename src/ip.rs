use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use std::collections::{hash_map, HashMap};
use std::ptr;
use std::io::Read;
use std::str::FromStr;

use super::cloud::{Protocol, Error, Table, Address};
use super::util::{as_obj, as_bytes};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    V4Net(Ipv4Addr, u8),
    V6Net(Ipv6Addr, u8),
}

impl Address for IpAddress {
    fn to_bytes(&self) -> Vec<u8> {
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
            &IpAddress::V4Net(addr, prefix_len) => {
                let mut bytes = IpAddress::V4(addr).to_bytes();
                bytes.push(prefix_len);
                bytes
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
            },
            &IpAddress::V6Net(addr, prefix_len) => {
                let mut bytes = IpAddress::V6(addr).to_bytes();
                bytes.push(prefix_len);
                bytes
            }
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.len() {
            4 => Ok(IpAddress::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
            5 => Ok(IpAddress::V4Net(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]), bytes[4])),
            16 => {
                let data = unsafe { as_obj::<[u16; 8]>(&bytes) };
                Ok(IpAddress::V6(Ipv6Addr::new(
                    u16::from_be(data[0]), u16::from_be(data[1]),
                    u16::from_be(data[2]), u16::from_be(data[3]),
                    u16::from_be(data[4]), u16::from_be(data[5]),
                    u16::from_be(data[6]), u16::from_be(data[7]),
                )))
            },
            17 => {
                let data = unsafe { as_obj::<[u16; 8]>(&bytes) };
                Ok(IpAddress::V6Net(Ipv6Addr::new(
                    u16::from_be(data[0]), u16::from_be(data[1]),
                    u16::from_be(data[2]), u16::from_be(data[3]),
                    u16::from_be(data[4]), u16::from_be(data[5]),
                    u16::from_be(data[6]), u16::from_be(data[7]),
                ), bytes[16]))
            }
            _ => Err(Error::ParseError("Invalid address size"))
        }
    }
}

impl IpAddress {
    pub fn from_str(addr: &str) -> Result<Self, Error> {
        if let Some(pos) = addr.find("/") {
            let prefix_len = try!(u8::from_str(&addr[pos+1..])
                .map_err(|_| Error::ParseError("Failed to parse prefix length")));
            let addr = &addr[..pos];
            let ipv4 = Ipv4Addr::from_str(addr).map(|addr| IpAddress::V4Net(addr, prefix_len));
            let ipv6 = Ipv6Addr::from_str(addr).map(|addr| IpAddress::V6Net(addr, prefix_len));
            ipv4.or(ipv6).map_err(|_| Error::ParseError("Failed to parse address"))
        } else {
            let ipv4 = Ipv4Addr::from_str(addr).map(|addr| IpAddress::V4(addr));
            let ipv6 = Ipv6Addr::from_str(addr).map(|addr| IpAddress::V6(addr));
            ipv4.or(ipv6).map_err(|_| Error::ParseError("Failed to parse address"))
        }
    }
}

#[allow(dead_code)]
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
                Ok((try!(IpAddress::from_bytes(&data[12..16])), try!(IpAddress::from_bytes(&data[16..20]))))
            },
            6 => {
                if data.len() < 40 {
                    return Err(Error::ParseError("Truncated header"));
                }
                Ok((try!(IpAddress::from_bytes(&data[8..24])), try!(IpAddress::from_bytes(&data[24..40]))))
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

    fn learn(&mut self, src: Self::Address, addr: SocketAddr) {
        match src {
            IpAddress::V4(_) => (),
            IpAddress::V4Net(base, prefix_len) => {
                info!("Adding to routing table: {}/{} => {}", base, prefix_len, addr);
                self.add(IpAddress::V4(base).to_bytes(), prefix_len, addr);
            },
            IpAddress::V6(_) => (),
            IpAddress::V6Net(base, prefix_len) => {
                info!("Adding to routing table: {}/{} => {}", base, prefix_len, addr);
                self.add(IpAddress::V6(base).to_bytes(), prefix_len, addr);
            }
        }
    }

    fn lookup(&self, dst: &Self::Address) -> Option<SocketAddr> {
        self.lookup_bytes(&dst.to_bytes())
    }

    fn housekeep(&mut self) {
        //nothin to do
    }

    fn remove_all(&mut self, _addr: SocketAddr) {
        unimplemented!()
    }
}
