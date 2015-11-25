use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};
use std::io::Read;
use std::ptr;

use super::types::{Protocol, Error, Table, Address};


#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        if data.len() < 1 {
            return Err(Error::ParseError("Empty header"));
        }
        let version = data[0] >> 4;
        let mut src = [0; 16];
        let mut dst = [0; 16];
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::ParseError("Truncated header"));
                }
                unsafe {
                    ptr::copy_nonoverlapping(data[12..].as_ptr(), src.as_mut_ptr(), 4);
                    ptr::copy_nonoverlapping(data[16..].as_ptr(), dst.as_mut_ptr(), 4);
                }
                Ok((Address(src, 4), Address(dst, 4)))
            },
            6 => {
                if data.len() < 40 {
                    return Err(Error::ParseError("Truncated header"));
                }
                unsafe {
                    ptr::copy_nonoverlapping(data[8..].as_ptr(), src.as_mut_ptr(), 16);
                    ptr::copy_nonoverlapping(data[24..].as_ptr(), dst.as_mut_ptr(), 16);
                }
                Ok((Address(src, 16), Address(dst, 16)))
            },
            _ => Err(Error::ParseError("Invalid version"))
        }
    }
}


struct RoutingEntry {
    address: SocketAddr,
    bytes: [u8; 16],
    prefix_len: u8
}

pub struct RoutingTable(HashMap<[u8; 16], Vec<RoutingEntry>>);

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable(HashMap::new())
    }
}

impl Table for RoutingTable {
    fn learn(&mut self, addr: Address, prefix_len: Option<u8>, address: SocketAddr) {
        let prefix_len = match prefix_len {
            Some(val) => val,
            None => addr.0.len() as u8 * 8
        };
        info!("New routing entry: {:?}/{} => {}", addr, prefix_len, address);
        let group_len = (prefix_len as usize / 16) * 2;
        assert!(group_len <= 16);
        let mut group_bytes = [0; 16];
        unsafe { ptr::copy_nonoverlapping(addr.0.as_ptr(), group_bytes.as_mut_ptr(), group_len) };

        let routing_entry = RoutingEntry{address: address, bytes: addr.0, prefix_len: prefix_len};
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.0.len()/2 * 2;
        for i in 0..(len/2)+1 {
            if let Some(group) = self.0.get(&addr.0[0..len-2*i]) {
                for entry in group {
                    if entry.bytes.len() != addr.0.len() {
                        continue;
                    }
                    let mut match_len = 0;
                    for i in 0..addr.0.len() {
                        let b = addr.0[i] ^ entry.bytes[i];
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

    fn housekeep(&mut self) {
        //nothing to do
    }

    fn remove_all(&mut self, _addr: SocketAddr) {
        unimplemented!()
    }
}
