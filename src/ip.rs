use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};
use std::io::Read;

use super::types::{Protocol, Error, Table, Address};


#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        if data.len() < 1 {
            return Err(Error::ParseError("Empty header"));
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                let src = try!(Address::read_from_fixed(&data[12..], 4));
                let dst = try!(Address::read_from_fixed(&data[16..], 4));
                Ok((src, dst))
            },
            6 => {
                let src = try!(Address::read_from_fixed(&data[8..], 16));
                let dst = try!(Address::read_from_fixed(&data[24..], 16));
                Ok((src, dst))
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
            None => addr.len * 8
        };
        info!("New routing entry: {:?}/{} => {}", addr, prefix_len, address);
        let group_len = (prefix_len as usize / 16) * 2;
        assert!(group_len <= 16);
        let mut group_bytes = [0; 16];
        for i in 0..group_len {
            group_bytes[i] = addr.data[i];
        }
        let routing_entry = RoutingEntry{address: address, bytes: addr.data, prefix_len: prefix_len};
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.len as usize/2 * 2;
        for i in 0..(len/2)+1 {
            if let Some(group) = self.0.get(&addr.data[0..len-2*i]) {
                for entry in group {
                    let mut match_len = 0;
                    for j in 0..addr.len as usize {
                        let b = addr.data[j] ^ entry.bytes[j];
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
