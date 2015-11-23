use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};
use std::io::Read;

use super::types::{Protocol, Error, Table, Address};
use super::util::to_vec;

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
                if data.len() < 20 {
                    return Err(Error::ParseError("Truncated header"));
                }
                Ok((Address(to_vec(&data[12..16])), Address(to_vec(&data[16..20]))))
            },
            6 => {
                if data.len() < 40 {
                    return Err(Error::ParseError("Truncated header"));
                }
                Ok((Address(to_vec(&data[8..24])), Address(to_vec(&data[24..40]))))
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
}

impl Table for RoutingTable {
    fn learn(&mut self, addr: Address, prefix_len: Option<u8>, address: SocketAddr) {
        let prefix_len = match prefix_len {
            Some(val) => val,
            None => addr.0.len() as u8 * 8
        };
        let group_len = (prefix_len as usize / 16) * 2;
        let group_bytes: Vec<u8> = addr.0[..group_len].iter().map(|b| *b).collect();
        let routing_entry = RoutingEntry{address: address, bytes: addr.0, prefix_len: prefix_len};
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    fn lookup(&self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.0.len()/2 * 2;
        for i in 0..len/2 {
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
        //nothin to do
    }

    fn remove_all(&mut self, _addr: SocketAddr) {
        unimplemented!()
    }
}
