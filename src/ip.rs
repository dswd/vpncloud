use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};

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

    pub fn lookup(&self, bytes: Vec<u8>) -> Option<SocketAddr> {
        let mut len = bytes.len()/2 * 2;
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
