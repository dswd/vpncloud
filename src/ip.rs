// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};
use std::io::Read;
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

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
                if data.len() < 20 {
                    return Err(Error::ParseError("Truncated IPv4 header"));
                }
                let src = try!(Address::read_from_fixed(&data[12..], 4));
                let dst = try!(Address::read_from_fixed(&data[16..], 4));
                Ok((src, dst))
            },
            6 => {
                if data.len() < 40 {
                    return Err(Error::ParseError("Truncated IPv6 header"));
                }
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

type Hash = BuildHasherDefault<FnvHasher>;

pub struct RoutingTable(HashMap<Vec<u8>, Vec<RoutingEntry>, Hash>);

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable(HashMap::default())
    }
}

impl Table for RoutingTable {
    fn learn(&mut self, addr: Address, prefix_len: Option<u8>, address: SocketAddr) {
        let prefix_len = match prefix_len {
            Some(val) => val,
            None => addr.len * 8
        };
        info!("New routing entry: {}/{} => {}", addr, prefix_len, address);
        let group_len = prefix_len as usize / 8;
        assert!(group_len <= 16);
        let mut group_bytes = Vec::with_capacity(group_len);
        for i in 0..group_len {
            group_bytes.push(addr.data[i]);
        }
        let routing_entry = RoutingEntry{address: address, bytes: addr.data, prefix_len: prefix_len};
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.len as usize;
        let mut found = None;
        let mut found_len: isize = -1;
        for i in 0..len+1 {
            if let Some(group) = self.0.get(&addr.data[0..len-i]) {
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
                    if match_len as u8 >= entry.prefix_len && match_len as isize > found_len {
                        found = Some(entry.address);
                        found_len = match_len as isize;
                    }
                }
            }
        }
        found
    }

    fn housekeep(&mut self) {
        //nothing to do
    }

    fn remove_all(&mut self, _addr: SocketAddr) {
        unimplemented!()
    }
}
