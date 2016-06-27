// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::SocketAddr;
use std::collections::{hash_map, HashMap};
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

use super::types::{Protocol, Error, Table, Address};


/// An IP packet dissector
///
/// This dissector is able to extract the source and destination ip addresses of ipv4 packets and
/// ipv6 packets.
#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    /// Parses an ip packet and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ipv4 and ipv6 packet.
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

/// A prefix-based routing table
///
/// This table contains a mapping of prefixes associated with peer addresses.
/// To speed up lookup, prefixes are grouped into full bytes and map to a list of prefixes with
/// more fine grained prefixes.
#[derive(Default)]
pub struct RoutingTable(HashMap<Vec<u8>, Vec<RoutingEntry>, Hash>);

impl RoutingTable {
    /// Creates a new empty routing table
    pub fn new() -> Self {
        RoutingTable(HashMap::default())
    }
}

impl Table for RoutingTable {
    /// Learns the given address, inserting it in the hash map
    fn learn(&mut self, addr: Address, prefix_len: Option<u8>, address: SocketAddr) {
        // If prefix length is not set, treat the whole addess as significant
        let prefix_len = match prefix_len {
            Some(val) => val,
            None => addr.len * 8
        };
        info!("New routing entry: {}/{} => {}", addr, prefix_len, address);
        // Round the prefix length down to the next multiple of 8 and extraxt a prefix of that
        // length.
        let group_len = prefix_len as usize / 8;
        assert!(group_len <= 16);
        let mut group_bytes = Vec::with_capacity(group_len);
        group_bytes.extend_from_slice(&addr.data[0..group_len]);
        // Create an entry
        let routing_entry = RoutingEntry{address: address, bytes: addr.data, prefix_len: prefix_len};
        // Add the entry to the routing table, creating a new list of the prefix group is empty.
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => { entry.insert(vec![routing_entry]); () }
        }
    }

    /// Retrieves a peer for an address if it is inside the routing table
    fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.len as usize;
        let mut found = None;
        let mut found_len: isize = -1;
        // Iterate over the prefix length from longest prefix group to shortest (empty) prefix
        // group
        for i in 0..len+1 {
            if let Some(group) = self.0.get(&addr.data[0..len-i]) {
                // If the group is not empty, check every entry
                for entry in group {
                    // Calculate the match length of the address and the prefix
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
                    // If the full prefix matches and the match is longer than the longest prefix
                    // found so far, remember the peer
                    if match_len as u8 >= entry.prefix_len && match_len as isize > found_len {
                        found = Some(entry.address);
                        found_len = match_len as isize;
                    }
                }
            }
        }
        // Return the longest match found (if any).
        found
    }

    /// This method does not do anything.
    fn housekeep(&mut self) {
        //nothing to do
    }

    /// Removes an address from the map and returns whether something has been removed
    #[inline]
    fn remove(&mut self, _addr: &Address) -> bool {
        // Do nothing, removing single address from prefix-based routing tables does not make sense
        false
    }

    /// Removed all addresses associated with a certain peer
    fn remove_all(&mut self, addr: &SocketAddr) {
        for (_key, entry) in &mut self.0 {
            entry.retain(|entr| &entr.address != addr);
        }
    }
}
