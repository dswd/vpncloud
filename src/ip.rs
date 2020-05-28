// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::{hash_map, HashMap},
    hash::BuildHasherDefault,
    io::{self, Write},
    net::SocketAddr
};

use fnv::FnvHasher;

use super::types::{Address, Error, Protocol, Table};


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
        if data.is_empty() {
            return Err(Error::Parse("Empty header"))
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::Parse("Truncated IPv4 header"))
                }
                let src = Address::read_from_fixed(&data[12..], 4)?;
                let dst = Address::read_from_fixed(&data[16..], 4)?;
                Ok((src, dst))
            }
            6 => {
                if data.len() < 40 {
                    return Err(Error::Parse("Truncated IPv6 header"))
                }
                let src = Address::read_from_fixed(&data[8..], 16)?;
                let dst = Address::read_from_fixed(&data[24..], 16)?;
                Ok((src, dst))
            }
            _ => Err(Error::Parse("Invalid version"))
        }
    }
}


struct RoutingEntry {
    address: SocketAddr,
    bytes: Address,
    prefix_len: u8
}

type Hash = BuildHasherDefault<FnvHasher>;

/// A prefix-based routing table
///
/// This table contains a mapping of prefixes associated with peer addresses.
/// To speed up lookup, prefixes are grouped into full bytes and map to a list of prefixes with
/// more fine grained prefixes.
#[derive(Default)]
pub struct RoutingTable(HashMap<[u8; 16], Vec<RoutingEntry>, Hash>);

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
        let mut group_bytes = [0; 16];
        group_bytes[..group_len].copy_from_slice(&addr.data[..group_len]);
        // Create an entry
        let routing_entry = RoutingEntry { address, bytes: addr, prefix_len };
        // Add the entry to the routing table, creating a new list of the prefix group is empty.
        match self.0.entry(group_bytes) {
            hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(routing_entry),
            hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![routing_entry]);
            }
        }
    }

    /// Retrieves a peer for an address if it is inside the routing table
    #[allow(unknown_lints, clippy::needless_range_loop)]
    fn lookup(&mut self, addr: &Address) -> Option<SocketAddr> {
        let len = addr.len as usize;
        let mut found = None;
        let mut found_len: isize = -1;
        // Iterate over the prefix length from longest prefix group to shortest (empty) prefix
        // group
        let mut group_bytes = addr.data;
        for i in len..16 {
            group_bytes[i] = 0;
        }
        for i in (0..=len).rev() {
            if i < len {
                group_bytes[i] = 0;
            }
            if let Some(group) = self.0.get(&group_bytes) {
                // If the group is not empty, check every entry
                for entry in group {
                    // Calculate the match length of the address and the prefix
                    let mut match_len = 0;
                    for j in 0..addr.len as usize {
                        let b = addr.data[j] ^ entry.bytes.data[j];
                        if b == 0 {
                            match_len += 8;
                        } else {
                            match_len += b.leading_zeros();
                            break
                        }
                    }
                    // If the full prefix matches and the match is longer than the longest prefix
                    // found so far, remember the peer
                    if match_len as u8 >= entry.prefix_len && entry.prefix_len as isize > found_len {
                        found = Some(entry.address);
                        found_len = entry.prefix_len as isize;
                    }
                }
            }
        }
        // Return the longest match found (if any).
        found
    }

    /// This method does not do anything.
    fn housekeep(&mut self) {
        // nothing to do
    }

    /// Write out the table
    fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        writeln!(out, "Routing table:")?;
        for entries in self.0.values() {
            for entry in entries {
                writeln!(out, " - {}/{} => {}", entry.bytes, entry.prefix_len, entry.address)?;
            }
        }
        Ok(())
    }

    /// Removes an address from the map and returns whether something has been removed
    #[inline]
    fn remove(&mut self, _addr: &Address) -> bool {
        // Do nothing, removing single address from prefix-based routing tables does not make sense
        false
    }

    /// Removed all addresses associated with a certain peer
    fn remove_all(&mut self, addr: &SocketAddr) {
        for entry in &mut self.0.values_mut() {
            entry.retain(|entr| &entr.address != addr);
        }
    }
}


#[cfg(test)] use std::net::ToSocketAddrs;
#[cfg(test)] use std::str::FromStr;


#[test]
fn decode_ipv4_packet() {
    let data = [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
    assert_eq!(dst, Address { data: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
}

#[test]
fn decode_ipv6_packet() {
    let data = [
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1
    ];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6], len: 16 });
    assert_eq!(dst, Address { data: [0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1], len: 16 });
}

#[test]
fn decode_invalid_packet() {
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2]).is_ok());
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1
    ])
    .is_ok());
    // no data
    assert!(Packet::parse(&[]).is_err());
    // wrong version
    assert!(Packet::parse(&[0x20]).is_err());
    // truncated ipv4
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1]).is_err());
    // truncated ipv6
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2
    ])
    .is_err());
}


#[test]
fn routing_table_ipv4() {
    let mut table = RoutingTable::new();
    let peer1 = "1.2.3.4:1".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "1.2.3.4:2".to_socket_addrs().unwrap().next().unwrap();
    let peer3 = "1.2.3.4:3".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&Address::from_str("192.168.1.1").unwrap()).is_none());
    table.learn(Address::from_str("192.168.1.1").unwrap(), Some(32), peer1);
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    table.learn(Address::from_str("192.168.1.2").unwrap(), None, peer2);
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    table.learn(Address::from_str("192.168.1.0").unwrap(), Some(24), peer3);
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    table.learn(Address::from_str("192.168.0.0").unwrap(), Some(16), peer1);
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    table.learn(Address::from_str("0.0.0.0").unwrap(), Some(0), peer2);
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("192.168.1.3").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("1.2.3.4").unwrap()), Some(peer2));
    table.learn(Address::from_str("192.168.2.0").unwrap(), Some(27), peer3);
    assert_eq!(table.lookup(&Address::from_str("192.168.2.31").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("192.168.2.32").unwrap()), Some(peer1));
    table.learn(Address::from_str("192.168.2.0").unwrap(), Some(28), peer3);
    assert_eq!(table.lookup(&Address::from_str("192.168.2.1").unwrap()), Some(peer3));
}

#[test]
fn routing_table_ipv6() {
    let mut table = RoutingTable::new();
    let peer1 = "::1:1".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "::1:2".to_socket_addrs().unwrap().next().unwrap();
    let peer3 = "::1:3".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&Address::from_str("::1").unwrap()).is_none());
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap(), Some(128), peer1);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap(), None, peer2);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    table.learn(Address::from_str("dead:beef:dead:beef::").unwrap(), Some(64), peer3);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    table.learn(Address::from_str("dead:beef:dead:be00::").unwrap(), Some(56), peer1);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:1::").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:be01::").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    table.learn(Address::from_str("::").unwrap(), Some(0), peer2);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:1::").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:be01::").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:1").unwrap()), Some(peer1));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:2").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:3").unwrap()), Some(peer3));
    assert_eq!(table.lookup(&Address::from_str("::1").unwrap()), Some(peer2));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:be00").unwrap(), Some(123), peer2);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be1f").unwrap()), Some(peer2));
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be20").unwrap()), Some(peer3));
    table.learn(Address::from_str("dead:beef:dead:beef:dead:beef:dead:be00").unwrap(), Some(124), peer3);
    assert_eq!(table.lookup(&Address::from_str("dead:beef:dead:beef:dead:beef:dead:be01").unwrap()), Some(peer3));
}
