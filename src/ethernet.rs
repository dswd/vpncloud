// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::SocketAddr;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

use super::types::{Error, Table, Protocol, Address};
use super::util::{now, Time, Duration};

/// An ethernet frame dissector
///
/// This dissector is able to extract the source and destination addresses of ethernet frames.
///
/// If the ethernet frame contains a VLAN tag, both addresses will be prefixed with that tag,
/// resulting in 8-byte addresses. Additional nested tags will be ignored.
pub struct Frame;

impl Protocol for Frame {
    /// Parses an ethernet frame and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ethernet frame.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        if data.len() < 14 {
            return Err(Error::Parse("Frame is too short"));
        }
        let mut pos = 0;
        let dst_data = &data[pos..pos+6];
        pos += 6;
        let src_data = &data[pos..pos+6];
        pos += 6;
        if data[pos] == 0x81 && data[pos+1] == 0x00 {
            pos += 2;
            if data.len() < pos + 2 {
                return Err(Error::Parse("Vlan frame is too short"));
            }
            let mut src = [0; 16];
            let mut dst = [0; 16];
            src[0] = data[pos]; src[1] = data[pos+1];
            dst[0] = data[pos]; dst[1] = data[pos+1];
            src[2..8].copy_from_slice(src_data);
            dst[2..8].copy_from_slice(dst_data);
            Ok((Address{data: src, len: 8}, Address{data: dst, len: 8}))
        } else {
            let src = try!(Address::read_from_fixed(&src_data, 6));
            let dst = try!(Address::read_from_fixed(&dst_data, 6));
            Ok((src, dst))
        }
    }
}


struct SwitchTableValue {
    address: SocketAddr,
    timeout: Time
}

type Hash = BuildHasherDefault<FnvHasher>;


/// A table used to implement a learning switch
///
/// This table is a simple hash map between an address and the destination peer. It learns
/// addresses as they are seen and forgets them after some time.
pub struct SwitchTable {
    /// The table storing the actual mapping
    table: HashMap<Address, SwitchTableValue, Hash>,
    /// Timeout period for forgetting learnt addresses
    timeout: Duration
}

impl SwitchTable {
    /// Creates a new switch table
    pub fn new(timeout: Duration) -> Self {
        SwitchTable{table: HashMap::default(), timeout: timeout}
    }
}

impl Table for SwitchTable {
    /// Forget addresses that have not been seen for the configured timeout
    fn housekeep(&mut self) {
        let now = now();
        let mut del: Vec<Address> = Vec::new();
        for (key, val) in &self.table {
            if val.timeout < now {
                del.push(*key);
            }
        }
        for key in del {
            info!("Forgot address {}", key);
            self.table.remove(&key);
        }
    }

    /// Learns the given address, inserting it in the hash map
    #[inline]
    fn learn(&mut self, key: Address, _prefix_len: Option<u8>, addr: SocketAddr) {
        let value = SwitchTableValue{address: addr, timeout: now()+self.timeout as Time};
        if self.table.insert(key, value).is_none() {
            info!("Learned address {} => {}", key, addr);
        }
    }

    /// Retrieves a peer for an address if it is inside the hash map
    #[inline]
    fn lookup(&mut self, key: &Address) -> Option<SocketAddr> {
        match self.table.get(key) {
            Some(value) => Some(value.address),
            None => None
        }
    }

    /// Removes an address from the map and returns whether something has been removed
    #[inline]
    fn remove(&mut self, key: &Address) -> bool {
        self.table.remove(key).is_some()
    }

    /// Removed all addresses associated with a certain peer
    fn remove_all(&mut self, addr: &SocketAddr) {
        let mut remove = Vec::new();
        for (key, val) in &self.table {
            if &val.address == addr {
                remove.push(*key);
            }
        }
        for key in remove {
            self.table.remove(&key);
        }
    }
}
