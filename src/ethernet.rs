// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::SocketAddr;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::hash::BuildHasherDefault;
use std::io::{self, Write};
use std::marker::PhantomData;

use fnv::FnvHasher;

use super::types::{Error, Table, Protocol, Address};
use super::util::{TimeSource, Time, Duration};

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
            let src = Address::read_from_fixed(src_data, 6)?;
            let dst = Address::read_from_fixed(dst_data, 6)?;
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
pub struct SwitchTable<TS> {
    /// The table storing the actual mapping
    table: HashMap<Address, SwitchTableValue, Hash>,
    /// Timeout period for forgetting learnt addresses
    timeout: Duration,
    // Timeout period for not overwriting learnt addresses
    protection_period: Duration,
    _dummy_ts: PhantomData<TS>
}

impl<TS: TimeSource> SwitchTable<TS> {
    /// Creates a new switch table
    pub fn new(timeout: Duration, protection_period: Duration) -> Self {
        Self{table: HashMap::default(), timeout, protection_period, _dummy_ts: PhantomData}
    }
}

impl<TS: TimeSource> Table for SwitchTable<TS> {
    /// Forget addresses that have not been seen for the configured timeout
    fn housekeep(&mut self) {
        let now = TS::now();
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

    /// Write out the table
    fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        let now = TS::now();
        writeln!(out, "Switch table:")?;
        for (addr, val) in &self.table {
            writeln!(out, " - {} => {} (ttl: {} s)", addr, val.address, val.timeout - now)?;
        }
        Ok(())
    }

    /// Learns the given address, inserting it in the hash map
    #[inline]
    fn learn(&mut self, key: Address, _prefix_len: Option<u8>, addr: SocketAddr) {
        let deadline = TS::now() + Time::from(self.timeout);
        match self.table.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(SwitchTableValue{address: addr, timeout: deadline});
                info!("Learned address {} => {}", key, addr);
            },
            Entry::Occupied(mut entry) => {
                let mut entry = entry.get_mut();
                if entry.timeout + Time::from(self.protection_period) > deadline {
                    // Do not override recently learnt entries
                    return
                }
                entry.timeout = deadline;
                entry.address = addr;
            }
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


#[cfg(test)] use std::str::FromStr;
#[cfg(test)] use std::net::ToSocketAddrs;
#[cfg(test)] use super::util::MockTimeSource;

#[test]
fn decode_frame_without_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address{data: [1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0], len: 6});
    assert_eq!(dst, Address{data: [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], len: 6});
}

#[test]
fn decode_frame_with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address{data: [4,210,1,2,3,4,5,6,0,0,0,0,0,0,0,0], len: 8});
    assert_eq!(dst, Address{data: [4,210,6,5,4,3,2,1,0,0,0,0,0,0,0,0], len: 8});
}

#[test]
fn decode_invalid_frame() {
    assert!(Frame::parse(&[6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8]).is_ok());
    // truncated frame
    assert!(Frame::parse(&[]).is_err());
    // truncated vlan frame
    assert!(Frame::parse(&[6,5,4,3,2,1,1,2,3,4,5,6,0x81,0x00]).is_err());
}

#[test]
fn switch() {
    MockTimeSource::set_time(1000);
    let mut table = SwitchTable::<MockTimeSource>::new(10, 1);
    let addr = Address::from_str("12:34:56:78:90:ab").unwrap();
    let peer = "1.2.3.4:5678".to_socket_addrs().unwrap().next().unwrap();
    let peer2 = "1.2.3.5:7890".to_socket_addrs().unwrap().next().unwrap();
    assert!(table.lookup(&addr).is_none());
    MockTimeSource::set_time(1000);
    table.learn(addr.clone(), None, peer.clone());
    assert_eq!(table.lookup(&addr), Some(peer));
    MockTimeSource::set_time(1000);
    table.learn(addr.clone(), None, peer2.clone());
    assert_eq!(table.lookup(&addr), Some(peer));
    MockTimeSource::set_time(1010);
    table.learn(addr.clone(), None, peer2.clone());
    assert_eq!(table.lookup(&addr), Some(peer2));
}
