// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::SocketAddr;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

use super::types::{Error, Table, Protocol, Address};
use super::util::{now, Time, Duration};

pub struct Frame;

impl Protocol for Frame {
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        if data.len() < 14 {
            return Err(Error::ParseError("Frame is too short"));
        }
        let mut pos = 0;
        let dst_data = &data[pos..pos+6];
        pos += 6;
        let src_data = &data[pos..pos+6];
        pos += 6;
        if data[pos] == 0x81 && data[pos+1] == 0x00 {
            pos += 2;
            if data.len() < pos + 2 {
                return Err(Error::ParseError("Vlan frame is too short"));
            }
            let mut src = [0; 16];
            let mut dst = [0; 16];
            src[0] = data[pos]; src[1] = data[pos+1];
            dst[0] = data[pos]; dst[1] = data[pos+1];
            src[2..8].clone_from_slice(src_data);
            dst[2..8].clone_from_slice(dst_data);
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

pub struct SwitchTable {
    table: HashMap<Address, SwitchTableValue, Hash>,
    cache: Option<(Address, SocketAddr)>,
    timeout: Duration
}

impl SwitchTable {
    pub fn new(timeout: Duration) -> Self {
        SwitchTable{table: HashMap::default(), cache: None, timeout: timeout}
    }
}

impl Table for SwitchTable {
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
        self.cache = None;
    }

    #[inline]
    fn learn(&mut self, key: Address, _prefix_len: Option<u8>, addr: SocketAddr) {
        let value = SwitchTableValue{address: addr, timeout: now()+self.timeout as Time};
        if self.table.insert(key, value).is_none() {
            info!("Learned address {} => {}", key, addr);
        }
    }

    #[inline]
    fn lookup(&mut self, key: &Address) -> Option<SocketAddr> {
        match self.table.get(key) {
            Some(value) => Some(value.address),
            None => None
        }
    }

    #[inline]
    fn remove(&mut self, key: &Address) -> bool {
        self.table.remove(key).is_some()
    }

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
