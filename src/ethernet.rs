use std::{mem, fmt};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::io::Write;

use super::cloud::{Error, Table, Protocol, Address};
use super::util::as_obj;

use time::{Duration, SteadyTime};


#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl fmt::Debug for Mac {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

pub type VlanId = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthAddr {
    pub mac: Mac,
    pub vlan: Option<VlanId>
}

impl Address for EthAddr {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, Error> {
        unimplemented!()
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}


#[derive(PartialEq)]
pub struct Frame;

impl Protocol for Frame {
    type Address = EthAddr;

    fn parse(data: &[u8]) -> Result<(EthAddr, EthAddr), Error> {
        if data.len() < 14 {
            return Err(Error::ParseError("Frame is too short"));
        }
        let mut pos = 0;
        let dst = *unsafe { as_obj::<Mac>(&data[pos..]) };
        pos += mem::size_of::<Mac>();
        let src = *unsafe { as_obj::<Mac>(&data[pos..]) };
        pos += mem::size_of::<Mac>();
        let mut vlan = None;
        if data[pos] == 0x81 && data[pos+1] == 0x00 {
            pos += 2;
            if data.len() < pos + 2 {
                return Err(Error::ParseError("Vlan frame is too short"));
            }
            vlan = Some(u16::from_be(* unsafe { as_obj::<u16>(&data[pos..]) }));
        }
        Ok((EthAddr{mac: src, vlan: vlan}, EthAddr{mac: dst, vlan: vlan}))
    }
}


struct MacTableValue {
    address: SocketAddr,
    timeout: SteadyTime
}


pub struct MacTable {
    table: HashMap<EthAddr, MacTableValue>,
    timeout: Duration
}

impl MacTable {
    pub fn new(timeout: Duration) -> MacTable {
        MacTable{table: HashMap::new(), timeout: timeout}
    }
}

impl Table for MacTable {
    type Address = EthAddr;

    fn housekeep(&mut self) {
        let now = SteadyTime::now();
        let mut del: Vec<Self::Address> = Vec::new();
        for (&key, val) in &self.table {
            if val.timeout < now {
                del.push(key);
            }
        }
        for key in del {
            info!("Forgot mac: {:?} (vlan {:?})", key.mac, key.vlan);
            self.table.remove(&key);
        }
    }

    fn learn(&mut self, key: Self::Address, addr: SocketAddr) {
       let value = MacTableValue{address: addr, timeout: SteadyTime::now()+self.timeout};
       if self.table.insert(key, value).is_none() {
           info!("Learned mac: {:?} (vlan {:?}) => {}", key.mac, key.vlan, addr);
       }
    }

    fn lookup(&self, key: &Self::Address) -> Option<SocketAddr> {
       match self.table.get(key) {
           Some(value) => Some(value.address),
           None => None
       }
    }

    fn remove_all(&mut self, _addr: SocketAddr) {
        unimplemented!()
    }
}


#[test]
fn without_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, EthAddr{mac: Mac([1,2,3,4,5,6]), vlan: None});
    assert_eq!(dst, EthAddr{mac: Mac([6,5,4,3,2,1]), vlan: None});
}

#[test]
fn with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, EthAddr{mac: Mac([1,2,3,4,5,6]), vlan: Some(1234)});
    assert_eq!(dst, EthAddr{mac: Mac([6,5,4,3,2,1]), vlan: Some(1234)});
}
