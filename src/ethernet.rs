use std::net::SocketAddr;
use std::collections::HashMap;

use super::types::{Error, Table, Protocol, Address};
use super::util::{now, Time, Duration};

#[derive(PartialEq)]
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
            for i in 0..6 {
                src[i+2] = src_data[i];
                dst[i+2] = dst_data[i];
            }
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

pub struct SwitchTable {
    table: HashMap<Address, SwitchTableValue>,
    cache: Option<(Address, SocketAddr)>,
    timeout: Duration
}

impl SwitchTable {
    pub fn new(timeout: Duration) -> Self {
        SwitchTable{table: HashMap::new(), cache: None, timeout: timeout}
    }
}

impl Table for SwitchTable {
    fn housekeep(&mut self) {
        let now = now();
        let mut del: Vec<Address> = Vec::new();
        for (key, val) in &self.table {
            if val.timeout < now {
                del.push(key.clone());
            }
        }
        for key in del {
            info!("Forgot address {:?}", key);
            self.table.remove(&key);
        }
        self.cache = None;
    }

    #[inline]
    fn learn(&mut self, key: Address, _prefix_len: Option<u8>, addr: SocketAddr) {
        let value = SwitchTableValue{address: addr, timeout: now()+self.timeout as Time};
        if self.table.insert(key.clone(), value).is_none() {
            info!("Learned address {:?} => {}", key, addr);
        }
    }

    #[inline]
    fn lookup(&mut self, key: &Address) -> Option<SocketAddr> {
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
    assert_eq!(src, Address{data: [1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0], len: 6});
    assert_eq!(dst, Address{data: [6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], len: 6});
}

#[test]
fn with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address{data: [4,210,1,2,3,4,5,6,0,0,0,0,0,0,0,0], len: 8});
    assert_eq!(dst, Address{data: [4,210,6,5,4,3,2,1,0,0,0,0,0,0,0,0], len: 8});
}
