use std::ptr;
use std::net::SocketAddr;
use std::collections::HashMap;

use super::types::{Error, Table, Protocol, Address};

use time::{Duration, SteadyTime};


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
            unsafe {
                ptr::copy_nonoverlapping(data[pos..].as_ptr(), src.as_mut_ptr(), 2);
                ptr::copy_nonoverlapping(src_data.as_ptr(), src[2..].as_mut_ptr(), 6);
                ptr::copy_nonoverlapping(data[pos..].as_ptr(), dst.as_mut_ptr(), 2);
                ptr::copy_nonoverlapping(dst_data.as_ptr(), dst[2..].as_mut_ptr(), 6);
            }
            Ok((Address(src, 8), Address(dst, 8)))
        } else {
            let mut src = [0; 16];
            let mut dst = [0; 16];
            unsafe {
                ptr::copy_nonoverlapping(src_data.as_ptr(), src.as_mut_ptr(), 6);
                ptr::copy_nonoverlapping(dst_data.as_ptr(), dst.as_mut_ptr(), 6);
            }
            Ok((Address(src, 6), Address(dst, 6)))
        }
    }
}


struct SwitchTableValue {
    address: SocketAddr,
    timeout: SteadyTime
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
        let now = SteadyTime::now();
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
        let value = SwitchTableValue{address: addr, timeout: SteadyTime::now()+self.timeout};
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
    assert_eq!(src, Address([1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0], 6));
    assert_eq!(dst, Address([6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0], 6));
}

#[test]
fn with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address([4,210,1,2,3,4,5,6,0,0,0,0,0,0,0,0], 8));
    assert_eq!(dst, Address([4,210,6,5,4,3,2,1,0,0,0,0,0,0,0,0], 8));
}
