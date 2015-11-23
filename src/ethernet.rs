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
            let mut src = Vec::with_capacity(8);
            let mut dst = Vec::with_capacity(8);
            unsafe {
                src.set_len(8);
                ptr::copy_nonoverlapping(data[pos..].as_ptr(), src.as_mut_ptr(), 2);
                ptr::copy_nonoverlapping(src_data.as_ptr(), src[2..].as_mut_ptr(), 6);
                dst.set_len(8);
                ptr::copy_nonoverlapping(data[pos..].as_ptr(), dst.as_mut_ptr(), 2);
                ptr::copy_nonoverlapping(dst_data.as_ptr(), dst[2..].as_mut_ptr(), 6);
            }
            Ok((Address(src), Address(dst)))
        } else {
            let mut src = Vec::with_capacity(6);
            let mut dst = Vec::with_capacity(6);
            unsafe {
                ptr::copy_nonoverlapping(src_data.as_ptr(), src.as_mut_ptr(), 6);
                src.set_len(6);
                ptr::copy_nonoverlapping(dst_data.as_ptr(), dst.as_mut_ptr(), 6);
                dst.set_len(6);
            }
            Ok((Address(src), Address(dst)))
        }
    }
}


struct MacTableValue {
    address: SocketAddr,
    timeout: SteadyTime
}


pub struct MacTable {
    table: HashMap<Address, MacTableValue>,
    timeout: Duration
}

impl MacTable {
    pub fn new(timeout: Duration) -> MacTable {
        MacTable{table: HashMap::new(), timeout: timeout}
    }
}

impl Table for MacTable {
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
    }

    fn learn(&mut self, key: Address, _prefix_len: Option<u8>, addr: SocketAddr) {
       let value = MacTableValue{address: addr, timeout: SteadyTime::now()+self.timeout};
       if self.table.insert(key.clone(), value).is_none() {
           info!("Learned address {:?} => {}", key, addr);
       }
    }

    fn lookup(&self, key: &Address) -> Option<SocketAddr> {
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
    assert_eq!(src, Address(vec![1,2,3,4,5,6]));
    assert_eq!(dst, Address(vec![6,5,4,3,2,1]));
}

#[test]
fn with_vlan() {
    let data = [6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address(vec![4,210,1,2,3,4,5,6]));
    assert_eq!(dst, Address(vec![4,210,6,5,4,3,2,1]));
}
