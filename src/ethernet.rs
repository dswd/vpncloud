use std::{mem, ptr, fmt};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::marker::PhantomData;

use super::ethcloud::{Error, Table, InterfaceMessage, VirtualInterface};
use super::util::{as_bytes, as_obj};

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
    pub vlan: VlanId
}

#[derive(PartialEq)]
pub struct Frame<'a> {
    pub src: EthAddr,
    pub dst: EthAddr,
    pub payload: &'a [u8]
}

impl<'a> fmt::Debug for Frame<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(formatter, "src: {:?}, dst: {:?}, vlan: {}, payload: {} bytes",
            self.src.mac, self.dst.mac, self.src.vlan, self.payload.len())
    }
}

impl<'a> InterfaceMessage for Frame<'a> {
    type Address = EthAddr;

    fn src(&self) -> Self::Address {
        self.src
    }

    fn dst(&self) -> Self::Address {
        self.dst
    }
}

pub struct TapDevice<'a>(PhantomData<&'a ()>);

impl<'a> VirtualInterface for TapDevice<'a> {
    type Message = Frame<'a>;

    fn read(&mut self) -> Result<Self::Message, Error> {
        unimplemented!();
    }

    fn write(&mut self, msg: Self::Message) -> Result<(), Error> {
        unimplemented!();
    }
}

pub fn decode(data: &[u8]) -> Result<Frame, Error> {
    if data.len() < 14 {
        return Err(Error::ParseError("Frame is too short"));
    }
    let mut pos = 0;
    let dst = *unsafe { as_obj::<Mac>(&data[pos..]) };
    pos += mem::size_of::<Mac>();
    let src = *unsafe { as_obj::<Mac>(&data[pos..]) };
    pos += mem::size_of::<Mac>();
    let mut vlan = 0;
    let mut payload = &data[pos..];
    if data[pos] == 0x81 && data[pos+1] == 0x00 {
        pos += 2;
        if data.len() < pos + 2 {
            return Err(Error::ParseError("Vlan frame is too short"));
        }
        vlan = u16::from_be(* unsafe { as_obj::<u16>(&data[pos..]) });
        pos += 2;
        payload = &data[pos..];
    }
    Ok(Frame{src: EthAddr{mac: src, vlan: vlan}, dst: EthAddr{mac: dst, vlan: vlan}, payload: payload})
}

pub fn encode(frame: &Frame, buf: &mut [u8]) -> usize {
    assert!(buf.len() >= 16 + frame.payload.len());
    let mut pos = 0;
    unsafe {
        let dst_dat = as_bytes::<Mac>(&frame.dst.mac);
        ptr::copy_nonoverlapping(dst_dat.as_ptr(), buf[pos..].as_mut_ptr(), dst_dat.len());
        pos += dst_dat.len();
        let src_dat = as_bytes::<Mac>(&frame.src.mac);
        ptr::copy_nonoverlapping(src_dat.as_ptr(), buf[pos..].as_mut_ptr(), src_dat.len());
        pos += src_dat.len();
        if frame.src.vlan != 0 {
            buf[pos] = 0x81; buf[pos+1] = 0x00;
            pos += 2;
            let vlan_dat = mem::transmute::<u16, [u8; 2]>(frame.src.vlan.to_be());
            ptr::copy_nonoverlapping(vlan_dat.as_ptr(), buf[pos..].as_mut_ptr(), vlan_dat.len());
            pos += vlan_dat.len();
        }
        ptr::copy_nonoverlapping(frame.payload.as_ptr(), buf[pos..].as_mut_ptr(), frame.payload.len());
    }
    pos += frame.payload.len();
    pos
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
            info!("Forgot mac: {:?} (vlan {})", key.mac, key.vlan);
            self.table.remove(&key);
        }
    }

    fn learn(&mut self, key: Self::Address, addr: SocketAddr) {
       let value = MacTableValue{address: addr, timeout: SteadyTime::now()+self.timeout};
       if self.table.insert(key, value).is_none() {
           info!("Learned mac: {:?} (vlan {}) => {}", key.mac, key.vlan, addr);
       }
    }

    fn lookup(&self, key: Self::Address) -> Option<SocketAddr> {
       match self.table.get(&key) {
           Some(value) => Some(value.address),
           None => None
       }
    }
}


#[test]
fn without_vlan() {
    let src = Mac([1,2,3,4,5,6]);
    let dst = Mac([6,5,4,3,2,1]);
    let payload = [1,2,3,4,5,6,7,8];
    let mut buf = [0u8; 1024];
    let frame = Frame{src: EthAddr{mac: src, vlan: 0}, dst: EthAddr{mac: dst, vlan: 0}, payload: &payload};
    let size = encode(&frame, &mut buf);
    assert_eq!(size, 20);
    assert_eq!(&buf[..size], &[6,5,4,3,2,1,1,2,3,4,5,6,1,2,3,4,5,6,7,8]);
    let frame2 = decode(&buf[..size]).unwrap();
    assert_eq!(frame, frame2);
}

#[test]
fn with_vlan() {
    let src = Mac([1,2,3,4,5,6]);
    let dst = Mac([6,5,4,3,2,1]);
    let payload = [1,2,3,4,5,6,7,8];
    let mut buf = [0u8; 1024];
    let frame = Frame{src: EthAddr{mac: src, vlan: 0}, dst: EthAddr{mac: dst, vlan: 0}, payload: &payload};
    let size = encode(&frame, &mut buf);
    assert_eq!(size, 24);
    assert_eq!(&buf[..size], &[6,5,4,3,2,1,1,2,3,4,5,6,0x81,0,4,210,1,2,3,4,5,6,7,8]);
    let frame2 = decode(&buf[..size]).unwrap();
    assert_eq!(frame, frame2);
}
