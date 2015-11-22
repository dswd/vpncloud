use std::{mem, ptr, fmt, fs};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Result as IoResult, Error as IoError, Read, Write};

use super::cloud::{Error, Table, Protocol, VirtualInterface};
use super::util::{as_bytes, as_obj};

use time::{Duration, SteadyTime};

extern {
    fn setup_tap_device(fd: i32, ifname: *mut u8) -> i32;
}


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


pub struct TapDevice {
    fd: fs::File,
    ifname: String
}

impl TapDevice {
    pub fn new(ifname: &str) -> IoResult<Self> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        let mut ifname_c = ifname_string.into_bytes();
        let res = unsafe { setup_tap_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) };
        match res {
            0 => Ok(TapDevice{fd: fd, ifname: String::from_utf8(ifname_c).unwrap()}),
            _ => Err(IoError::last_os_error())
        }
    }

    #[inline(always)]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }
}

impl AsRawFd for TapDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl VirtualInterface for TapDevice {
    fn read(&mut self, mut buffer: &mut [u8]) -> Result<usize, Error> {
        self.fd.read(&mut buffer).map_err(|_| Error::TunTapDevError("Read error"))
    }

    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.fd.write_all(&data) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::TunTapDevError("Write error"))
        }
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
