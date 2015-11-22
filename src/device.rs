use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Result as IoResult, Error as IoError, Read, Write};
use std::marker::PhantomData;
use std::fs;

use super::cloud::{Error, VirtualInterface};

extern {
    fn setup_tap_device(fd: i32, ifname: *mut u8) -> i32;
    fn setup_tun_device(fd: i32, ifname: *mut u8) -> i32;
}


trait DeviceSetup {
    fn setup_device(RawFd, &str) -> IoResult<String>;
}

#[allow(dead_code)]
struct TapSetup;

impl DeviceSetup for TapSetup {
    fn setup_device(fd: RawFd, ifname: &str) -> IoResult<String> {
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        let mut ifname_c = ifname_string.into_bytes();
        let res = unsafe { setup_tap_device(fd, ifname_c.as_mut_ptr()) };
        match res {
            0 => Ok(String::from_utf8(ifname_c).unwrap()),
            _ => Err(IoError::last_os_error())
        }
    }
}

#[allow(dead_code)]
struct TunSetup;

impl DeviceSetup for TunSetup {
    fn setup_device(fd: RawFd, ifname: &str) -> IoResult<String> {
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        let mut ifname_c = ifname_string.into_bytes();
        let res = unsafe { setup_tun_device(fd, ifname_c.as_mut_ptr()) };
        match res {
            0 => Ok(String::from_utf8(ifname_c).unwrap()),
            _ => Err(IoError::last_os_error())
        }
    }
}


pub struct Device<T> {
    fd: fs::File,
    ifname: String,
    _dummy_t: PhantomData<T>
}

impl<T: DeviceSetup> Device<T> {
    pub fn new(ifname: &str) -> IoResult<Self> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));
        let ifname = try!(T::setup_device(fd.as_raw_fd(), ifname));
        Ok(Device{fd: fd, ifname: ifname, _dummy_t: PhantomData})
    }

    #[inline(always)]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }
}

impl<T> AsRawFd for Device<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl<T> VirtualInterface for Device<T> {
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

pub type TapDevice = Device<TapSetup>;
pub type TunDevice = Device<TunSetup>;
