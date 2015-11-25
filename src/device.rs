use std::os::unix::io::{AsRawFd, RawFd};
use std::io::{Result as IoResult, Error as IoError, Read, Write};
use std::fs;

use super::types::{Error, Type};

extern {
    fn setup_tap_device(fd: i32, ifname: *mut u8) -> i32;
    fn setup_tun_device(fd: i32, ifname: *mut u8) -> i32;
}


pub struct Device {
    fd: fs::File,
    ifname: String
}

impl Device {
    pub fn new(ifname: &str, type_: Type) -> IoResult<Self> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        assert!(ifname_string.len() <= 32);
        let mut ifname_c = ifname_string.into_bytes();
        let res = match type_ {
            Type::Tun => unsafe { setup_tun_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) },
            Type::Tap => unsafe { setup_tap_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) }
        };
        match res {
            0 => Ok(Device{fd: fd, ifname: String::from_utf8(ifname_c).unwrap()}),
            _ => Err(IoError::last_os_error())
        }
    }

    #[inline(always)]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    #[inline]
    pub fn read(&mut self, mut buffer: &mut [u8]) -> Result<usize, Error> {
        self.fd.read(&mut buffer).map_err(|_| Error::TunTapDevError("Read error"))
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.fd.write_all(&data) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::TunTapDevError("Write error"))
        }
    }
}

impl AsRawFd for Device {
    #[inline(always)]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
