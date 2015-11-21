use std::fs;
use std::io::{Read, Write, Result as IoResult, Error as IoError};
use std::os::unix::io::{AsRawFd, RawFd};

extern {
    fn setup_tap_device(fd: i32, ifname: *mut u8) -> i32;
    fn setup_tun_device(fd: i32, ifname: *mut u8) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum DeviceType {
    TunDevice, TapDevice
}

pub struct TunTapDevice {
    fd: fs::File,
    ifname: String,
    iftype: DeviceType
}

impl TunTapDevice {
    pub fn new(ifname: &str, iftype: DeviceType) -> IoResult<Self> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        let mut ifname_c = ifname_string.into_bytes();
        let res = match iftype {
            DeviceType::TapDevice => unsafe { setup_tap_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) },
            DeviceType::TunDevice => unsafe { setup_tun_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) }
        };
        match res {
            0 => Ok(TunTapDevice{fd: fd, ifname: String::from_utf8(ifname_c).unwrap(), iftype: iftype}),
            _ => Err(IoError::last_os_error())
        }
    }

    #[inline(always)]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    #[inline(always)]
    pub fn iftype(&self) -> DeviceType {
        self.iftype
    }

    #[inline(always)]
    pub fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        self.fd.read(buffer)
    }

    #[inline(always)]
    pub fn write(&mut self, buffer: &[u8]) -> IoResult<()> {
        self.fd.write_all(buffer)
    }
}

impl AsRawFd for TunTapDevice {
    #[inline(always)]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
