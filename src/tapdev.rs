use std::fs;
use std::io::{Read, Write, Result as IoResult, Error as IoError};
use std::os::unix::io::{AsRawFd, FromRawFd};

extern {
    fn setup_tap_device(fd: i32, ifname: *mut u8) -> i32;
}

pub struct TapDevice {
    fd: fs::File,
    ifname: String
}

impl TapDevice {
    pub fn new(ifname: &str) -> IoResult<TapDevice> {
        let fd = try!(fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun"));
        let mut ifname_string = String::with_capacity(32);
        ifname_string.push_str(ifname);
        ifname_string.push('\0');
        let mut ifname_c = ifname_string.into_bytes();
        match unsafe { setup_tap_device(fd.as_raw_fd(), ifname_c.as_mut_ptr()) } {
            0 => Ok(TapDevice{fd: fd, ifname: String::from_utf8(ifname_c).unwrap()}),
            _ => Err(IoError::last_os_error())
        }
    }

    pub fn clone(&self) -> TapDevice {
        let fd = unsafe { fs::File::from_raw_fd(self.fd.as_raw_fd()) };
        TapDevice{fd: fd, ifname: self.ifname.clone()}
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
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
