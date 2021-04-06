// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    cmp,
    collections::VecDeque,
    convert::TryInto,
    fmt,
    fs::{self, File},
    io::{self, BufRead, BufReader, Cursor, Error as IoError, Read, Write},
    net::{Ipv4Addr, UdpSocket},
    os::unix::io::{AsRawFd, RawFd},
    str,
    str::FromStr,
};

use crate::{crypto, error::Error, util::MsgBuffer};

static TUNSETIFF: libc::c_ulong = 1074025674;

#[repr(C)]
union IfReqData {
    flags: libc::c_short,
    value: libc::c_int,
    addr: (libc::c_short, Ipv4Addr),
    _dummy: [u8; 24],
}

#[repr(C)]
struct IfReq {
    ifr_name: [u8; libc::IF_NAMESIZE],
    data: IfReqData,
}

impl IfReq {
    fn new(name: &str) -> Self {
        assert!(name.len() < libc::IF_NAMESIZE);
        let mut ifr_name = [0; libc::IF_NAMESIZE];
        ifr_name[..name.len()].clone_from_slice(name.as_bytes());
        Self { ifr_name, data: IfReqData { _dummy: [0; 24] } }
    }
}

/// The type of a tun/tap device
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Type {
    /// Tun interface: This interface transports IP packets.
    #[serde(rename = "tun")]
    Tun,
    /// Tap interface: This interface transports Ethernet frames.
    #[serde(rename = "tap")]
    Tap,
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Type::Tun => write!(formatter, "tun"),
            Type::Tap => write!(formatter, "tap"),
        }
    }
}

impl FromStr for Type {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match &text.to_lowercase() as &str {
            "tun" => Self::Tun,
            "tap" => Self::Tap,
            _ => return Err("Unknown device type"),
        })
    }
}

pub trait Device: AsRawFd {
    /// Returns the type of this device
    fn get_type(&self) -> Type;

    /// Returns the interface name of this device.
    fn ifname(&self) -> &str;

    /// Reads a packet/frame from the device
    ///
    /// This method reads one packet or frame (depending on the device type) into the `buffer`.
    /// The `buffer` must be large enough to hold a packet/frame of maximum size, otherwise the
    /// packet/frame will be split.
    /// The method will block until a packet/frame is ready to be read.
    /// On success, the method will return the starting position and the amount of bytes read into
    /// the buffer.
    ///
    /// # Errors
    /// This method will return an error if the underlying read call fails.
    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    /// Writes a packet/frame to the device
    ///
    /// This method writes one packet or frame (depending on the device type) from `data` to the
    /// device. The data starts at the position `start` in the buffer. The buffer should have at
    /// least 4 bytes of space before the start of the packet.
    /// The method will block until the packet/frame has been written.
    ///
    /// # Errors
    /// This method will return an error if the underlying read call fails.
    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error>;

    fn get_ip(&self) -> Result<Ipv4Addr, Error>;
}

/// Represents a tun/tap device
pub struct TunTapDevice {
    fd: File,
    ifname: String,
    type_: Type,
}

impl TunTapDevice {
    /// Creates a new tun/tap device
    ///
    /// This method creates a new device of the `type_` kind with the name `ifname`.
    ///
    /// The `ifname` must be an interface name not longer than 31 bytes. It can contain the string
    /// `%d` which will be replaced with the next free index number that guarantees that the
    /// interface name will be free. In this case, the `ifname()` method can be used to obtain the
    /// final interface name.
    ///
    /// # Errors
    /// This method will return an error when the underlying system call fails. Common cases are:
    /// - The special device file `/dev/net/tun` does not exist or is not accessible by the current user.
    /// - The interface name is invalid or already in use.
    /// - The current user does not have enough permissions to create tun/tap devices (this requires root permissions).
    ///
    /// # Panics
    /// This method panics if the interface name is longer than 31 bytes.
    #[allow(clippy::useless_conversion)]
    pub fn new(ifname: &str, type_: Type, path: Option<&str>) -> io::Result<Self> {
        let path = path.unwrap_or_else(|| Self::default_path(type_));
        let fd = fs::OpenOptions::new().read(true).write(true).open(path)?;
        let flags = match type_ {
            Type::Tun => libc::IFF_TUN | libc::IFF_NO_PI,
            Type::Tap => libc::IFF_TAP | libc::IFF_NO_PI,
        };
        let mut ifreq = IfReq::new(ifname);
        ifreq.data.flags = flags as libc::c_short;
        let res = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF.try_into().unwrap(), &mut ifreq) };
        match res {
            0 => {
                let mut ifname = String::with_capacity(32);
                let mut cursor = Cursor::new(ifreq.ifr_name);
                cursor.read_to_string(&mut ifname)?;
                ifname = ifname.trim_end_matches('\0').to_owned();
                Ok(Self { fd, ifname, type_ })
            }
            _ => Err(IoError::last_os_error()),
        }
    }

    /// Returns the default device path for a given type
    #[inline]
    pub fn default_path(type_: Type) -> &'static str {
        match type_ {
            Type::Tun | Type::Tap => "/dev/net/tun",
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_after_read(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
        target_os = "bitrig",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_after_read(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() + 4);
        } else {
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    fn correct_data_before_write(&mut self, _buffer: &mut MsgBuffer) {}

    #[cfg(any(
        target_os = "bitrig",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[inline]
    fn correct_data_before_write(&mut self, buffer: &mut MsgBuffer) {
        if self.type_ == Type::Tun {
            // BSD-based systems add a 4-byte header containing the Ethertype for TUN
            buffer.set_start(buffer.get_start() - 4);
            match buffer.message()[4] >> 4 {
                // IP version
                4 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x08, 0x00]),
                6 => buffer.message_mut()[0..4].copy_from_slice(&[0x00, 0x00, 0x86, 0xdd]),
                _ => unreachable!(),
            }
        }
    }

    pub fn get_overhead(&self) -> usize {
        40 /* for outer IPv6 header, can't be sure to only have IPv4 peers */
        + 8 /* for outer UDP header */
        + crypto::EXTRA_LEN + crypto::TAG_LEN /* crypto overhead */
        + 1 /* message type header */
        + match self.type_ {
            Type::Tap => 14, /* inner ethernet header */
            Type::Tun => 0
        }
    }

    pub fn set_mtu(&self, value: Option<usize>) -> io::Result<()> {
        let value = match value {
            Some(value) => value,
            None => {
                let default_device = get_default_device()?;
                get_device_mtu(&default_device)? - self.get_overhead()
            }
        };
        info!("Setting MTU {} on device {}", value, self.ifname);
        set_device_mtu(&self.ifname, value)
    }

    pub fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        set_device_addr(&self.ifname, addr)?;
        set_device_netmask(&self.ifname, netmask)?;
        set_device_enabled(&self.ifname, true)
    }

    pub fn get_rp_filter(&self) -> io::Result<u8> {
        Ok(cmp::max(get_rp_filter("all")?, get_rp_filter(&self.ifname)?))
    }

    pub fn fix_rp_filter(&self) -> io::Result<()> {
        if get_rp_filter("all")? > 1 {
            info!("Setting net.ipv4.conf.all.rp_filter=1");
            set_rp_filter("all", 1)?
        }
        if get_rp_filter(&self.ifname)? != 1 {
            info!("Setting net.ipv4.conf.{}.rp_filter=1", self.ifname);
            set_rp_filter(&self.ifname, 1)?
        }
        Ok(())
    }
}

impl Device for TunTapDevice {
    fn get_type(&self) -> Type {
        self.type_
    }

    fn ifname(&self) -> &str {
        &self.ifname
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        buffer.clear();
        let read = self.fd.read(buffer.buffer()).map_err(|e| Error::DeviceIo("Read error", e))?;
        buffer.set_length(read);
        self.correct_data_after_read(buffer);
        Ok(())
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.correct_data_before_write(buffer);
        match self.fd.write_all(buffer.message()) {
            Ok(_) => self.fd.flush().map_err(|e| Error::DeviceIo("Flush error", e)),
            Err(e) => Err(Error::DeviceIo("Write error", e)),
        }
    }

    fn get_ip(&self) -> Result<Ipv4Addr, Error> {
        get_device_addr(&self.ifname).map_err(|e| Error::DeviceIo("Error getting IP address", e))
    }
}

impl AsRawFd for TunTapDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
}

impl MockDevice {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn put_inbound(&mut self, data: Vec<u8>) {
        self.inbound.push_back(data)
    }

    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

impl Device for MockDevice {
    fn get_type(&self) -> Type {
        Type::Tun
    }

    fn ifname(&self) -> &str {
        "mock0"
    }

    fn read(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        if let Some(data) = self.inbound.pop_front() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(())
        } else {
            Err(Error::Device("empty"))
        }
    }

    fn write(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        self.outbound.push_back(buffer.message().into());
        Ok(())
    }

    fn get_ip(&self) -> Result<Ipv4Addr, Error> {
        Err(Error::Device("Dummy devices have no IP address"))
    }
}

impl Default for MockDevice {
    fn default() -> Self {
        Self { outbound: VecDeque::with_capacity(10), inbound: VecDeque::with_capacity(10) }
    }
}

impl AsRawFd for MockDevice {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_mtu(ifname: &str, mtu: usize) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.value = mtu as libc::c_int;
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_mtu(ifname: &str) -> io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(unsafe { ifreq.data.value as usize }),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn get_device_addr(ifname: &str) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFADDR.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => {
            let af = unsafe { ifreq.data.addr.0 };
            if af as libc::c_int != libc::AF_INET {
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Invalid address family".to_owned()));
            }
            let ip = unsafe { ifreq.data.addr.1 };
            Ok(ip)
        }
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_addr(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr = (libc::AF_INET as libc::c_short, addr);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(dead_code)]
#[allow(clippy::useless_conversion)]
fn get_device_netmask(ifname: &str) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => {
            let af = unsafe { ifreq.data.addr.0 };
            if af as libc::c_int != libc::AF_INET {
                return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Invalid address family".to_owned()));
            }
            let ip = unsafe { ifreq.data.addr.1 };
            Ok(ip)
        }
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_netmask(ifname: &str, addr: Ipv4Addr) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    ifreq.data.addr = (libc::AF_INET as libc::c_short, addr);
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

#[allow(clippy::useless_conversion)]
fn set_device_enabled(ifname: &str, up: bool) -> io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = IfReq::new(ifname);
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS.try_into().unwrap(), &mut ifreq) } != 0 {
        return Err(IoError::last_os_error());
    }
    if up {
        unsafe { ifreq.data.value |= libc::IFF_UP | libc::IFF_RUNNING }
    } else {
        unsafe { ifreq.data.value &= !libc::IFF_UP }
    }
    let res = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS.try_into().unwrap(), &mut ifreq) };
    match res {
        0 => Ok(()),
        _ => Err(IoError::last_os_error()),
    }
}

fn get_default_device() -> io::Result<String> {
    let fd = BufReader::new(File::open("/proc/net/route")?);
    let mut best = None;
    for line in fd.lines() {
        let line = line?;
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts[1] == "00000000" {
            best = Some(parts[0].to_string());
            break;
        }
        if parts[2] != "00000000" {
            best = Some(parts[0].to_string())
        }
    }
    if let Some(ifname) = best {
        Ok(ifname)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, "No default interface found".to_string()))
    }
}

fn get_rp_filter(device: &str) -> io::Result<u8> {
    let mut fd = File::open(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    let mut contents = String::with_capacity(10);
    fd.read_to_string(&mut contents)?;
    u8::from_str(contents.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid rp_filter value"))
}

fn set_rp_filter(device: &str, val: u8) -> io::Result<()> {
    let mut fd = File::create(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", device))?;
    writeln!(fd, "{}", val)
}
