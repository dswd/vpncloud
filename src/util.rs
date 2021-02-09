// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::process::Command;
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::atomic::{AtomicIsize, Ordering},
};

use crate::error::Error;

#[cfg(not(target_os = "linux"))]
use time;

use signal::{trap::Trap, Signal};
use smallvec::SmallVec;
use std::time::Instant;

pub type Duration = u32;
pub type Time = i64;

#[derive(Clone)]
pub struct MsgBuffer {
    space_before: usize,
    buffer: [u8; 65535],
    start: usize,
    end: usize,
}

impl MsgBuffer {
    pub fn new(space_before: usize) -> Self {
        Self { buffer: [0; 65535], space_before, start: space_before, end: space_before }
    }

    pub fn get_start(&self) -> usize {
        self.start
    }

    pub fn set_start(&mut self, start: usize) {
        self.start = start
    }

    pub fn prepend_byte(&mut self, byte: u8) {
        self.start -= 1;
        self.buffer[self.start] = byte
    }

    pub fn take_prefix(&mut self) -> u8 {
        let byte = self.buffer[self.start];
        self.start += 1;
        byte
    }

    pub fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..]
    }

    pub fn message(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    pub fn take(&mut self) -> Option<&[u8]> {
        if self.start != self.end {
            let end = self.end;
            self.end = self.start;
            Some(&self.buffer[self.start..end])
        } else {
            None
        }
    }

    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[self.start..self.end]
    }

    pub fn set_length(&mut self, length: usize) {
        self.end = self.start + length
    }

    pub fn clone_from(&mut self, other: &[u8]) {
        self.set_length(other.len());
        self.message_mut().clone_from_slice(other);
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn clear(&mut self) {
        self.set_start(self.space_before);
        self.set_length(0)
    }
}

const HEX_CHARS: &[u8] = b"0123456789abcdef";

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(HEX_CHARS[(byte >> 4) as usize] as char);
        s.push(HEX_CHARS[(byte & 0xf) as usize] as char);
    }
    s
}

pub fn addr_nice(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6addr) = addr {
        if let Some(ip) = v6addr.ip().to_ipv4() {
            return (ip, addr.port()).into();
        }
    }
    addr
}

pub struct Encoder;

impl Encoder {
    #[inline]
    pub fn read_u16(data: &[u8]) -> u16 {
        (u16::from(data[0]) << 8) | u16::from(data[1])
    }

    #[inline]
    pub fn write_u16(val: u16, data: &mut [u8]) {
        data[0] = ((val >> 8) & 0xff) as u8;
        data[1] = (val & 0xff) as u8;
    }

    #[inline]
    pub fn read_u32(data: &[u8]) -> u32 {
        (u32::from(data[0]) << 24) | (u32::from(data[1]) << 16) | (u32::from(data[2]) << 8) | u32::from(data[3])
    }

    #[inline]
    pub fn write_u32(val: u32, data: &mut [u8]) {
        data[0] = ((val >> 24) & 0xff) as u8;
        data[1] = ((val >> 16) & 0xff) as u8;
        data[2] = ((val >> 8) & 0xff) as u8;
        data[3] = (val & 0xff) as u8;
    }

    #[inline]
    pub fn read_u64(data: &[u8]) -> u64 {
        (u64::from(data[0]) << 56)
            | (u64::from(data[1]) << 48)
            | (u64::from(data[2]) << 40)
            | (u64::from(data[3]) << 32)
            | (u64::from(data[4]) << 24)
            | (u64::from(data[5]) << 16)
            | (u64::from(data[6]) << 8)
            | u64::from(data[7])
    }

    #[inline]
    pub fn write_u64(val: u64, data: &mut [u8]) {
        data[0] = ((val >> 56) & 0xff) as u8;
        data[1] = ((val >> 48) & 0xff) as u8;
        data[2] = ((val >> 40) & 0xff) as u8;
        data[3] = ((val >> 32) & 0xff) as u8;
        data[4] = ((val >> 24) & 0xff) as u8;
        data[5] = ((val >> 16) & 0xff) as u8;
        data[6] = ((val >> 8) & 0xff) as u8;
        data[7] = (val & 0xff) as u8;
    }
}

macro_rules! fail {
    ($format:expr) => ( {
        use std::process;
        error!($format);
        log::logger().flush();
        process::exit(-1);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        use std::process;
        error!($format, $( $arg ),+ );
        log::logger().flush();
        process::exit(-1);
    } );
}

macro_rules! try_fail {
    ($val:expr, $format:expr) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, err)
        }
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, $( $arg ),+, err)
        }
    } );
}

pub fn get_internal_ip() -> Ipv4Addr {
    // Get the internal address (this trick gets the address by opening a UDP connection which
    // does not really open anything but returns the correct address)
    let dummy_sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");
    dummy_sock.connect("8.8.8.8:53").expect("Failed to connect");
    if let SocketAddr::V4(addr) = dummy_sock.local_addr().expect("Failed to get local address") {
        *addr.ip()
    } else {
        unreachable!()
    }
}

#[allow(unknown_lints, clippy::needless_pass_by_value)]
pub fn resolve<Addr: ToSocketAddrs + fmt::Debug>(addr: Addr) -> Result<SmallVec<[SocketAddr; 4]>, Error> {
    let mut addrs =
        addr.to_socket_addrs().map_err(|_| Error::NameUnresolvable(format!("{:?}", addr)))?.collect::<SmallVec<_>>();
    // Try IPv4 first as it usually is faster
    addrs.sort_by_key(|addr| match *addr {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 6,
    });
    // Remove duplicates in addrs (why are there duplicates???)
    addrs.dedup();
    Ok(addrs)
}

#[allow(unused_macros)]
macro_rules! addr {
    ($addr: expr) => {{
        std::net::ToSocketAddrs::to_socket_addrs($addr).unwrap().next().unwrap()
    }};
}

pub struct Bytes(pub u64);

impl fmt::Display for Bytes {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut size = self.0 as f32;
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.0} B", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} KiB", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} MiB", size);
        }
        if size >= 512.0 {
            size /= 1024.0;
        } else {
            return write!(formatter, "{:.1} GiB", size);
        }
        write!(formatter, "{:.1} TiB", size)
    }
}

pub struct CtrlC {
    dummy_time: Instant,
    trap: Trap,
}

impl CtrlC {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn was_pressed(&self) -> bool {
        self.trap.wait(self.dummy_time).is_some()
    }
}

impl Default for CtrlC {
    fn default() -> Self {
        let dummy_time = Instant::now();
        let trap = Trap::trap(&[Signal::SIGINT, Signal::SIGTERM, Signal::SIGQUIT]);
        Self { dummy_time, trap }
    }
}

pub trait TimeSource: Sync + Copy + Send + 'static {
    fn now() -> Time;
}

#[derive(Clone, Copy)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    #[cfg(target_os = "linux")]
    fn now() -> Time {
        let mut tv = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            libc::clock_gettime(6, &mut tv);
        }
        tv.tv_sec as Time
    }

    #[cfg(not(target_os = "linux"))]
    fn now() -> Time {
        time::get_time().sec
    }
}

thread_local! {
    static MOCK_TIME: AtomicIsize = AtomicIsize::new(0);
}

#[derive(Clone, Copy)]
pub struct MockTimeSource;

impl MockTimeSource {
    pub fn set_time(time: Time) {
        MOCK_TIME.with(|t| t.store(time as isize, Ordering::SeqCst))
    }
}

impl TimeSource for MockTimeSource {
    fn now() -> Time {
        MOCK_TIME.with(|t| t.load(Ordering::SeqCst) as Time)
    }
}

/// Helper function that multiplies the base62 data in buf[0..buflen] by 16 and adds m to it
fn base62_add_mult_16(buf: &mut [u8], mut buflen: usize, m: u8) -> usize {
    let mut d: usize = m as usize;
    for item in buf.iter_mut().take(buflen) {
        d += *item as usize * 16;
        *item = (d % 62) as u8;
        d /= 62;
    }
    assert!(d < 62);
    if d > 0 {
        buf[buflen] = d as u8;
        buflen += 1;
    }
    buflen
}

const BASE62: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub fn to_base62(data: &[u8]) -> String {
    let l = data.len();
    let mut buf = vec![0; l * 2];
    let mut buflen = 0;
    for b in data {
        buflen = base62_add_mult_16(&mut buf, buflen, b / 16);
        buflen = base62_add_mult_16(&mut buf, buflen, b % 16);
    }
    buf[0..buflen].reverse();
    let mut result = String::with_capacity(buflen);
    for b in &buf[0..buflen] {
        result.push(BASE62[*b as usize]);
    }
    result
}

pub fn from_base62(data: &str) -> Result<Vec<u8>, char> {
    let mut buf = Vec::with_capacity(data.len() / 2 + data.len() / 4);
    for c in data.chars() {
        let mut val = match c {
            '0'..='9' => ((c as usize) % ('0' as usize)),
            'A'..='Z' => ((c as usize) % ('A' as usize)) + 10,
            'a'..='z' => ((c as usize) % ('a' as usize)) + 36,
            _ => return Err(c),
        };
        for item in &mut buf {
            val += *item as usize * 62;
            *item = (val % 256) as u8;
            val /= 256;
        }
        if val > 0 {
            buf.push(val as u8);
        }
    }
    buf.reverse();
    Ok(buf)
}

#[derive(Default)]
pub struct StatsdMsg {
    entries: Vec<String>,
    key: Vec<String>,
}

impl StatsdMsg {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add<T: fmt::Display>(&mut self, key: &str, val: T, type_: &str) -> &mut Self {
        self.entries.push(format!("{}.{}:{}|{}", self.key.join("."), key, val, type_));
        self
    }

    pub fn with_ns<F: FnOnce(&mut Self)>(&mut self, ns: &str, f: F) -> &mut Self {
        self.key.push(ns.to_string());
        f(self);
        self.key.pop();
        self
    }

    pub fn build(&self) -> String {
        self.entries.join("\n")
    }
}

pub fn run_cmd(mut cmd: Command) {
    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                error!("Command returned error: {:?}", status.code())
            }
        }
        Err(e) => error!("Failed to execute command {:?}: {}", cmd, e),
    }
}

#[test]
fn base62() {
    assert_eq!("", to_base62(&[0]));
    assert_eq!("z", to_base62(&[61]));
    assert_eq!("10", to_base62(&[62]));
    assert_eq!("48", to_base62(&[1, 0]));
    assert_eq!("1Xp7Ke", to_base62(b"Test"));
    assert!(from_base62("").unwrap().is_empty());
    assert_eq!(vec![61], from_base62("z").unwrap());
    assert_eq!(vec![62], from_base62("10").unwrap());
    assert_eq!(vec![1, 0], from_base62("48").unwrap());
    assert_eq!(b"Test".to_vec(), from_base62("1Xp7Ke").unwrap());
}
