// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddr, ToSocketAddrs};
use std::fmt;

use super::types::Error;

#[cfg(target_os = "linux")]
use libc;

#[cfg(not(target_os = "linux"))]
use time;

pub type Duration = u32;
pub type Time = i64;

#[inline]
#[cfg(target_os = "linux")]
pub fn now() -> Time {
    let mut tv = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(6, &mut tv); }
    tv.tv_sec as Time
}

#[inline]
#[cfg(not(target_os = "linux"))]
pub fn now() -> Time {
    time::get_time().sec
}

const HEX_CHARS: &'static [u8] = b"0123456789abcdef";

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        v.push(HEX_CHARS[(byte >> 4) as usize]);
        v.push(HEX_CHARS[(byte & 0xf) as usize]);
    }
    unsafe {
        String::from_utf8_unchecked(v)
    }
}


pub struct Encoder;

impl Encoder {
    #[inline]
    pub fn read_u16(data: &[u8]) -> u16 {
        ((data[0] as u16) << 8) | data[1] as u16
    }

    #[inline]
    pub fn write_u16(val: u16, data: &mut [u8]) {
        data[0] = ((val >> 8) & 0xff) as u8;
        data[1] = (val & 0xff) as u8;
    }

    #[inline]
    pub fn read_u64(data: &[u8]) -> u64 {
        ((data[0] as u64) << 56) | ((data[1] as u64) << 48) |
        ((data[2] as u64) << 40) | ((data[3] as u64) << 32) |
        ((data[4] as u64) << 24) | ((data[5] as u64) << 16) |
        ((data[6] as u64) << 8) | data[7] as u64
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
        process::exit(-1);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        use std::process;
        error!($format, $( $arg ),+ );
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


pub fn resolve<Addr: ToSocketAddrs+fmt::Display>(addr: Addr) -> Result<Vec<SocketAddr>, Error> {
    let addrs = try!(addr.to_socket_addrs().map_err(|_| Error::Name(format!("{}", addr))));
    // Remove duplicates in addrs (why are there duplicates???)
    let mut addrs = addrs.collect::<Vec<_>>();
    addrs.dedup();
    Ok(addrs)
}
