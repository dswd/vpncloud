// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{error::Error, types::Address};
use std::io::{Cursor, Read};

pub trait Protocol: Sized {
    fn parse(_: &[u8]) -> Result<(Address, Address), Error>;
}

/// An ethernet frame dissector
///
/// This dissector is able to extract the source and destination addresses of ethernet frames.
///
/// If the ethernet frame contains a VLAN tag, both addresses will be prefixed with that tag,
/// resulting in 8-byte addresses. Additional nested tags will be ignored.
pub struct Frame;

impl Protocol for Frame {
    /// Parses an ethernet frame and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ethernet frame.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        let mut cursor = Cursor::new(data);
        let mut src = [0; 16];
        let mut dst = [0; 16];
        let mut proto = [0; 2];
        cursor
            .read_exact(&mut dst[..6])
            .and_then(|_| cursor.read_exact(&mut src[..6]))
            .and_then(|_| cursor.read_exact(&mut proto))
            .map_err(|_| Error::Parse("Frame is too short"))?;
        if proto == [0x81, 0x00] {
            src.copy_within(..6, 2);
            dst.copy_within(..6, 2);
            cursor.read_exact(&mut src[..2]).map_err(|_| Error::Parse("Vlan frame is too short"))?;
            src[0] &= 0x0f; // restrict vlan id to 12 bits
            dst[..2].copy_from_slice(&src[..2]);
            if src[0..1] == [0, 0] {
                // treat vlan id 0x000 as untagged
                src.copy_within(2..8, 0);
                dst.copy_within(2..8, 0);
                return Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }));
            }
            Ok((Address { data: src, len: 8 }, Address { data: dst, len: 8 }))
        } else {
            Ok((Address { data: src, len: 6 }, Address { data: dst, len: 6 }))
        }
    }
}

#[test]
fn decode_frame_without_vlan() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address { data: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 6 });
    assert_eq!(dst, Address { data: [6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 6 });
}

#[test]
fn decode_frame_with_vlan() {
    let data = [6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 0x81, 0, 4, 210, 1, 2, 3, 4, 5, 6, 7, 8];
    let (src, dst) = Frame::parse(&data).unwrap();
    assert_eq!(src, Address { data: [4, 210, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0], len: 8 });
    assert_eq!(dst, Address { data: [4, 210, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0], len: 8 });
}

#[test]
fn decode_invalid_frame() {
    assert!(Frame::parse(&[6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8]).is_ok());
    // truncated frame
    assert!(Frame::parse(&[]).is_err());
    // truncated vlan frame
    assert!(Frame::parse(&[6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 0x81, 0x00]).is_err());
}

/// An IP packet dissector
///
/// This dissector is able to extract the source and destination ip addresses of ipv4 packets and
/// ipv6 packets.
#[allow(dead_code)]
pub struct Packet;

impl Protocol for Packet {
    /// Parses an ip packet and extracts the source and destination addresses
    ///
    /// # Errors
    /// This method will fail when the given data is not a valid ipv4 and ipv6 packet.
    fn parse(data: &[u8]) -> Result<(Address, Address), Error> {
        // HOT PATH
        if data.is_empty() {
            return Err(Error::Parse("Empty header"));
        }
        let version = data[0] >> 4;
        match version {
            4 => {
                if data.len() < 20 {
                    return Err(Error::Parse("Truncated IPv4 header"));
                }
                let src = Address::read_from_fixed(&data[12..], 4)?;
                let dst = Address::read_from_fixed(&data[16..], 4)?;
                Ok((src, dst))
            }
            6 => {
                if data.len() < 40 {
                    return Err(Error::Parse("Truncated IPv6 header"));
                }
                let src = Address::read_from_fixed(&data[8..], 16)?;
                let dst = Address::read_from_fixed(&data[24..], 16)?;
                Ok((src, dst))
            }
            _ => Err(Error::Parse("Invalid IP protocol version")),
        }
    }
}

#[test]
fn decode_ipv4_packet() {
    let data = [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
    assert_eq!(dst, Address { data: [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4 });
}

#[test]
fn decode_ipv6_packet() {
    let data = [
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1,
    ];
    let (src, dst) = Packet::parse(&data).unwrap();
    assert_eq!(src, Address { data: [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6], len: 16 });
    assert_eq!(dst, Address { data: [0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1], len: 16 });
}

#[test]
fn decode_invalid_packet() {
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2]).is_ok());
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2, 1
    ])
    .is_ok());
    // no data
    assert!(Packet::parse(&[]).is_err());
    // wrong version
    assert!(Packet::parse(&[0x20]).is_err());
    // truncated ipv4
    assert!(Packet::parse(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1]).is_err());
    // truncated ipv6
    assert!(Packet::parse(&[
        0x60, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5,
        4, 3, 2
    ])
    .is_err());
}
