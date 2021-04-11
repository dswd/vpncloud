// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use crate::{
    crypto::Payload,
    error::Error,
    types::{NodeId, Range, RangeList, NODE_ID_BYTES},
    util::MsgBuffer,
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use smallvec::{smallvec, SmallVec};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Take, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

pub const MESSAGE_TYPE_DATA: u8 = 0;
pub const MESSAGE_TYPE_NODE_INFO: u8 = 1;
pub const MESSAGE_TYPE_KEEPALIVE: u8 = 2;
pub const MESSAGE_TYPE_CLOSE: u8 = 0xff;

pub type AddrList = SmallVec<[SocketAddr; 4]>;
pub type PeerList = SmallVec<[PeerInfo; 16]>;

#[derive(Debug, PartialEq)]
pub struct PeerInfo {
    pub node_id: Option<NodeId>,
    pub addrs: AddrList,
}

#[derive(Debug, PartialEq)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub peers: PeerList,
    pub claims: RangeList,
    pub peer_timeout: Option<u16>,
    pub addrs: AddrList,
}

impl NodeInfo {
    const PART_CLAIMS: u8 = 2;
    const PART_END: u8 = 0;
    const PART_NODEID: u8 = 4;
    const PART_PEERS: u8 = 1;
    const PART_PEER_TIMEOUT: u8 = 3;
    const PART_ADDRS: u8 = 5;

    fn read_addr_list<R: Read>(r: &mut Take<R>) -> Result<AddrList, io::Error> {
        let flags = r.read_u8()?;
        Self::read_addr_list_inner(r, flags)
    }

    fn read_addr_list_inner<R: Read>(r: &mut Take<R>, flags: u8) -> Result<AddrList, io::Error> {
        let num_ipv4_addrs = (flags & 0x07) as usize;
        let num_ipv6_addrs = (flags & 0x38) as usize / 8;
        let mut addrs = SmallVec::with_capacity(num_ipv4_addrs + num_ipv6_addrs);
        for _ in 0..num_ipv6_addrs {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip)?;
            let port = r.read_u16::<NetworkEndian>()?;
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
            addrs.push(addr);
        }
        for _ in 0..num_ipv4_addrs {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip)?;
            let port = r.read_u16::<NetworkEndian>()?;
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            addrs.push(addr);
        }
        Ok(addrs)
    }

    fn decode_peer_list_part<R: Read>(r: &mut Take<R>) -> Result<PeerList, io::Error> {
        let mut peers = smallvec![];
        while r.limit() > 0 {
            let flags = r.read_u8()?;
            let has_node_id = (flags & 0x80) != 0;
            let mut node_id = None;
            if has_node_id {
                let mut id = [0; NODE_ID_BYTES];
                r.read_exact(&mut id)?;
                node_id = Some(id)
            }
            let addrs = Self::read_addr_list_inner(r, flags)?;
            peers.push(PeerInfo { addrs, node_id })
        }
        Ok(peers)
    }

    fn decode_claims_part<R: Read>(mut r: &mut Take<R>) -> Result<RangeList, Error> {
        let mut claims = smallvec![];
        while r.limit() > 0 {
            claims.push(Range::read_from(&mut r)?);
        }
        Ok(claims)
    }

    fn decode_internal<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut peers = smallvec![];
        let mut claims = smallvec![];
        let mut peer_timeout = None;
        let mut node_id = None;
        let mut addrs = smallvec![];
        loop {
            let part = r.read_u8().map_err(|_| Error::Message("Truncated message"))?;
            if part == Self::PART_END {
                break;
            }
            let part_len = r.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))? as usize;
            let mut rp = r.take(part_len as u64);
            match part {
                Self::PART_PEERS => {
                    peers = Self::decode_peer_list_part(&mut rp).map_err(|_| Error::Message("Truncated message"))?
                }
                Self::PART_CLAIMS => claims = Self::decode_claims_part(&mut rp)?,
                Self::PART_PEER_TIMEOUT => {
                    peer_timeout =
                        Some(rp.read_u16::<NetworkEndian>().map_err(|_| Error::Message("Truncated message"))?)
                }
                Self::PART_NODEID => {
                    let mut data = [0; NODE_ID_BYTES];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                    node_id = Some(data);
                }
                Self::PART_ADDRS => {
                    addrs = Self::read_addr_list(&mut rp).map_err(|_| Error::Message("Truncated message"))?;
                }
                _ => {
                    let mut data = vec![0; part_len];
                    rp.read_exact(&mut data).map_err(|_| Error::Message("Truncated message"))?;
                }
            }
            r = rp.into_inner();
        }
        let node_id = match node_id {
            Some(node_id) => node_id,
            None => return Err(Error::Message("Payload without node_id")),
        };
        Ok(Self { node_id, peers, claims, peer_timeout, addrs })
    }

    pub fn decode<R: Read>(r: R) -> Result<Self, Error> {
        Self::decode_internal(r).map_err(|_| Error::Message("Input data too short"))
    }

    fn encode_peer_list_part<W: Write>(&self, mut out: W) -> Result<(), io::Error> {
        for p in &self.peers {
            let mut addr_ipv4: SmallVec<[SocketAddrV4; 16]> = smallvec![];
            let mut addr_ipv6: SmallVec<[SocketAddrV6; 16]> = smallvec![];
            for a in &p.addrs {
                match a {
                    SocketAddr::V4(addr) => addr_ipv4.push(*addr),
                    SocketAddr::V6(addr) => addr_ipv6.push(*addr),
                }
            }
            while addr_ipv4.len() >= 8 {
                addr_ipv4.pop();
            }
            while addr_ipv6.len() >= 8 {
                addr_ipv6.pop();
            }
            let mut flags = addr_ipv6.len() as u8 * 8 + addr_ipv4.len() as u8;
            if p.node_id.is_some() {
                flags += 0x80;
            }
            out.write_u8(flags)?;
            if let Some(node_id) = &p.node_id {
                out.write_all(node_id)?;
            }
            for a in addr_ipv6 {
                out.write_all(&a.ip().octets())?;
                out.write_u16::<NetworkEndian>(a.port())?;
            }
            for a in addr_ipv4 {
                out.write_all(&a.ip().octets())?;
                out.write_u16::<NetworkEndian>(a.port())?;
            }
        }
        Ok(())
    }

    fn encode_addrs_part<W: Write>(&self, mut out: W) -> Result<(), io::Error> {
        let mut addr_ipv4: SmallVec<[SocketAddrV4; 16]> = smallvec![];
        let mut addr_ipv6: SmallVec<[SocketAddrV6; 16]> = smallvec![];
        for a in &self.addrs {
            match a {
                SocketAddr::V4(addr) => addr_ipv4.push(*addr),
                SocketAddr::V6(addr) => addr_ipv6.push(*addr),
            }
        }
        while addr_ipv4.len() >= 8 {
            addr_ipv4.pop();
        }
        while addr_ipv6.len() >= 8 {
            addr_ipv6.pop();
        }
        let flags = addr_ipv6.len() as u8 * 8 + addr_ipv4.len() as u8;
        out.write_u8(flags)?;
        for a in addr_ipv6 {
            out.write_all(&a.ip().octets())?;
            out.write_u16::<NetworkEndian>(a.port())?;
        }
        for a in addr_ipv4 {
            out.write_all(&a.ip().octets())?;
            out.write_u16::<NetworkEndian>(a.port())?;
        }
        Ok(())
    }

    fn encode_part<F: FnOnce(&mut Cursor<&mut [u8]>) -> Result<(), io::Error>>(
        cursor: &mut Cursor<&mut [u8]>, part: u8, f: F,
    ) -> Result<(), io::Error> {
        cursor.write_u8(part)?;
        cursor.write_u16::<NetworkEndian>(0)?;
        let part_start = cursor.position();
        f(cursor)?;
        let part_end = cursor.position();
        let len = part_end - part_start;
        cursor.seek(SeekFrom::Start(part_start - 2))?;
        cursor.write_u16::<NetworkEndian>(len as u16)?;
        cursor.seek(SeekFrom::Start(part_end))?;
        Ok(())
    }

    fn encode_internal(&self, buffer: &mut MsgBuffer) -> Result<(), io::Error> {
        let len;
        {
            let mut cursor = Cursor::new(buffer.buffer());
            Self::encode_part(&mut cursor, Self::PART_NODEID, |cursor| cursor.write_all(&self.node_id))?;
            Self::encode_part(&mut cursor, Self::PART_PEERS, |cursor| self.encode_peer_list_part(cursor))?;
            Self::encode_part(&mut cursor, Self::PART_CLAIMS, |mut cursor| {
                for c in &self.claims {
                    c.write_to(&mut cursor);
                }
                Ok(())
            })?;
            if let Some(timeout) = self.peer_timeout {
                Self::encode_part(&mut cursor, Self::PART_PEER_TIMEOUT, |cursor| {
                    cursor.write_u16::<NetworkEndian>(timeout)
                })?
            }
            Self::encode_part(&mut cursor, Self::PART_ADDRS, |cursor| self.encode_addrs_part(cursor))?;
            cursor.write_u8(Self::PART_END)?;
            len = cursor.position() as usize;
        }
        buffer.set_length(len);
        Ok(())
    }

    pub fn encode(&self, buffer: &mut MsgBuffer) {
        self.encode_internal(buffer).expect("Buffer too small")
    }
}

impl Payload for NodeInfo {
    fn write_to(&self, buffer: &mut MsgBuffer) {
        self.encode(buffer)
    }

    fn read_from<R: Read>(r: R) -> Result<Self, Error> {
        Self::decode(r)
    }
}
