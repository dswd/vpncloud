// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2018-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::HashMap,
    io::{self, Write},
    net::SocketAddr
};

use super::{cloud::Hash, types::Address, util::Bytes};


#[derive(Default)]
pub struct TrafficEntry {
    pub out_bytes_total: u64,
    pub out_packets_total: usize,
    pub out_bytes: u64,
    pub out_packets: usize,
    pub in_bytes_total: u64,
    pub in_packets_total: usize,
    pub in_bytes: u64,
    pub in_packets: usize,
    pub idle_periods: usize
}

impl TrafficEntry {
    #[inline]
    fn count_out(&mut self, bytes: usize) {
        self.out_packets += 1;
        self.out_bytes += bytes as u64;
    }

    #[inline]
    fn count_in(&mut self, bytes: usize) {
        self.in_packets += 1;
        self.in_bytes += bytes as u64;
    }

    fn period(&mut self) {
        self.out_bytes_total += self.out_bytes;
        self.out_packets_total += self.out_packets;
        self.in_bytes_total += self.in_bytes;
        self.in_packets_total += self.in_packets;
        if self.in_packets == 0 && self.out_packets == 0 {
            self.idle_periods += 1;
        } else {
            self.idle_periods = 0;
        }
        self.out_packets = 0;
        self.in_packets = 0;
        self.out_bytes = 0;
        self.in_bytes = 0;
    }
}


#[derive(Default)]
pub struct TrafficStats {
    peers: HashMap<SocketAddr, TrafficEntry, Hash>,
    payload: HashMap<(Address, Address), TrafficEntry, Hash>
}

impl TrafficStats {
    #[inline]
    pub fn count_out_traffic(&mut self, peer: SocketAddr, bytes: usize) {
        self.peers.entry(peer).or_insert_with(TrafficEntry::default).count_out(bytes);
    }

    #[inline]
    pub fn count_in_traffic(&mut self, peer: SocketAddr, bytes: usize) {
        self.peers.entry(peer).or_insert_with(TrafficEntry::default).count_in(bytes);
    }

    #[inline]
    pub fn count_out_payload(&mut self, remote: Address, local: Address, bytes: usize) {
        self.payload.entry((remote, local)).or_insert_with(TrafficEntry::default).count_out(bytes);
    }

    #[inline]
    pub fn count_in_payload(&mut self, remote: Address, local: Address, bytes: usize) {
        self.payload.entry((remote, local)).or_insert_with(TrafficEntry::default).count_in(bytes);
    }

    pub fn period(&mut self, cleanup_idle: Option<usize>) {
        for entry in self.peers.values_mut() {
            entry.period();
        }
        for entry in self.payload.values_mut() {
            entry.period();
        }
        if let Some(periods) = cleanup_idle {
            self.peers.retain(|_, entry| entry.idle_periods < periods);
            self.payload.retain(|_, entry| entry.idle_periods < periods);
        }
    }

    pub fn get_peer_traffic(&self) -> impl Iterator<Item = (&SocketAddr, &TrafficEntry)> {
        self.peers.iter()
    }

    pub fn get_payload_traffic(&self) -> impl Iterator<Item = (&(Address, Address), &TrafficEntry)> {
        self.payload.iter()
    }

    #[inline]
    pub fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        writeln!(out, "Peer traffic:")?;
        let mut peers: Vec<_> = self.get_peer_traffic().collect();
        peers.sort_unstable_by_key(|(_, data)| (data.out_bytes + data.in_bytes));
        for (addr, data) in peers.iter().rev() {
            writeln!(out, " - {}: in={}/s, out={}/s", addr, Bytes(data.in_bytes / 60), Bytes(data.out_bytes / 60))?;
        }
        writeln!(out)?;
        writeln!(out, "Payload traffic:")?;
        let mut payload: Vec<_> = self.get_payload_traffic().collect();
        payload.sort_unstable_by_key(|(_, data)| (data.out_bytes + data.in_bytes));
        for ((remote, local), data) in payload.iter().rev() {
            writeln!(
                out,
                " - {} <-> {}: in={}/s, out={}/s",
                remote,
                local,
                Bytes(data.in_bytes / 60),
                Bytes(data.out_bytes / 60)
            )?;
        }
        Ok(())
    }
}
