// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use fnv::FnvHasher;
use std::{
    cmp::min, collections::HashMap, hash::BuildHasherDefault, io, io::Write, marker::PhantomData, net::SocketAddr
};

use crate::{
    types::{Address, Range, RangeList},
    util::{addr_nice, Duration, Time, TimeSource}
};


type Hash = BuildHasherDefault<FnvHasher>;


struct CacheValue {
    peer: SocketAddr,
    timeout: Time
}

struct ClaimEntry {
    peer: SocketAddr,
    claim: Range,
    timeout: Time
}

pub struct ClaimTable<TS: TimeSource> {
    cache: HashMap<Address, CacheValue, Hash>,
    cache_timeout: Duration,
    claims: Vec<ClaimEntry>,
    claim_timeout: Duration,
    _dummy: PhantomData<TS>
}

impl<TS: TimeSource> ClaimTable<TS> {
    pub fn new(cache_timeout: Duration, claim_timeout: Duration) -> Self {
        Self { cache: HashMap::default(), cache_timeout, claims: vec![], claim_timeout, _dummy: PhantomData }
    }

    pub fn cache(&mut self, addr: Address, peer: SocketAddr) {
        self.cache.insert(addr, CacheValue { peer, timeout: TS::now() + self.cache_timeout as Time });
    }

    pub fn set_claims(&mut self, peer: SocketAddr, mut claims: RangeList) {
        for entry in &mut self.claims {
            if entry.peer == peer {
                let pos = claims.iter().position(|r| r == &entry.claim);
                if let Some(pos) = pos {
                    entry.timeout = TS::now() + self.claim_timeout as Time;
                    claims.swap_remove(pos);
                    if claims.is_empty() {
                        break
                    }
                } else {
                    entry.timeout = 0
                }
            }
        }
        for claim in claims {
            self.claims.push(ClaimEntry { peer, claim, timeout: TS::now() + self.claim_timeout as Time })
        }
        self.housekeep()
    }

    pub fn remove_claims(&mut self, peer: SocketAddr) {
        for entry in &mut self.claims {
            if entry.peer == peer {
                entry.timeout = 0
            }
        }
        self.housekeep()
    }

    pub fn lookup(&mut self, addr: Address) -> Option<SocketAddr> {
        if let Some(entry) = self.cache.get(&addr) {
            return Some(entry.peer)
        }
        for entry in &self.claims {
            if entry.claim.matches(addr) {
                self.cache.insert(addr, CacheValue {
                    peer: entry.peer,
                    timeout: min(TS::now() + self.cache_timeout as Time, entry.timeout)
                });
                return Some(entry.peer)
            }
        }
        None
    }

    pub fn housekeep(&mut self) {
        let now = TS::now();
        // TODO: also remove cache when removing claims
        self.cache.retain(|_, v| v.timeout >= now);
        self.claims.retain(|e| e.timeout >= now);
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn claim_len(&self) -> usize {
        self.claims.len()
    }

    /// Write out the table
    pub fn write_out<W: Write>(&self, out: &mut W) -> Result<(), io::Error> {
        let now = TS::now();
        writeln!(out, "forwarding_table:")?;
        writeln!(out, "  claims:")?;
        for entry in &self.claims {
            writeln!(
                out,
                "    - \"{}\": {{ peer: \"{}\", timeout: {} }}",
                entry.claim,
                addr_nice(entry.peer),
                entry.timeout - now
            )?;
        }
        writeln!(out, "  cache:")?;
        for (addr, entry) in &self.cache {
            writeln!(
                out,
                "    - \"{}\": {{ peer: \"{}\", timeout: {} }}",
                addr,
                addr_nice(entry.peer),
                entry.timeout - now
            )?;
        }
        Ok(())
    }
}

// TODO: test

#[cfg(feature = "bench")]
mod bench {
    use super::*;
    use crate::util::MockTimeSource;

    use test::Bencher;
    use std::str::FromStr;
    use smallvec::smallvec;

    #[bench]
    fn lookup_warm(b: &mut Bencher) {
        let mut table = ClaimTable::<MockTimeSource>::new(60, 60);
        let addr = Address::from_str("1.2.3.4").unwrap();
        table.cache(addr, SocketAddr::from_str("1.2.3.4:3210").unwrap());
        b.iter(|| table.lookup(addr));
        b.bytes = 1400;
    }

    #[bench]
    fn lookup_cold(b: &mut Bencher) {
        let mut table = ClaimTable::<MockTimeSource>::new(60, 60);
        let addr = Address::from_str("1.2.3.4").unwrap();
        table.set_claims(SocketAddr::from_str("1.2.3.4:3210").unwrap(), smallvec![
            Range::from_str("1.2.3.4/32").unwrap()
        ]);
        b.iter(|| {
            table.cache.clear();
            table.lookup(addr)
        });
        b.bytes = 1400;
    }
}
