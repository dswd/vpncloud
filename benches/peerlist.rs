#![feature(test)]
extern crate test;
extern crate time;

use std::net::{SocketAddr, ToSocketAddrs, SocketAddrV4, Ipv4Addr};
use std::collections::HashMap;

use time::{Duration, SteadyTime};

use test::Bencher;

struct PeerListHashMap {
    timeout: Duration,
    peers: HashMap<SocketAddr, SteadyTime>
}

impl PeerListHashMap {
    fn new(timeout: Duration) -> Self {
        PeerListHashMap{peers: HashMap::new(), timeout: timeout}
    }

    fn add(&mut self, addr: &SocketAddr) {
        if self.peers.insert(*addr, SteadyTime::now()+self.timeout).is_none() {
        }
    }
}

struct PeerListVec {
    timeout: Duration,
    peers: Vec<(SocketAddr, SteadyTime)>
}

impl PeerListVec {
    fn new(timeout: Duration) -> Self {
        PeerListVec{peers: Vec::new(), timeout: timeout}
    }

    fn add(&mut self, addr: &SocketAddr) {
        for &(ref peer, ref timeout) in &self.peers {
            if peer == addr {
                return;
            }
        }
        self.peers.push((*addr, SteadyTime::now()+self.timeout));
    }
}

fn bench_hashmap_add_n(b: &mut Bencher, n: u16) {
    let mut peers = PeerListHashMap::new(Duration::seconds(60));
    for i in 0..n {
        peers.add(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 1), i)));
    }
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    b.iter(|| {
        peers.add(&addr)
    })
}

#[bench]
fn bench_hashmap_add_0(b: &mut Bencher) {
    bench_hashmap_add_n(b, 0);
}

#[bench]
fn bench_hashmap_add_1(b: &mut Bencher) {
    bench_hashmap_add_n(b, 1);
}

#[bench]
fn bench_hashmap_add_10(b: &mut Bencher) {
    bench_hashmap_add_n(b, 10);
}

#[bench]
fn bench_hashmap_add_100(b: &mut Bencher) {
    bench_hashmap_add_n(b, 100);
}

#[bench]
fn bench_hashmap_add_1000(b: &mut Bencher) {
    bench_hashmap_add_n(b, 1000);
}

fn bench_vec_add_n(b: &mut Bencher, n: u16) {
    let mut peers = PeerListVec::new(Duration::seconds(60));
    for i in 0..n {
        peers.add(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 1), i)));
    }
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
    b.iter(|| {
        peers.add(&addr)
    })
}

#[bench]
fn bench_vec_add_0(b: &mut Bencher) {
    bench_vec_add_n(b, 0);
}

#[bench]
fn bench_vec_add_1(b: &mut Bencher) {
    bench_vec_add_n(b, 1);
}

#[bench]
fn bench_vec_add_10(b: &mut Bencher) {
    bench_vec_add_n(b, 10);
}

#[bench]
fn bench_vec_add_100(b: &mut Bencher) {
    bench_vec_add_n(b, 100);
}

#[bench]
fn bench_vec_add_1000(b: &mut Bencher) {
    bench_vec_add_n(b, 1000);
}
