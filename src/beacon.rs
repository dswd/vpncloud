// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2019-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use base_62;
use ring::digest;

use std::num::Wrapping;
use std::path::Path;
use std::io::{self, Write, Read};
use std::fs::{self, Permissions, File};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::mem;
use std::thread;
use std::process::{Command, Stdio};

use super::util::{now, Encoder};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, SocketAddrV6, Ipv6Addr};


fn base_62_sanitize(data: &str) -> String {
    data.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

fn sha512(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().iter().map(|b| *b).collect()
}

fn now_hour_16() -> u16 {
    ((now() / 3600) & 0xffff) as u16
}

struct FutureResult<T> {
    has_result: AtomicBool,
    result: Mutex<T>
}

#[derive(Clone)]
pub struct BeaconSerializer {
    magic: Vec<u8>,
    shared_key: Vec<u8>,
    future_peers: Arc<FutureResult<Vec<SocketAddr>>>,
}

impl BeaconSerializer {
    pub fn new(magic: &[u8], shared_key: &[u8]) -> Self {
        BeaconSerializer {
            magic: magic.to_owned(),
            shared_key: shared_key.to_owned(),
            future_peers: Arc::new(FutureResult {
                has_result: AtomicBool::new(false),
                result: Mutex::new(Vec::new())
            })
        }
    }

    fn seed(&self, key: &str) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(key.as_bytes());
        data.extend_from_slice(&self.magic);
        data.extend_from_slice(&self.shared_key);
        sha512(&data)
    }

    fn mask_with_seed(&self, data: &[u8], key: &str) -> Vec<u8> {
        let mask = self.seed(key);
        let mut output = Vec::with_capacity(data.len());
        for i in 0..data.len() {
            output.push(data[i] ^ mask[i]);
        }
        output
    }

    fn begin(&self) -> String {
        base_62::encode(&self.seed("begin"))[0..5].to_string()
    }

    fn end(&self) -> String {
        base_62::encode(&self.seed("end"))[0..5].to_string()
    }

    fn peerlist_encode(&self, peers: &[SocketAddr], now_hour: u16) -> String {
        let mut data = Vec::new();
        // Add timestamp
        data.append(&mut self.mask_with_seed(&now_hour.to_be_bytes(), "time"));
        // Split addresses into v4 and v6
        let mut v4addrs = Vec::new();
        let mut v6addrs = Vec::new();
        for p in peers {
            match *p {
                SocketAddr::V4(addr) => v4addrs.push(addr),
                SocketAddr::V6(addr) => v6addrs.push(addr)
            }
        }
        // Add count of v4 addresses
        data.append(&mut self.mask_with_seed(&[v4addrs.len() as u8], "v4count"));
        // Add v4 addresses
        for addr in v4addrs {
            let mut dat = [0u8; 6];
            dat[0..4].copy_from_slice(&addr.ip().octets());
            Encoder::write_u16(addr.port(), &mut dat[4..]);
            data.append(&mut self.mask_with_seed(&dat, "peer"));
        }
        // Add v6 addresses
        for addr in v6addrs {
            let mut dat = [0u8; 18];
            let ip = addr.ip().segments();
            Encoder::write_u16(ip[0], &mut dat[0..]);
            Encoder::write_u16(ip[1], &mut dat[2..]);
            Encoder::write_u16(ip[2], &mut dat[4..]);
            Encoder::write_u16(ip[3], &mut dat[6..]);
            Encoder::write_u16(ip[4], &mut dat[8..]);
            Encoder::write_u16(ip[5], &mut dat[10..]);
            Encoder::write_u16(ip[6], &mut dat[12..]);
            Encoder::write_u16(ip[7], &mut dat[14..]);
            Encoder::write_u16(addr.port(), &mut dat[16..]);
            data.append(&mut self.mask_with_seed(&dat, "peer"));
        }
        let mut parity = 0;
        for b in &data {
            parity ^= b;
        }
        data.push(parity);
        base_62::encode(&data)
    }

    fn peerlist_decode(&self, data: &str, ttl_hours: Option<u16>, now_hour: u16) -> Vec<SocketAddr> {
        let mut data = base_62::decode(data).expect("Invalid input");
        let mut peers = Vec::new();
        let mut pos = 0;
        if data.len() < 4 {
            return peers
        }
        let mut parity = data.pop().unwrap();
        for b in &data {
            parity ^= b;
        }
        if parity != 0 {
            return peers
        }
        let then = Wrapping(Encoder::read_u16(&self.mask_with_seed(&data[pos..=pos+1], "time")));
        if let Some(ttl) = ttl_hours {
            let now = Wrapping(now_hour);
            if now - then > Wrapping(ttl) && then - now > Wrapping(ttl) {
                return peers
            }
        }
        pos += 2;
        let v4count = self.mask_with_seed(&[data[pos]], "v4count")[0] as usize;
        pos += 1;
        if v4count * 6 > data.len() - pos || (data.len() - pos - v4count * 6) % 18 > 0 {
            return peers
        }
        for _ in 0..v4count {
            assert!(data.len() >= pos + 6);
            let dat = self.mask_with_seed(&data[pos..pos+6], "peer");
            pos += 6;
            let port = Encoder::read_u16(&dat[4..]);
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(dat[0], dat[1], dat[2], dat[3]), port));
            peers.push(addr);
        }
        let v6count = (data.len() - pos)/18;
        for _ in 0..v6count {
            assert!(data.len() >= pos + 18);
            let dat = self.mask_with_seed(&data[pos..pos+18], "peer");
            pos += 18;
            let mut ip = [0u16; 8];
            for i in 0..8 {
                ip[i] = Encoder::read_u16(&dat[i*2..i*2+2]);
            }
            let port = Encoder::read_u16(&dat[16..]);
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(ip[0], ip[1], ip[2],
              ip[3], ip[4], ip[5], ip[6], ip[7]), port, 0, 0));
            peers.push(addr);
        }
        peers
    }

    fn encode_internal(&self, peers: &[SocketAddr], now_hour: u16) -> String {
        format!("{}{}{}", self.begin(), self.peerlist_encode(peers, now_hour), self.end())
    }

    pub fn encode(&self, peers: &[SocketAddr]) -> String {
        self.encode_internal(peers, now_hour_16())
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, peers: &[SocketAddr], path: P) -> Result<(), io::Error> {
        let beacon = self.encode(peers);
        debug!("Beacon: {}", beacon);
        let mut f = try!(File::create(&path));
        try!(writeln!(&mut f, "{}", beacon));
        try!(fs::set_permissions(&path, Permissions::from_mode(0o644)));
        Ok(())
    }

    pub fn write_to_cmd(&self, peers: &[SocketAddr], cmd: &str) -> Result<(), io::Error> {
        let begin = self.begin();
        let data = self.peerlist_encode(peers, now_hour_16());
        let end = self.end();
        let beacon = format!("{}{}{}", begin, data, end);
        debug!("Calling beacon command: {}", cmd);
        let process = try!(Command::new("sh").args(&["-c", cmd])
            .env("begin", begin).env("data", data).env("end", end).env("beacon", beacon)
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn());
        thread::spawn(move || {
            let output = process.wait_with_output().expect("Failed to wait on child");
            if !output.status.success() {
                error!("Beacon command failed: {}", String::from_utf8_lossy(&output.stderr));
            } else {
                debug!("Beacon command succeeded");
            }
        });
        Ok(())
    }

    fn decode_internal(&self, data: &str, ttl_hours: Option<u16>, now_hour: u16) -> Vec<SocketAddr> {
        let data = base_62_sanitize(data);
        let mut peers = Vec::new();
        let begin = self.begin();
        let end = self.end();
        let mut pos = 0;
        while let Some(found) = data[pos..].find(&begin) {
            pos += found;
            let start_pos = pos + begin.len();
            if let Some(found) = data[pos..].find(&end) {
                let end_pos = pos + found;
                peers.append(&mut self.peerlist_decode(&data[start_pos..end_pos], ttl_hours, now_hour));
                pos = start_pos
            } else {
                break
            }
        }
        peers
    }

    pub fn decode(&self, data: &str, ttl_hours: Option<u16>) -> Vec<SocketAddr> {
        self.decode_internal(data, ttl_hours, now_hour_16())
    }

    pub fn read_from_file<P: AsRef<Path>>(&self, path: P, ttl_hours: Option<u16>) -> Result<Vec<SocketAddr>, io::Error> {
        let mut f = try!(File::open(&path));
        let mut contents = String::new();
        try!(f.read_to_string(&mut contents));
        Ok(self.decode(&contents, ttl_hours))
    }

    pub fn read_from_cmd(&self, cmd: &str, ttl_hours: Option<u16>) -> Result<(), io::Error> {
        let begin = self.begin();
        let end = self.end();
        debug!("Calling beacon command: {}", cmd);
        let process = try!(Command::new("sh").args(&["-c", cmd])
            .env("begin", begin).env("end", end)
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn());
        let this = self.clone();
        thread::spawn(move || {
            let output = process.wait_with_output().expect("Failed to wait on child");
            if output.status.success() {
                let data = String::from_utf8_lossy(&output.stdout);
                let mut peers = this.decode(&data, ttl_hours);
                debug!("Beacon command succeeded with {} peers", peers.len());
                mem::swap(&mut peers, &mut this.future_peers.result.lock().expect("Lock poisoned"));
                this.future_peers.has_result.store(true, Ordering::Relaxed);
            } else {
                error!("Beacon command failed: {}", String::from_utf8_lossy(&output.stderr));
            }
        });
        Ok(())
    }

    pub fn get_cmd_results(&self) -> Option<Vec<SocketAddr>> {
        if self.future_peers.has_result.load(Ordering::Relaxed) {
            let mut peers = Vec::new();
            mem::swap(&mut peers, &mut self.future_peers.result.lock().expect("Lock poisoned"));
            self.future_peers.has_result.store(false, Ordering::Relaxed);
            Some(peers)
        } else {
            None
        }
    }
}


#[cfg(test)] use std::str::FromStr;
#[cfg(test)] use std::time::Duration;
#[cfg(test)] use tempfile;

#[test]
fn encode() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", ser.encode_internal(&peers, 2000));
    peers.push(SocketAddr::from_str("[::1]:5678").unwrap());
    assert_eq!("JHEiL4gZk5Jq5R3IRnwJiIqgGzBPgXJrhO1hrmeSRCNLaw26VcVSGriv", ser.encode_internal(&peers, 2000));
}

#[test]
fn decode() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 2000)));
    peers.push(SocketAddr::from_str("[::1]:5678").unwrap());
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("JHEiL4gZk5Jq5R3IRnwJiIqgGzBPgXJrhO1hrmeSRCNLaw26VcVSGriv", None, 2000)));
}

#[test]
fn decode_split() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("JHEiL-pS.FT:n8 R4\tPI\nQ1(mu)Dy[5t]Y3ülEäSGriv", None, 2000)));
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("J -, \nHE--iLpSFTn8R4PIQ1muDy5tY3lES(G}rÖÄÜ\niv", None, 2000)));
}

#[test]
fn decode_offset() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("Hello World: JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv! End of the World", None, 2000)));
}

#[test]
fn decode_multiple() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode_internal("JHEiL4dGxY6nwSaDoRBSGriv JHEiL7c3Y6ptTMaDoRBSGriv", None, 2000)));
}

#[test]
fn decode_ttl() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 2000).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 2100).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 2005).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 1995).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", Some(24), 2000).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", Some(24), 1995).len());
    assert_eq!(2, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", Some(24), 2005).len());
    assert_eq!(0, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", Some(24), 2100).len());
    assert_eq!(0, ser.decode_internal("JHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", Some(24), 1900).len());
}

#[test]
fn decode_invalid() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    assert_eq!(0, ser.decode_internal("", None, 2000).len());
    assert_eq!(0, ser.decode_internal("JHEiLSGriv", None, 2000).len());
    assert_eq!(0, ser.decode_internal("JHEiL--", None, 2000).len());
    assert_eq!(0, ser.decode_internal("--SGriv", None, 2000).len());
    assert_eq!(0, ser.decode_internal("JHEiLpSFTn8R4PIQ1nuDy5tY3lESGriv", None, 2000).len());
    assert_eq!(2, ser.decode_internal("SGrivJHEiLpSFTn8R4PIQ1muDy5tY3lESGrivJHEiL", None, 2000).len());
    assert_eq!(2, ser.decode_internal("JHEiLJHEiLpSFTn8R4PIQ1muDy5tY3lESGriv", None, 2000).len());
}

#[test]
fn encode_decode() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    let data = ser.encode(&peers);
    let peers2 = ser.decode(&data, None);
    assert_eq!(format!("{:?}", peers), format!("{:?}", peers2));
}

#[test]
fn encode_decode_file() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    let file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    assert!(ser.write_to_file(&peers, file.path()).is_ok());
    let peers2 = ser.read_from_file(file.path(), None);
    assert!(peers2.is_ok());
    assert_eq!(format!("{:?}", peers), format!("{:?}", peers2.unwrap()));
}

#[test]
fn encode_decode_cmd() {
    let ser = BeaconSerializer::new(b"vpnc", b"mysecretkey");
    let mut peers = Vec::new();
    peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
    peers.push(SocketAddr::from_str("6.6.6.6:53").unwrap());
    let file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    assert!(ser.write_to_cmd(&peers, &format!("echo $beacon > {}", file.path().display())).is_ok());
    thread::sleep(Duration::from_millis(100));
    let res = ser.read_from_cmd(&format!("cat {}", file.path().display()), None);
    assert!(res.is_ok());
    thread::sleep(Duration::from_millis(100));
    let peers2 = ser.get_cmd_results();
    assert!(peers2.is_some());
    assert_eq!(format!("{:?}", peers), format!("{:?}", peers2.unwrap()));
}