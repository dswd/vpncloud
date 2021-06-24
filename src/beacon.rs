// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use ring::digest;

use std::{
    fs::{self, File, Permissions},
    io::{self, Read, Write},
    marker::PhantomData,
    mem,
    num::Wrapping,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use super::util::{from_base62, to_base62, Encoder, TimeSource};
use smallvec::SmallVec;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const TYPE_BEGIN: u8 = 0;
const TYPE_END: u8 = 1;
const TYPE_DATA: u8 = 2;
const TYPE_SEED: u8 = 3;

fn base_62_sanitize(data: &str) -> String {
    data.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

fn sha512(data: &[u8]) -> SmallVec<[u8; 64]> {
    digest::digest(&digest::SHA512, data).as_ref().into()
}

struct FutureResult<T> {
    has_result: AtomicBool,
    result: Mutex<T>,
}

#[derive(Clone)]
pub struct BeaconSerializer<TS> {
    shared_key: Vec<u8>,
    future_peers: Arc<FutureResult<Vec<SocketAddr>>>,
    _dummy_ts: PhantomData<TS>,
}

impl<TS: TimeSource> BeaconSerializer<TS> {
    pub fn new(shared_key: &[u8]) -> Self {
        Self {
            shared_key: shared_key.to_owned(),
            future_peers: Arc::new(FutureResult { has_result: AtomicBool::new(false), result: Mutex::new(Vec::new()) }),
            _dummy_ts: PhantomData,
        }
    }

    fn now_hour_16() -> u16 {
        ((TS::now() / 3600) & 0xffff) as u16
    }

    fn get_keystream(&self, type_: u8, seed: u8, iter: u8) -> SmallVec<[u8; 64]> {
        let mut data = SmallVec::<[u8; 128]>::new();
        data.extend_from_slice(&[type_, seed, iter]);
        data.extend_from_slice(&self.shared_key);
        sha512(&data)
    }

    #[allow(clippy::needless_range_loop)]
    fn mask_with_keystream(&self, data: &mut [u8], type_: u8, seed: u8) {
        let mut iter = 0;
        let mut mask = self.get_keystream(type_, seed, iter);
        let mut pos = 0;
        for i in 0..data.len() {
            data[i] ^= mask[pos];
            pos += 1;
            if pos == 16 {
                pos = 0;
                iter += 1;
                mask = self.get_keystream(type_, seed, iter);
            }
        }
    }

    fn begin(&self) -> String {
        to_base62(&self.get_keystream(TYPE_BEGIN, 0, 0))[0..5].to_string()
    }

    fn end(&self) -> String {
        to_base62(&self.get_keystream(TYPE_END, 0, 0))[0..5].to_string()
    }

    fn encrypt_data(&self, data: &mut Vec<u8>) {
        // Note: the 1 byte seed is only meant to protect from random changes,
        // not malicious ones. For full protection, at least 8 bytes (~12
        // characters) would be needed.
        let seed = sha512(data as &[u8])[0];
        self.mask_with_keystream(data as &mut [u8], TYPE_DATA, seed);
        data.push(seed ^ self.get_keystream(TYPE_SEED, 0, 0)[0]);
    }

    fn decrypt_data(&self, data: &mut Vec<u8>) -> bool {
        if data.is_empty() {
            return false;
        }
        let seed = data.pop().unwrap() ^ self.get_keystream(TYPE_SEED, 0, 0)[0];
        self.mask_with_keystream(data as &mut [u8], TYPE_DATA, seed);
        seed == sha512(data as &[u8])[0]
    }

    fn peerlist_encode(&self, peers: &[SocketAddr]) -> String {
        let mut data = Vec::new();
        // Add timestamp
        data.extend_from_slice(&Self::now_hour_16().to_be_bytes());
        // Split addresses into v4 and v6
        let mut v4addrs = SmallVec::<[SocketAddrV4; 256]>::new();
        let mut v6addrs = SmallVec::<[SocketAddrV6; 256]>::new();
        for p in peers {
            match *p {
                SocketAddr::V4(addr) => v4addrs.push(addr),
                SocketAddr::V6(addr) => v6addrs.push(addr),
            }
        }
        // Add count of v4 addresses
        data.push(v4addrs.len() as u8);
        // Add v4 addresses
        for addr in v4addrs {
            let mut dat = [0u8; 6];
            dat[0..4].copy_from_slice(&addr.ip().octets());
            Encoder::write_u16(addr.port(), &mut dat[4..]);
            data.extend_from_slice(&dat);
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
            data.extend_from_slice(&dat);
        }
        self.encrypt_data(&mut data);
        to_base62(&data)
    }

    fn peerlist_decode(&self, data: &str, ttl_hours: Option<u16>) -> Vec<SocketAddr> {
        let mut data = from_base62(data).expect("Invalid input");
        let mut peers = Vec::new();
        let mut pos = 0;
        if data.len() < 4 {
            return peers;
        }
        if !self.decrypt_data(&mut data) {
            return peers;
        }
        let then = Wrapping(Encoder::read_u16(&data[pos..=pos + 1]));
        if let Some(ttl) = ttl_hours {
            let now = Wrapping(Self::now_hour_16());
            if now - then > Wrapping(ttl) && then - now > Wrapping(ttl) {
                return peers;
            }
        }
        pos += 2;
        let v4count = data[pos] as usize;
        pos += 1;
        if v4count * 6 > data.len() - pos || (data.len() - pos - v4count * 6) % 18 > 0 {
            return peers;
        }
        for _ in 0..v4count {
            assert!(data.len() >= pos + 6);
            let dat = &data[pos..pos + 6];
            pos += 6;
            let port = Encoder::read_u16(&dat[4..]);
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(dat[0], dat[1], dat[2], dat[3]), port));
            peers.push(addr);
        }
        let v6count = (data.len() - pos) / 18;
        for _ in 0..v6count {
            assert!(data.len() >= pos + 18);
            let dat = &data[pos..pos + 18];
            pos += 18;
            let mut ip = [0u16; 8];
            for i in 0..8 {
                ip[i] = Encoder::read_u16(&dat[i * 2..i * 2 + 2]);
            }
            let port = Encoder::read_u16(&dat[16..]);
            let addr = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]),
                port,
                0,
                0,
            ));
            peers.push(addr);
        }
        peers
    }

    pub fn encode(&self, peers: &[SocketAddr]) -> String {
        format!("{}{}{}", self.begin(), self.peerlist_encode(peers), self.end())
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, peers: &[SocketAddr], path: P) -> Result<(), io::Error> {
        let beacon = self.encode(peers);
        debug!("Beacon: {}", beacon);
        let path = path.as_ref();
        if path.exists() {
            fs::remove_file(path)?
        }
        let mut f = File::create(path)?;
        writeln!(&mut f, "{}", beacon)?;
        fs::set_permissions(path, Permissions::from_mode(0o444))?;
        Ok(())
    }

    pub fn write_to_cmd(&self, peers: &[SocketAddr], cmd: &str) -> Result<(), io::Error> {
        let begin = self.begin();
        let data = self.peerlist_encode(peers);
        let end = self.end();
        let beacon = format!("{}{}{}", begin, data, end);
        debug!("Calling beacon command: {}", cmd);
        let process = Command::new("sh")
            .args(&["-c", cmd])
            .env("begin", begin)
            .env("data", data)
            .env("end", end)
            .env("beacon", beacon)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
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

    pub fn decode(&self, data: &str, ttl_hours: Option<u16>) -> Vec<SocketAddr> {
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
                peers.append(&mut self.peerlist_decode(&data[start_pos..end_pos], ttl_hours));
                pos = start_pos
            } else {
                break;
            }
        }
        peers
    }

    pub fn read_from_file<P: AsRef<Path>>(
        &self, path: P, ttl_hours: Option<u16>,
    ) -> Result<Vec<SocketAddr>, io::Error> {
        let mut f = File::open(&path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        Ok(self.decode(&contents, ttl_hours))
    }

    pub fn read_from_cmd(&self, cmd: &str, ttl_hours: Option<u16>) -> Result<(), io::Error> {
        let begin = self.begin();
        let end = self.end();
        debug!("Calling beacon command: {}", cmd);
        let process = Command::new("sh")
            .args(&["-c", cmd])
            .env("begin", begin)
            .env("end", end)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
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

#[cfg(test)]
use crate::util::MockTimeSource;
#[cfg(test)]
use std::str::FromStr;
#[cfg(test)]
use std::time::Duration;

#[test]
fn encode() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let mut peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    assert_eq!("WsHI31EWDMBYxvITiILIrm2k9gEik22E", ser.encode(&peers));
    peers.push(SocketAddr::from_str("[::1]:5678").unwrap());
    assert_eq!("WsHI3GXKaXCveo6uejmZizZ72kR6Y0L9T7h49TXONp1ugfKvvvEik22E", ser.encode(&peers));
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:54").unwrap()];
    assert_eq!("WsHI32gm9eMSHP3Lm1GXcdP7rD3ik22E", ser.encode(&peers));
}

#[test]
fn decode() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let mut peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    assert_eq!(format!("{:?}", peers), format!("{:?}", ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", None)));
    peers.push(SocketAddr::from_str("[::1]:5678").unwrap());
    assert_eq!(
        format!("{:?}", peers),
        format!("{:?}", ser.decode("WsHI3GXKaXCveo6uejmZizZ72kR6Y0L9T7h49TXONp1ugfKvvvEik22E", None))
    );
}

#[test]
fn decode_split() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    assert_eq!(
        format!("{:?}", peers),
        format!("{:?}", ser.decode("WsHI3-1E.WD:MB Yx\tvI\nTi(IL)Ir[m2]k9ügEäik22E", None))
    );
    assert_eq!(
        format!("{:?}", peers),
        format!("{:?}", ser.decode("W -, \nsH--I31EWDMBYxvITiILIrm2k9gEi(k)2ÖÄÜ\n2E", None))
    );
}

#[test]
fn decode_offset() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    assert_eq!(
        format!("{:?}", peers),
        format!("{:?}", ser.decode("Hello World: WsHI31EWDMBYxvITiILIrm2k9gEik22E! End of the World", None))
    );
}

#[test]
fn decode_multiple() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    assert_eq!(
        format!("{:?}", peers),
        format!("{:?}", ser.decode("WsHI31HVpqxFNMNSPrvik22E WsHI34yOBcZIulKdtn2ik22E", None))
    );
}

#[test]
fn decode_ttl() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    MockTimeSource::set_time(2000 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", None).len());
    MockTimeSource::set_time(2100 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", None).len());
    MockTimeSource::set_time(2005 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", None).len());
    MockTimeSource::set_time(1995 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", None).len());
    MockTimeSource::set_time(2000 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", Some(24)).len());
    MockTimeSource::set_time(1995 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", Some(24)).len());
    MockTimeSource::set_time(2005 * 3600);
    assert_eq!(2, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", Some(24)).len());
    MockTimeSource::set_time(2100 * 3600);
    assert_eq!(0, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", Some(24)).len());
    MockTimeSource::set_time(1900 * 3600);
    assert_eq!(0, ser.decode("WsHI31EWDMBYxvITiILIrm2k9gEik22E", Some(24)).len());
}

#[test]
fn decode_invalid() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    assert_eq!(0, ser.decode("", None).len());
    assert_eq!(0, ser.decode("WsHI3ik22E", None).len());
    assert_eq!(0, ser.decode("WsHI3--", None).len());
    assert_eq!(0, ser.decode("--ik22E", None).len());
    assert_eq!(0, ser.decode("WsHI32EWDMBYxvITiILIrm2k9gEik22E", None).len());
    assert_eq!(2, ser.decode("ik22EWsHI31EWDMBYxvITiILIrm2k9gEik22EWsHI3", None).len());
    assert_eq!(2, ser.decode("WsHI3WsHI31EWDMBYxvITiILIrm2k9gEik22Eik22E", None).len());
}

#[test]
fn encode_decode() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    let data = ser.encode(&peers);
    let peers2 = ser.decode(&data, None);
    assert_eq!(format!("{:?}", peers), format!("{:?}", peers2));
}

#[test]
fn encode_decode_file() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
    let file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    assert!(ser.write_to_file(&peers, file.path()).is_ok());
    let peers2 = ser.read_from_file(file.path(), None);
    assert!(peers2.is_ok());
    assert_eq!(format!("{:?}", peers), format!("{:?}", peers2.unwrap()));
}

#[test]
fn encode_decode_cmd() {
    MockTimeSource::set_time(2000 * 3600);
    let ser = BeaconSerializer::<MockTimeSource>::new(b"mysecretkey");
    let peers = vec![SocketAddr::from_str("1.2.3.4:5678").unwrap(), SocketAddr::from_str("6.6.6.6:53").unwrap()];
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
