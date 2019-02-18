use bs58;
use ring::digest;

use std::str::FromStr;

use super::util::{now, Encoder};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, SocketAddrV6, Ipv6Addr};


fn base58_encode(data: &[u8]) -> String {
  bs58::encode(data).into_string()
}

fn base58_decode(data: &str) -> Vec<u8> {
  bs58::decode(data).into_vec().unwrap()
}

fn sha512(data: &[u8]) -> Vec<u8> {
  digest::digest(&digest::SHA512, data).as_ref().iter().map(|b| *b).collect()
}


pub struct BeaconSerializer {
  magic: Vec<u8>,
  shared_key: String
}

impl BeaconSerializer {
  pub fn new(magic: &[u8], shared_key: &str) -> Self {
    BeaconSerializer {
      magic: magic.to_owned(),
      shared_key: shared_key.to_string()
    }
  }

  fn seed(&self, key: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(key.as_bytes());
    data.extend_from_slice(&self.magic);
    data.extend_from_slice(self.shared_key.as_bytes());
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
    base58_encode(&self.seed("begin"))[0..5].to_string()
  }

  fn end(&self) -> String {
    base58_encode(&self.seed("end"))[0..5].to_string()
  }

  fn peerlist_encode(&self, peers: &[SocketAddr]) -> String {
    let mut data = Vec::new();
    // Add timestamp
    data.append(&mut self.mask_with_seed(&(now() as u32).to_be_bytes(), "time"));
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
    base58_encode(&data)
  }

  fn peerlist_decode(&self, data: &str) -> Vec<SocketAddr> {
    let data = base58_decode(data);
    let mut peers = Vec::new();
    //TODO: decode time
    let mut pos = 4;
    let v4count = self.mask_with_seed(&[data[pos]], "v4count")[0];
    pos += 1;
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

  fn decode(&self, data: &str) -> Vec<SocketAddr> {
    //TODO: remove anything that is not base58
    let mut peers = Vec::new();
    let begin = self.begin();
    let end = self.end();
    let mut pos = 0;
    while let Some(found) = data[pos..].find(&begin) {
      pos += found;
      let start_pos = pos + begin.len();
      if let Some(found) = data[pos..].find(&end) {
        let end_pos = pos + found;
        peers.append(&mut self.peerlist_decode(&data[start_pos..end_pos]));
        pos = end_pos + end.len();
      } else {
        pos += begin.len();
      }
    }
    peers
  }
}


pub fn test() {
  let beacon = BeaconSerializer::new(b"vpnc", "mysecretkey");
  let mut peers = Vec::new();
  peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
  peers.push(SocketAddr::from_str("1.2.3.4:5678").unwrap());
  peers.push(SocketAddr::from_str("[::1]:5678").unwrap());
  let string = format!("{}{}{}", beacon.begin(), beacon.peerlist_encode(&peers), beacon.end());
  println!("{}", string);
  println!("{:?}", beacon.decode(&string));
}
