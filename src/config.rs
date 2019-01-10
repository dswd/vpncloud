// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2017  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{MAGIC, Args};

use super::device::Type;
use super::types::{Mode, HeaderMagic};
use super::crypto::CryptoMethod;
use super::util::{Encoder, Duration};

use std::hash::{Hash, Hasher};
use siphasher::sip::SipHasher24;


#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Config {
    pub device_type: Type,
    pub device_name: String,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,
    pub crypto: CryptoMethod,
    pub shared_key: Option<String>,
    pub magic: Option<String>,
    pub port: u16,
    pub peers: Vec<String>,
    pub peer_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub mode: Mode,
    pub dst_timeout: Duration,
    pub subnets: Vec<String>,
    pub port_forwarding: bool,
    pub daemonize: bool,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_type: Type::Tap, device_name: "vpncloud%d".to_string(),
            ifup: None, ifdown: None,
            crypto: CryptoMethod::ChaCha20, shared_key: None,
            magic: None,
            port: 3210, peers: vec![], peer_timeout: 1800, keepalive: None,
            mode: Mode::Normal, dst_timeout: 300,
            subnets: vec![],
            port_forwarding: true,
            daemonize: false,
            pid_file: None,
            stats_file: None,
            user: None,
            group: None
        }
    }
}

impl Config {
    pub fn merge_file(&mut self, file: ConfigFile) {
        if let Some(val) = file.device_type {
            self.device_type = val;
        }
        if let Some(val) = file.device_name {
            self.device_name = val;
        }
        if let Some(val) = file.ifup {
            self.ifup = Some(val);
        }
        if let Some(val) = file.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = file.crypto {
            self.crypto = val;
        }
        if let Some(val) = file.shared_key {
            self.shared_key = Some(val);
        }
        if let Some(val) = file.magic {
            self.magic = Some(val);
        }
        if let Some(val) = file.port {
            self.port = val;
        }
        if let Some(mut val) = file.peers {
            self.peers.append(&mut val);
        }
        if let Some(val) = file.peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = file.keepalive {
            self.keepalive = Some(val);
        }
        if let Some(val) = file.mode {
            self.mode = val;
        }
        if let Some(val) = file.dst_timeout {
            self.dst_timeout = val;
        }
        if let Some(mut val) = file.subnets {
            self.subnets.append(&mut val);
        }
        if let Some(val) = file.port_forwarding {
            self.port_forwarding = val;
        }
        if let Some(val) = file.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = file.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = file.user {
            self.user = Some(val);
        }
        if let Some(val) = file.group {
            self.group = Some(val);
        }
    }

    pub fn merge_args(&mut self, mut args: Args) {
        if let Some(val) = args.flag_type {
            self.device_type = val;
        }
        if let Some(val) = args.flag_device {
            self.device_name = val;
        }
        if let Some(val) = args.flag_ifup {
            self.ifup = Some(val);
        }
        if let Some(val) = args.flag_ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = args.flag_crypto {
            self.crypto = val;
        }
        if let Some(val) = args.flag_shared_key {
            self.shared_key = Some(val);
        }
        if let Some(val) = args.flag_network_id {
            warn!("The --network-id argument is deprecated, please use --magic instead.");
            self.magic = Some(val);
        }
        if let Some(val) = args.flag_magic {
            self.magic = Some(val);
        }
        if let Some(val) = args.flag_listen {
            self.port = val;
        }
        self.peers.append(&mut args.flag_connect);
        if let Some(val) = args.flag_peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = args.flag_keepalive {
            self.keepalive = Some(val);
        }
        if let Some(val) = args.flag_mode {
            self.mode = val;
        }
        if let Some(val) = args.flag_dst_timeout {
            self.dst_timeout = val;
        }
        self.subnets.append(&mut args.flag_subnet);
        if args.flag_no_port_forwarding {
            self.port_forwarding = false;
        }
        if args.flag_daemon {
            self.daemonize = true;
        }
        if let Some(val) = args.flag_pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = args.flag_stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = args.flag_user {
            self.user = Some(val);
        }
        if let Some(val) = args.flag_group {
            self.group = Some(val);
        }
    }

    pub fn get_magic(&self) -> HeaderMagic {
        if let Some(ref name) = self.magic {
            if name.starts_with("hash:") {
                let mut s = SipHasher24::new();
                name[5..].hash(&mut s);
                let mut data = [0; 4];
                Encoder::write_u32((s.finish() & 0xffff_ffff) as u32, &mut data);
                data
            } else {
                let num = try_fail!(u32::from_str_radix(name, 16), "Failed to parse header magic: {}");
                let mut data = [0; 4];
                Encoder::write_u32(num, &mut data);
                data
            }
        } else {
            MAGIC
        }
    }

    pub fn get_keepalive(&self) -> Duration {
        match self.keepalive {
            Some(dur) => dur,
            None => self.peer_timeout/2-60
        }
    }
}


#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct ConfigFile {
    pub device_type: Option<Type>,
    pub device_name: Option<String>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,
    pub crypto: Option<CryptoMethod>,
    pub shared_key: Option<String>,
    pub magic: Option<String>,
    pub port: Option<u16>,
    pub peers: Option<Vec<String>>,
    pub peer_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
    pub mode: Option<Mode>,
    pub dst_timeout: Option<Duration>,
    pub subnets: Option<Vec<String>>,
    pub port_forwarding: Option<bool>,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
}
