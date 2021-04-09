// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{device::Type, types::Mode, util::Duration};
use crate::config::{ConfigFile, ConfigFileBeacon, ConfigFileDevice, ConfigFileStatsd, CryptoConfig};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum OldCryptoMethod {
    #[serde(rename = "chacha20")]
    ChaCha20,
    #[serde(rename = "aes256")]
    AES256,
    #[serde(rename = "aes128")]
    AES128,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct OldConfigFile {
    #[serde(alias = "device-type")]
    pub device_type: Option<Type>,
    #[serde(alias = "device-name")]
    pub device_name: Option<String>,
    #[serde(alias = "device-path")]
    pub device_path: Option<String>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,
    pub crypto: Option<OldCryptoMethod>,
    #[serde(alias = "shared-key")]
    pub shared_key: Option<String>,
    pub magic: Option<String>,
    pub port: Option<u16>,
    pub listen: Option<String>,
    pub peers: Option<Vec<String>>,
    #[serde(alias = "peer-timeout")]
    pub peer_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
    #[serde(alias = "beacon-store")]
    pub beacon_store: Option<String>,
    #[serde(alias = "beacon-load")]
    pub beacon_load: Option<String>,
    #[serde(alias = "beacon-interval")]
    pub beacon_interval: Option<Duration>,
    pub mode: Option<Mode>,
    #[serde(alias = "dst-timeout")]
    pub dst_timeout: Option<Duration>,
    pub subnets: Option<Vec<String>>,
    #[serde(alias = "port-forwarding")]
    pub port_forwarding: Option<bool>,
    #[serde(alias = "pid-file")]
    pub pid_file: Option<String>,
    #[serde(alias = "stats-file")]
    pub stats_file: Option<String>,
    #[serde(alias = "statsd-server")]
    pub statsd_server: Option<String>,
    #[serde(alias = "statsd-prefix")]
    pub statsd_prefix: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
}

impl OldConfigFile {
    #[allow(clippy::or_fun_call)]
    pub fn convert(self) -> ConfigFile {
        if self.device_type.is_none() {
            warn!("The default device type changed from TAP to TUN")
        }
        if self.ifup.is_some() {
            info!("There is a new option --ip that can handle most use cases of --ifup")
        }
        info!("The converted config enables all available encryption algorithms");
        if self.shared_key.is_none() {
            warn!("Operation without a password is no longer supported, password set to 'none'");
        }
        if self.magic.is_some() {
            warn!("The magic header functionality is no longer supported")
        }
        if self.listen.is_some() && self.port.is_some() {
            warn!("The port option is no longer available, using listen instead")
        }
        if self.peer_timeout.is_none() {
            info!("The default peer timeout changed from 10 minutes to 5 minutes")
        }
        warn!("Even with a converted config file version 2 nodes can not communicate with version 1 nodes");
        ConfigFile {
            auto_claim: None,
            beacon: Some(ConfigFileBeacon {
                interval: self.beacon_interval,
                load: self.beacon_load,
                store: self.beacon_store,
                password: self.shared_key.clone(),
            }),
            claims: self.subnets,
            crypto: CryptoConfig {
                algorithms: vec![],
                password: Some(self.shared_key.unwrap_or_else(|| "none".to_string())),
                private_key: None,
                public_key: None,
                trusted_keys: vec![],
            },
            device: Some(ConfigFileDevice {
                fix_rp_filter: None,
                name: self.device_name,
                path: self.device_path,
                type_: self.device_type,
            }),
            group: self.group,
            ifdown: self.ifdown,
            ifup: self.ifup,
            ip: None,
            advertise_addresses: None,
            keepalive: self.keepalive,
            listen: self.listen.or(self.port.map(|p| format!("{}", p))),
            mode: self.mode,
            peer_timeout: self.peer_timeout,
            peers: self.peers,
            pid_file: self.pid_file,
            port_forwarding: self.port_forwarding,
            stats_file: self.stats_file,
            statsd: Some(ConfigFileStatsd { prefix: self.statsd_prefix, server: self.statsd_server }),
            switch_timeout: self.dst_timeout,
            user: self.user,
            hook: None,
            hooks: HashMap::new(),
        }
    }
}
