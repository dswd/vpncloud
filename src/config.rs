// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{device::Type, types::Mode, util::run_cmd, util::Duration};
pub use crate::crypto::Config as CryptoConfig;

use std::{cmp::max, collections::HashMap, ffi::OsStr, process, thread};
use structopt::{clap::Shell, StructOpt};

pub const DEFAULT_PEER_TIMEOUT: u16 = 300;
pub const DEFAULT_PORT: u16 = 3210;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct Config {
    pub device_type: Type,
    pub device_name: String,
    pub device_path: Option<String>,
    pub fix_rp_filter: bool,

    pub ip: Option<String>,
    pub advertise_addresses: Vec<String>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,

    pub listen: String,
    pub peers: Vec<String>,
    pub peer_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub beacon_store: Option<String>,
    pub beacon_load: Option<String>,
    pub beacon_interval: Duration,
    pub beacon_password: Option<String>,
    pub mode: Mode,
    pub switch_timeout: Duration,
    pub claims: Vec<String>,
    pub auto_claim: bool,
    pub port_forwarding: bool,
    pub daemonize: bool,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub statsd_server: Option<String>,
    pub statsd_prefix: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            device_type: Type::Tun,
            device_name: "vpncloud%d".to_string(),
            device_path: None,
            fix_rp_filter: false,
            ip: None,
            advertise_addresses: vec![],
            ifup: None,
            ifdown: None,
            crypto: CryptoConfig::default(),
            listen: "3210".to_string(),
            peers: vec![],
            peer_timeout: DEFAULT_PEER_TIMEOUT as Duration,
            keepalive: None,
            beacon_store: None,
            beacon_load: None,
            beacon_interval: 3600,
            beacon_password: None,
            mode: Mode::Normal,
            switch_timeout: 300,
            claims: vec![],
            auto_claim: true,
            port_forwarding: true,
            daemonize: false,
            pid_file: None,
            stats_file: None,
            statsd_server: None,
            statsd_prefix: None,
            user: None,
            group: None,
            hook: None,
            hooks: HashMap::new(),
        }
    }
}

impl Config {
    #[allow(clippy::cognitive_complexity)]
    pub fn merge_file(&mut self, mut file: ConfigFile) {
        if let Some(device) = file.device {
            if let Some(val) = device.type_ {
                self.device_type = val;
            }
            if let Some(val) = device.name {
                self.device_name = val;
            }
            if let Some(val) = device.path {
                self.device_path = Some(val);
            }
            if let Some(val) = device.fix_rp_filter {
                self.fix_rp_filter = val;
            }
        }
        if let Some(val) = file.ip {
            self.ip = Some(val);
        }
        if let Some(mut val) = file.advertise_addresses {
            self.advertise_addresses.append(&mut val);
        }
        if let Some(val) = file.ifup {
            self.ifup = Some(val);
        }
        if let Some(val) = file.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = file.listen {
            self.listen = val;
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
        if let Some(beacon) = file.beacon {
            if let Some(val) = beacon.store {
                self.beacon_store = Some(val);
            }
            if let Some(val) = beacon.load {
                self.beacon_load = Some(val);
            }
            if let Some(val) = beacon.interval {
                self.beacon_interval = val;
            }
            if let Some(val) = beacon.password {
                self.beacon_password = Some(val);
            }
        }
        if let Some(val) = file.mode {
            self.mode = val;
        }
        if let Some(val) = file.switch_timeout {
            self.switch_timeout = val;
        }
        if let Some(mut val) = file.claims {
            self.claims.append(&mut val);
        }
        if let Some(val) = file.auto_claim {
            self.auto_claim = val;
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
        if let Some(statsd) = file.statsd {
            if let Some(val) = statsd.server {
                self.statsd_server = Some(val);
            }
            if let Some(val) = statsd.prefix {
                self.statsd_prefix = Some(val);
            }
        }
        if let Some(val) = file.user {
            self.user = Some(val);
        }
        if let Some(val) = file.group {
            self.group = Some(val);
        }
        if let Some(val) = file.crypto.password {
            self.crypto.password = Some(val)
        }
        if let Some(val) = file.crypto.public_key {
            self.crypto.public_key = Some(val)
        }
        if let Some(val) = file.crypto.private_key {
            self.crypto.private_key = Some(val)
        }
        self.crypto.trusted_keys.append(&mut file.crypto.trusted_keys);
        if !file.crypto.algorithms.is_empty() {
            self.crypto.algorithms = file.crypto.algorithms.clone();
        }
        if let Some(val) = file.hook {
            self.hook = Some(val)
        }
        for (k, v) in file.hooks {
            self.hooks.insert(k, v);
        }
    }

    pub fn merge_args(&mut self, mut args: Args) {
        if let Some(val) = args.type_ {
            self.device_type = val;
        }
        if let Some(val) = args.device {
            self.device_name = val;
        }
        if let Some(val) = args.device_path {
            self.device_path = Some(val);
        }
        if args.fix_rp_filter {
            self.fix_rp_filter = true;
        }
        if let Some(val) = args.ip {
            self.ip = Some(val);
        }
        if let Some(val) = args.ifup {
            self.ifup = Some(val);
        }
        self.advertise_addresses.append(&mut args.advertise_addresses);
        if let Some(val) = args.ifdown {
            self.ifdown = Some(val);
        }
        if let Some(val) = args.listen {
            self.listen = val;
        }
        self.peers.append(&mut args.peers);
        if let Some(val) = args.peer_timeout {
            self.peer_timeout = val;
        }
        if let Some(val) = args.keepalive {
            self.keepalive = Some(val);
        }
        if let Some(val) = args.beacon_store {
            self.beacon_store = Some(val);
        }
        if let Some(val) = args.beacon_load {
            self.beacon_load = Some(val);
        }
        if let Some(val) = args.beacon_interval {
            self.beacon_interval = val;
        }
        if let Some(val) = args.beacon_password {
            self.beacon_password = Some(val);
        }
        if let Some(val) = args.mode {
            self.mode = val;
        }
        if let Some(val) = args.switch_timeout {
            self.switch_timeout = val;
        }
        self.claims.append(&mut args.claims);
        if args.no_auto_claim {
            self.auto_claim = false;
        }
        if args.no_port_forwarding {
            self.port_forwarding = false;
        }
        if args.daemon {
            self.daemonize = true;
        }
        if let Some(val) = args.pid_file {
            self.pid_file = Some(val);
        }
        if let Some(val) = args.stats_file {
            self.stats_file = Some(val);
        }
        if let Some(val) = args.statsd_server {
            self.statsd_server = Some(val);
        }
        if let Some(val) = args.statsd_prefix {
            self.statsd_prefix = Some(val);
        }
        if let Some(val) = args.user {
            self.user = Some(val);
        }
        if let Some(val) = args.group {
            self.group = Some(val);
        }
        if let Some(val) = args.password {
            self.crypto.password = Some(val)
        }
        if let Some(val) = args.public_key {
            self.crypto.public_key = Some(val)
        }
        if let Some(val) = args.private_key {
            self.crypto.private_key = Some(val)
        }
        self.crypto.trusted_keys.append(&mut args.trusted_keys);
        if !args.algorithms.is_empty() {
            self.crypto.algorithms = args.algorithms.clone();
        }
        for s in args.hook {
            if s.contains(':') {
                let pos = s.find(':').unwrap();
                let name = &s[..pos];
                let hook = &s[pos + 1..];
                self.hooks.insert(name.to_string(), hook.to_string());
            } else {
                self.hook = Some(s);
            }
        }
    }

    pub fn into_config_file(self) -> ConfigFile {
        ConfigFile {
            auto_claim: Some(self.auto_claim),
            claims: Some(self.claims),
            beacon: Some(ConfigFileBeacon {
                store: self.beacon_store,
                load: self.beacon_load,
                interval: Some(self.beacon_interval),
                password: self.beacon_password,
            }),
            device: Some(ConfigFileDevice {
                name: Some(self.device_name),
                path: self.device_path,
                type_: Some(self.device_type),
                fix_rp_filter: Some(self.fix_rp_filter),
            }),
            crypto: self.crypto,
            group: self.group,
            user: self.user,
            ifup: self.ifup,
            ifdown: self.ifdown,
            ip: self.ip,
            advertise_addresses: Some(self.advertise_addresses),
            keepalive: self.keepalive,
            listen: Some(self.listen),
            mode: Some(self.mode),
            peer_timeout: Some(self.peer_timeout),
            peers: Some(self.peers),
            pid_file: self.pid_file,
            port_forwarding: Some(self.port_forwarding),
            stats_file: self.stats_file,
            statsd: Some(ConfigFileStatsd { server: self.statsd_server, prefix: self.statsd_prefix }),
            switch_timeout: Some(self.switch_timeout),
            hook: self.hook,
            hooks: self.hooks,
        }
    }

    pub fn get_keepalive(&self) -> Duration {
        match self.keepalive {
            Some(dur) => dur,
            None => max(self.peer_timeout / 2 - 60, 1),
        }
    }

    pub fn call_hook(
        &self, event: &'static str, envs: impl IntoIterator<Item = (&'static str, impl AsRef<OsStr>)>, detach: bool,
    ) {
        let mut script = None;
        if let Some(ref s) = self.hook {
            script = Some(s);
        }
        if let Some(s) = self.hooks.get(event) {
            script = Some(s);
        }
        if script.is_none() {
            return;
        }
        let script = script.unwrap();
        let mut cmd = process::Command::new("sh");
        cmd.arg("-c").arg(script).envs(envs).env("EVENT", event);
        debug!("Running event script: {:?}", cmd);
        if detach {
            thread::spawn(move || run_cmd(cmd));
        } else {
            run_cmd(cmd)
        }
    }
}

#[derive(StructOpt, Debug, Default)]
pub struct Args {
    /// Read configuration options from the specified file.
    #[structopt(long)]
    pub config: Option<String>,

    /// Set the type of network
    #[structopt(name = "type", short, long, possible_values=&["tun", "tap"])]
    pub type_: Option<Type>,

    /// Set the path of the base device
    #[structopt(long)]
    pub device_path: Option<String>,

    /// Fix the rp_filter settings on the host
    #[structopt(long)]
    pub fix_rp_filter: bool,

    /// The mode of the VPN
    #[structopt(short, long, possible_values=&["normal", "router", "switch", "hub"])]
    pub mode: Option<Mode>,

    /// The shared password to encrypt all traffic
    #[structopt(short, long, env)]
    pub password: Option<String>,

    /// The private key to use
    #[structopt(long, alias = "key", conflicts_with = "password", env)]
    pub private_key: Option<String>,

    /// The public key to use
    #[structopt(long)]
    pub public_key: Option<String>,

    /// Other public keys to trust
    #[structopt(long = "trusted-key", alias = "trust", use_delimiter = true)]
    pub trusted_keys: Vec<String>,

    /// Algorithms to allow
    #[structopt(long = "algorithm", alias = "algo", use_delimiter=true, case_insensitive = true, possible_values=&["plain", "aes128", "aes256", "chacha20"])]
    pub algorithms: Vec<String>,

    /// The local subnets to claim (IP or IP/prefix)
    #[structopt(long = "claim", use_delimiter = true)]
    pub claims: Vec<String>,

    /// Do not automatically claim the device ip
    #[structopt(long)]
    pub no_auto_claim: bool,

    /// Name of the virtual device
    #[structopt(short, long)]
    pub device: Option<String>,

    /// The port number (or ip:port) on which to listen for data
    #[structopt(short, long)]
    pub listen: Option<String>,

    /// Address of a peer to connect to
    #[structopt(short = "c", long = "peer", alias = "connect")]
    pub peers: Vec<String>,

    /// Peer timeout in seconds
    #[structopt(long)]
    pub peer_timeout: Option<Duration>,

    /// Periodically send message to keep connections alive
    #[structopt(long)]
    pub keepalive: Option<Duration>,

    /// Switch table entry timeout in seconds
    #[structopt(long)]
    pub switch_timeout: Option<Duration>,

    /// The file path or |command to store the beacon
    #[structopt(long)]
    pub beacon_store: Option<String>,

    /// The file path or |command to load the beacon
    #[structopt(long)]
    pub beacon_load: Option<String>,

    /// Beacon store/load interval in seconds
    #[structopt(long)]
    pub beacon_interval: Option<Duration>,

    /// Password to encrypt the beacon with
    #[structopt(long)]
    pub beacon_password: Option<String>,

    /// Print debug information
    #[structopt(short, long, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Only print errors and warnings
    #[structopt(short, long)]
    pub quiet: bool,

    /// An IP address (plus optional prefix length) for the interface
    #[structopt(long)]
    pub ip: Option<String>,

    /// A list of IP Addresses to advertise as our external address(s)
    #[structopt(long = "advertise_addresses", use_delimiter = true)]
    pub advertise_addresses: Vec<String>,

    /// A command to setup the network interface
    #[structopt(long)]
    pub ifup: Option<String>,

    /// A command to bring down the network interface
    #[structopt(long)]
    pub ifdown: Option<String>,

    /// Print the version and exit
    #[structopt(long)]
    pub version: bool,

    /// Disable automatic port forwarding
    #[structopt(long)]
    pub no_port_forwarding: bool,

    /// Run the process in the background
    #[structopt(long)]
    pub daemon: bool,

    /// Store the process id in this file when daemonizing
    #[structopt(long)]
    pub pid_file: Option<String>,

    /// Print statistics to this file
    #[structopt(long)]
    pub stats_file: Option<String>,

    /// Send statistics to this statsd server
    #[structopt(long)]
    pub statsd_server: Option<String>,

    /// Use the given prefix for statsd records
    #[structopt(long, requires = "statsd-server")]
    pub statsd_prefix: Option<String>,

    /// Run as other user
    #[structopt(long)]
    pub user: Option<String>,

    /// Run as other group
    #[structopt(long)]
    pub group: Option<String>,

    /// Print logs also to this file
    #[structopt(long)]
    pub log_file: Option<String>,

    /// Call script on event
    #[structopt(long)]
    pub hook: Vec<String>,

    #[structopt(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    /// Generate and print a key-pair and exit
    #[structopt(name = "genkey", alias = "gen-key")]
    GenKey {
        /// The shared password to encrypt all traffic
        #[structopt(short, long, env)]
        password: Option<String>,
    },

    /// Run a websocket proxy
    #[cfg(feature = "websocket")]
    #[structopt(alias = "wsproxy")]
    WsProxy {
        /// Websocket listen address IP:PORT
        #[structopt(long, short, default_value = "3210")]
        listen: String,
    },

    /// Migrate an old config file
    #[structopt(alias = "migrate")]
    MigrateConfig {
        /// Config file
        #[structopt(long)]
        config_file: String,
    },

    /// Generate shell completions
    Completion {
        /// Shell to create completions for
        #[structopt(long, default_value = "bash")]
        shell: Shell,
    },

    /// Edit the config of a network
    #[cfg(feature = "wizard")]
    Config {
        /// Name of the network
        #[structopt(short, long)]
        name: Option<String>,
    },

    /// Install required utility files
    #[cfg(feature = "installer")]
    Install {
        /// Remove installed files again
        #[structopt(long)]
        uninstall: bool,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileDevice {
    #[serde(rename = "type")]
    pub type_: Option<Type>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub fix_rp_filter: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileBeacon {
    pub store: Option<String>,
    pub load: Option<String>,
    pub interval: Option<Duration>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFileStatsd {
    pub server: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
pub struct ConfigFile {
    pub device: Option<ConfigFileDevice>,

    pub ip: Option<String>,
    pub advertise_addresses: Option<Vec<String>>,
    pub ifup: Option<String>,
    pub ifdown: Option<String>,

    pub crypto: CryptoConfig,
    pub listen: Option<String>,
    pub peers: Option<Vec<String>>,
    pub peer_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,

    pub beacon: Option<ConfigFileBeacon>,
    pub mode: Option<Mode>,
    pub switch_timeout: Option<Duration>,
    pub claims: Option<Vec<String>>,
    pub auto_claim: Option<bool>,
    pub port_forwarding: Option<bool>,
    pub pid_file: Option<String>,
    pub stats_file: Option<String>,
    pub statsd: Option<ConfigFileStatsd>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub hook: Option<String>,
    pub hooks: HashMap<String, String>,
}

#[test]
fn config_file() {
    let config_file = "
device:
  type: tun
  name: vpncloud%d
  path: /dev/net/tun
ip: 10.0.1.1/16
advertise-addresses:
  - 192.168.0.1
  - 192.168.1.1
ifup: ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up
ifdown: 'true'
peers:
  - remote.machine.foo:3210
  - remote.machine.bar:3210
peer-timeout: 600
keepalive: 840
switch-timeout: 300
beacon:
  store: /run/vpncloud.beacon.out
  load: /run/vpncloud.beacon.in
  interval: 3600
  password: test123
mode: normal
claims:
  - 10.0.1.0/24
port-forwarding: true
user: nobody
group: nogroup
pid-file: /run/vpncloud.run
stats-file: /var/log/vpncloud.stats
statsd:
  server: example.com:1234
  prefix: prefix
    ";
    assert_eq!(
        serde_yaml::from_str::<ConfigFile>(config_file).unwrap(),
        ConfigFile {
            device: Some(ConfigFileDevice {
                type_: Some(Type::Tun),
                name: Some("vpncloud%d".to_string()),
                path: Some("/dev/net/tun".to_string()),
                fix_rp_filter: None
            }),
            ip: Some("10.0.1.1/16".to_string()),
            advertise_addresses: Some(vec!["192.168.0.1".to_string(), "192.168.1.1".to_string()]),
            ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
            ifdown: Some("true".to_string()),
            crypto: CryptoConfig::default(),
            listen: None,
            peers: Some(vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()]),
            peer_timeout: Some(600),
            keepalive: Some(840),
            beacon: Some(ConfigFileBeacon {
                store: Some("/run/vpncloud.beacon.out".to_string()),
                load: Some("/run/vpncloud.beacon.in".to_string()),
                interval: Some(3600),
                password: Some("test123".to_string())
            }),
            mode: Some(Mode::Normal),
            switch_timeout: Some(300),
            claims: Some(vec!["10.0.1.0/24".to_string()]),
            auto_claim: None,
            port_forwarding: Some(true),
            user: Some("nobody".to_string()),
            group: Some("nogroup".to_string()),
            pid_file: Some("/run/vpncloud.run".to_string()),
            stats_file: Some("/var/log/vpncloud.stats".to_string()),
            statsd: Some(ConfigFileStatsd {
                server: Some("example.com:1234".to_string()),
                prefix: Some("prefix".to_string())
            }),
            hook: None,
            hooks: HashMap::new()
        }
    )
}

#[test]
fn parse_example_config() {
    serde_yaml::from_str::<ConfigFile>(include_str!("../assets/example.net.disabled")).unwrap();
}

#[test]
fn config_merge() {
    let mut config = Config::default();
    config.merge_file(ConfigFile {
        device: Some(ConfigFileDevice {
            type_: Some(Type::Tun),
            name: Some("vpncloud%d".to_string()),
            path: None,
            fix_rp_filter: None,
        }),
        ip: None,
        advertise_addresses: Some(vec![]),
        ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
        ifdown: Some("true".to_string()),
        crypto: CryptoConfig::default(),
        listen: None,
        peers: Some(vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()]),
        peer_timeout: Some(600),
        keepalive: Some(840),
        beacon: Some(ConfigFileBeacon {
            store: Some("/run/vpncloud.beacon.out".to_string()),
            load: Some("/run/vpncloud.beacon.in".to_string()),
            interval: Some(7200),
            password: Some("test123".to_string()),
        }),
        mode: Some(Mode::Normal),
        switch_timeout: Some(300),
        claims: Some(vec!["10.0.1.0/24".to_string()]),
        auto_claim: Some(true),
        port_forwarding: Some(true),
        user: Some("nobody".to_string()),
        group: Some("nogroup".to_string()),
        pid_file: Some("/run/vpncloud.run".to_string()),
        stats_file: Some("/var/log/vpncloud.stats".to_string()),
        statsd: Some(ConfigFileStatsd {
            server: Some("example.com:1234".to_string()),
            prefix: Some("prefix".to_string()),
        }),
        hook: None,
        hooks: HashMap::new(),
    });
    assert_eq!(
        config,
        Config {
            device_type: Type::Tun,
            device_name: "vpncloud%d".to_string(),
            device_path: None,
            ip: None,
            advertise_addresses: vec![],
            ifup: Some("ifconfig $IFNAME 10.0.1.1/16 mtu 1400 up".to_string()),
            ifdown: Some("true".to_string()),
            listen: "3210".to_string(),
            peers: vec!["remote.machine.foo:3210".to_string(), "remote.machine.bar:3210".to_string()],
            peer_timeout: 600,
            keepalive: Some(840),
            switch_timeout: 300,
            beacon_store: Some("/run/vpncloud.beacon.out".to_string()),
            beacon_load: Some("/run/vpncloud.beacon.in".to_string()),
            beacon_interval: 7200,
            beacon_password: Some("test123".to_string()),
            mode: Mode::Normal,
            port_forwarding: true,
            claims: vec!["10.0.1.0/24".to_string()],
            user: Some("nobody".to_string()),
            group: Some("nogroup".to_string()),
            pid_file: Some("/run/vpncloud.run".to_string()),
            stats_file: Some("/var/log/vpncloud.stats".to_string()),
            statsd_server: Some("example.com:1234".to_string()),
            statsd_prefix: Some("prefix".to_string()),
            ..Default::default()
        }
    );
    config.merge_args(Args {
        type_: Some(Type::Tap),
        device: Some("vpncloud0".to_string()),
        device_path: Some("/dev/null".to_string()),
        ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
        ifdown: Some("ifconfig $IFNAME down".to_string()),
        password: Some("anothersecret".to_string()),
        listen: Some("[::]:3211".to_string()),
        peer_timeout: Some(1801),
        keepalive: Some(850),
        switch_timeout: Some(301),
        beacon_store: Some("/run/vpncloud.beacon.out2".to_string()),
        beacon_load: Some("/run/vpncloud.beacon.in2".to_string()),
        beacon_interval: Some(3600),
        beacon_password: Some("test1234".to_string()),
        mode: Some(Mode::Switch),
        claims: vec![],
        peers: vec!["another:3210".to_string()],
        no_port_forwarding: true,
        daemon: true,
        pid_file: Some("/run/vpncloud-mynet.run".to_string()),
        stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
        statsd_server: Some("example.com:2345".to_string()),
        statsd_prefix: Some("prefix2".to_string()),
        user: Some("root".to_string()),
        group: Some("root".to_string()),
        ..Default::default()
    });
    assert_eq!(
        config,
        Config {
            device_type: Type::Tap,
            device_name: "vpncloud0".to_string(),
            device_path: Some("/dev/null".to_string()),
            fix_rp_filter: false,
            ip: None,
            advertise_addresses: vec![],

            ifup: Some("ifconfig $IFNAME 10.0.1.2/16 mtu 1400 up".to_string()),
            ifdown: Some("ifconfig $IFNAME down".to_string()),
            crypto: CryptoConfig { password: Some("anothersecret".to_string()), ..CryptoConfig::default() },
            listen: "[::]:3211".to_string(),
            peers: vec![
                "remote.machine.foo:3210".to_string(),
                "remote.machine.bar:3210".to_string(),
                "another:3210".to_string()
            ],
            peer_timeout: 1801,
            keepalive: Some(850),
            switch_timeout: 301,
            beacon_store: Some("/run/vpncloud.beacon.out2".to_string()),
            beacon_load: Some("/run/vpncloud.beacon.in2".to_string()),
            beacon_interval: 3600,
            beacon_password: Some("test1234".to_string()),
            mode: Mode::Switch,
            port_forwarding: false,
            claims: vec!["10.0.1.0/24".to_string()],
            auto_claim: true,
            user: Some("root".to_string()),
            group: Some("root".to_string()),
            pid_file: Some("/run/vpncloud-mynet.run".to_string()),
            stats_file: Some("/var/log/vpncloud-mynet.stats".to_string()),
            statsd_server: Some("example.com:2345".to_string()),
            statsd_prefix: Some("prefix2".to_string()),
            daemonize: true,
            hook: None,
            hooks: HashMap::new()
        }
    );
}
