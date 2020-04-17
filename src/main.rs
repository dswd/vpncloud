// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#![cfg_attr(feature = "bench", feature(test))]

#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;

#[cfg(test)] extern crate tempfile;
#[cfg(feature = "bench")] extern crate test;

#[macro_use]
pub mod util;
#[cfg(test)]
#[macro_use]
mod tests;
pub mod beacon;
#[cfg(feature = "bench")] mod benches;
pub mod cloud;
pub mod config;
pub mod crypto;
pub mod device;
pub mod ethernet;
pub mod ip;
pub mod net;
pub mod poll;
pub mod port_forwarding;
pub mod traffic;
pub mod types;
pub mod udpmessage;

use docopt::Docopt;

use std::{
    fs::{self, File, Permissions},
    io::{self, Write},
    net::UdpSocket,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    str::FromStr,
    sync::Mutex
};

use crate::{
    cloud::GenericCloud,
    config::Config,
    crypto::{Crypto, CryptoMethod},
    device::{Device, TunTapDevice, Type},
    ethernet::SwitchTable,
    ip::RoutingTable,
    port_forwarding::PortForwarding,
    types::{Error, HeaderMagic, Mode, Protocol, Range},
    util::{Duration, SystemTimeSource}
};


const VERSION: u8 = 1;
const MAGIC: HeaderMagic = *b"vpn\x01";

static USAGE: &str = include_str!("usage.txt");


#[derive(Deserialize, Debug, Default)]
pub struct Args {
    flag_config: Option<String>,
    flag_type: Option<Type>,
    flag_device_path: Option<String>,
    flag_mode: Option<Mode>,
    flag_shared_key: Option<String>,
    flag_crypto: Option<CryptoMethod>,
    flag_subnet: Vec<String>,
    flag_device: Option<String>,
    flag_listen: Option<String>,
    flag_network_id: Option<String>,
    flag_magic: Option<String>,
    flag_connect: Vec<String>,
    flag_peer_timeout: Option<Duration>,
    flag_keepalive: Option<Duration>,
    flag_dst_timeout: Option<Duration>,
    flag_beacon_store: Option<String>,
    flag_beacon_load: Option<String>,
    flag_beacon_interval: Option<Duration>,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_ifup: Option<String>,
    flag_ifdown: Option<String>,
    flag_version: bool,
    flag_no_port_forwarding: bool,
    flag_daemon: bool,
    flag_pid_file: Option<String>,
    flag_stats_file: Option<String>,
    flag_user: Option<String>,
    flag_group: Option<String>,
    flag_log_file: Option<String>
}

struct DualLogger {
    file: Mutex<Option<File>>
}

impl DualLogger {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Result<Self, io::Error> {
        if let Some(path) = path {
            let path = path.as_ref();
            if path.exists() {
                fs::remove_file(path)?
            }
            let file = File::create(path)?;
            Ok(DualLogger { file: Mutex::new(Some(file)) })
        } else {
            Ok(DualLogger { file: Mutex::new(None) })
        }
    }
}

impl log::Log for DualLogger {
    #[inline]
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    #[inline]
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
            let mut file = self.file.lock().expect("Lock poisoned");
            if let Some(ref mut file) = *file {
                let time = time::OffsetDateTime::now_local().format("%F %T");
                writeln!(file, "{} - {} - {}", time, record.level(), record.args())
                    .expect("Failed to write to logfile");
            }
        }
    }

    #[inline]
    fn flush(&self) {
        let mut file = self.file.lock().expect("Lock poisoned");
        if let Some(ref mut file) = *file {
            try_fail!(file.flush(), "Logging error: {}");
        }
    }
}

fn run_script(script: &str, ifname: &str) {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&script).env("IFNAME", ifname);
    debug!("Running script: {:?}", cmd);
    match cmd.status() {
        Ok(status) => {
            if !status.success() {
                error!("Script returned with error: {:?}", status.code())
            }
        }
        Err(e) => error!("Failed to execute script {:?}: {}", script, e)
    }
}

enum AnyTable {
    Switch(SwitchTable<SystemTimeSource>),
    Routing(RoutingTable)
}

enum AnyCloud<P: Protocol> {
    Switch(GenericCloud<TunTapDevice, P, SwitchTable<SystemTimeSource>, UdpSocket, SystemTimeSource>),
    Routing(GenericCloud<TunTapDevice, P, RoutingTable, UdpSocket, SystemTimeSource>)
}

impl<P: Protocol> AnyCloud<P> {
    #[allow(unknown_lints, clippy::too_many_arguments)]
    fn new(
        config: &Config, device: TunTapDevice, table: AnyTable, learning: bool, broadcast: bool, addresses: Vec<Range>,
        crypto: Crypto, port_forwarding: Option<PortForwarding>, stats_file: Option<File>
    ) -> Self
    {
        match table {
            AnyTable::Switch(t) => {
                AnyCloud::Switch(GenericCloud::<
                    TunTapDevice,
                    P,
                    SwitchTable<SystemTimeSource>,
                    UdpSocket,
                    SystemTimeSource
                >::new(
                    config,
                    device,
                    t,
                    learning,
                    broadcast,
                    addresses,
                    crypto,
                    port_forwarding,
                    stats_file
                ))
            }
            AnyTable::Routing(t) => {
                AnyCloud::Routing(GenericCloud::<TunTapDevice, P, RoutingTable, UdpSocket, SystemTimeSource>::new(
                    config,
                    device,
                    t,
                    learning,
                    broadcast,
                    addresses,
                    crypto,
                    port_forwarding,
                    stats_file
                ))
            }
        }
    }

    fn ifname(&self) -> &str {
        match *self {
            AnyCloud::Switch(ref c) => c.ifname(),
            AnyCloud::Routing(ref c) => c.ifname()
        }
    }

    fn run(&mut self) {
        match *self {
            AnyCloud::Switch(ref mut c) => c.run(),
            AnyCloud::Routing(ref mut c) => c.run()
        }
    }

    fn connect(&mut self, a: &str) -> Result<(), Error> {
        match *self {
            AnyCloud::Switch(ref mut c) => c.connect(a),
            AnyCloud::Routing(ref mut c) => c.connect(a)
        }
    }

    fn add_reconnect_peer(&mut self, a: String) {
        match *self {
            AnyCloud::Switch(ref mut c) => c.add_reconnect_peer(a),
            AnyCloud::Routing(ref mut c) => c.add_reconnect_peer(a)
        }
    }
}


#[allow(clippy::cognitive_complexity)]
fn run<P: Protocol>(config: Config) {
    let device = try_fail!(
        TunTapDevice::new(&config.device_name, config.device_type, config.device_path.as_ref().map(|s| s as &str)),
        "Failed to open virtual {} interface {}: {}",
        config.device_type,
        config.device_name
    );
    info!("Opened device {}", device.ifname());
    let mut ranges = Vec::with_capacity(config.subnets.len());
    for s in &config.subnets {
        ranges.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
    }
    let dst_timeout = config.dst_timeout;
    let (learning, broadcasting, table) = match config.mode {
        Mode::Normal => {
            match config.device_type {
                Type::Tap => (true, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10))),
                Type::Tun => (false, false, AnyTable::Routing(RoutingTable::new())),
                Type::Dummy => (false, false, AnyTable::Switch(SwitchTable::new(dst_timeout, 10)))
            }
        }
        Mode::Router => (false, false, AnyTable::Routing(RoutingTable::new())),
        Mode::Switch => (true, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10))),
        Mode::Hub => (false, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10)))
    };
    let crypto = match config.shared_key {
        Some(ref key) => Crypto::from_shared_key(config.crypto, key),
        None => Crypto::None
    };
    let port_forwarding = if config.port_forwarding { PortForwarding::new(config.listen.port()) } else { None };
    let stats_file = match config.stats_file {
        None => None,
        Some(ref name) => {
            let path = Path::new(name);
            if path.exists() {
                try_fail!(fs::remove_file(path), "Failed to remove file {}: {}", name);
            }
            let file = try_fail!(File::create(name), "Failed to create stats file: {}");
            try_fail!(
                fs::set_permissions(name, Permissions::from_mode(0o644)),
                "Failed to set permissions on stats file: {}"
            );
            Some(file)
        }
    };
    let mut cloud =
        AnyCloud::<P>::new(&config, device, table, learning, broadcasting, ranges, crypto, port_forwarding, stats_file);
    if let Some(script) = config.ifup {
        run_script(&script, cloud.ifname());
    }
    for addr in config.peers {
        try_fail!(cloud.connect(&addr as &str), "Failed to send message to {}: {}", &addr);
        cloud.add_reconnect_peer(addr);
    }
    if config.daemonize {
        info!("Running process as daemon");
        let mut daemonize = daemonize::Daemonize::new();
        if let Some(user) = config.user {
            daemonize = daemonize.user(&user as &str);
        }
        if let Some(group) = config.group {
            daemonize = daemonize.group(&group as &str);
        }
        if let Some(pid_file) = config.pid_file {
            daemonize = daemonize.pid_file(pid_file).chown_pid_file(true);
        }
        try_fail!(daemonize.start(), "Failed to daemonize: {}");
    } else if config.user.is_some() || config.group.is_some() {
        info!("Dropping privileges");
        let mut pd = privdrop::PrivDrop::default();
        if let Some(user) = config.user {
            pd = pd.user(user);
        }
        if let Some(group) = config.group {
            pd = pd.group(group);
        }
        try_fail!(pd.apply(), "Failed to drop privileges: {}");
    }
    cloud.run();
    if let Some(script) = config.ifdown {
        run_script(&script, cloud.ifname());
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.deserialize()).unwrap_or_else(|e| e.exit());
    if args.flag_version {
        println!("VpnCloud v{}, protocol version {}", env!("CARGO_PKG_VERSION"), VERSION);
        return
    }
    let logger = try_fail!(DualLogger::new(args.flag_log_file.as_ref()), "Failed to open logfile: {}");
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(!args.flag_verbose || !args.flag_quiet);
    log::set_max_level(if args.flag_verbose {
        log::LevelFilter::Debug
    } else if args.flag_quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    });
    let mut config = Config::default();
    if let Some(ref file) = args.flag_config {
        info!("Reading config file '{}'", file);
        let f = try_fail!(File::open(file), "Failed to open config file: {:?}");
        let config_file = try_fail!(serde_yaml::from_reader(f), "Failed to load config file: {:?}");
        config.merge_file(config_file)
    }
    config.merge_args(args);
    debug!("Config: {:?}", config);
    match config.device_type {
        Type::Tap => run::<ethernet::Frame>(config),
        Type::Tun => run::<ip::Packet>(config),
        Type::Dummy => run::<ethernet::Frame>(config)
    }
}
