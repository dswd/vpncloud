// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2017  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#![cfg_attr(feature = "bench", feature(test))]

#[macro_use] extern crate log;
#[macro_use] extern crate bitflags;
extern crate time;
extern crate docopt;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_yaml;
extern crate signal;
extern crate libc;
extern crate rand;
extern crate fnv;
extern crate net2;
extern crate yaml_rust;
extern crate igd;
extern crate siphasher;
extern crate daemonize;
extern crate ring;
extern crate bs58;
#[cfg(feature = "bench")] extern crate test;

#[macro_use] pub mod util;
pub mod types;
pub mod crypto;
pub mod udpmessage;
pub mod ethernet;
pub mod ip;
pub mod cloud;
pub mod device;
pub mod poll;
pub mod config;
pub mod port_forwarding;
pub mod traffic;
pub mod beacon;
#[cfg(test)] mod tests;
#[cfg(feature = "bench")] mod benches;

use docopt::Docopt;

use std::sync::Mutex;
use std::str::FromStr;
use std::process::Command;
use std::fs::File;
use std::path::Path;
use std::io::{self, Write};

use device::{Device, Type};
use ethernet::SwitchTable;
use ip::RoutingTable;
use types::{Mode, Range, Protocol, HeaderMagic, Error};
use cloud::GenericCloud;
use crypto::{Crypto, CryptoMethod};
use port_forwarding::PortForwarding;
use util::Duration;
use config::Config;


const VERSION: u8 = 1;
const MAGIC: HeaderMagic = *b"vpn\x01";

static USAGE: &'static str = include_str!("usage.txt");


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
    flag_listen: Option<u16>,
    flag_network_id: Option<String>,
    flag_magic: Option<String>,
    flag_connect: Vec<String>,
    flag_peer_timeout: Option<Duration>,
    flag_keepalive: Option<Duration>,
    flag_dst_timeout: Option<Duration>,
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
            let file = try!(File::create(path));
            Ok(DualLogger{file: Mutex::new(Some(file))})
        } else {
            Ok(DualLogger{file: Mutex::new(None)})
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
                let time = time::strftime("%F %T", &time::now()).expect("Failed to format timestamp");
                writeln!(file, "{} - {} - {}", time, record.level(), record.args()).expect("Failed to write to logfile");
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
        Ok(status) => if !status.success() {
            error!("Script returned with error: {:?}", status.code())
        },
        Err(e) => error!("Failed to execute script {:?}: {}", script, e)
    }
}

enum AnyTable {
    Switch(SwitchTable),
    Routing(RoutingTable)
}

enum AnyCloud<P: Protocol> {
    Switch(GenericCloud<P, SwitchTable>),
    Routing(GenericCloud<P, RoutingTable>)
}

impl<P: Protocol> AnyCloud<P> {
    #[allow(unknown_lints,clippy::too_many_arguments)]
    fn new(config: &Config, device: Device, table: AnyTable,
            learning: bool, broadcast: bool, addresses: Vec<Range>,
            crypto: Crypto, port_forwarding: Option<PortForwarding>) -> Self {
        match table {
            AnyTable::Switch(t) => AnyCloud::Switch(GenericCloud::<P, SwitchTable>::new(
                config, device,t, learning, broadcast, addresses, crypto, port_forwarding
            )),
            AnyTable::Routing(t) => AnyCloud::Routing(GenericCloud::<P, RoutingTable>::new(
                config, device,t, learning, broadcast, addresses, crypto, port_forwarding
            ))
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


fn run<P: Protocol> (config: Config) {
    let device = try_fail!(Device::new(&config.device_name, config.device_type, config.device_path.as_ref().map(|s| s as &str)),
        "Failed to open virtual {} interface {}: {}", config.device_type, config.device_name);
    info!("Opened device {}", device.ifname());
    let mut ranges = Vec::with_capacity(config.subnets.len());
    for s in &config.subnets {
        ranges.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
    }
    let dst_timeout = config.dst_timeout;
    let (learning, broadcasting, table) = match config.mode {
        Mode::Normal => match config.device_type {
            Type::Tap => (true, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10))),
            Type::Tun => (false, false, AnyTable::Routing(RoutingTable::new())),
            Type::Dummy => (false, false, AnyTable::Switch(SwitchTable::new(dst_timeout, 10)))
        },
        Mode::Router => (false, false, AnyTable::Routing(RoutingTable::new())),
        Mode::Switch => (true, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10))),
        Mode::Hub => (false, true, AnyTable::Switch(SwitchTable::new(dst_timeout, 10)))
    };
    Crypto::init();
    let crypto = match config.shared_key {
        Some(ref key) => Crypto::from_shared_key(config.crypto, key),
        None => Crypto::None
    };
    let port_forwarding = if config.port_forwarding {
        PortForwarding::new(config.port)
    } else {
        None
    };
    let mut cloud = AnyCloud::<P>::new(&config, device, table, learning,broadcasting,ranges, crypto, port_forwarding);
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
    }
    cloud.run();
    if let Some(script) = config.ifdown {
        run_script(&script, cloud.ifname());
    }
}

fn main() {
    beacon::test();
    return;
    let args: Args = Docopt::new(USAGE).and_then(|d| d.deserialize()).unwrap_or_else(|e| e.exit());
    if args.flag_version {
        Crypto::init();
        println!("VpnCloud v{}, protocol version {}, libsodium {} (AES256: {})",
            env!("CARGO_PKG_VERSION"),
            VERSION,
            Crypto::sodium_version(),
            Crypto::aes256_available()
        );
        return;
    }
    let logger = try_fail!(DualLogger::new(args.flag_log_file.as_ref()), "Failed to open logfile: {}");
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(!args.flag_verbose || !args.flag_quiet);
    log::set_max_level(
        if args.flag_verbose {
            log::LevelFilter::Debug
        } else if args.flag_quiet {
            log::LevelFilter::Error
        } else {
            log::LevelFilter::Info
        }
    );
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
