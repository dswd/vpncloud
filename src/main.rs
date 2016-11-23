// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#![cfg_attr(feature = "bench", feature(test))]

#[macro_use] extern crate log;
#[macro_use] extern crate bitflags;
extern crate time;
extern crate docopt;
extern crate rustc_serialize;
extern crate signal;
extern crate libc;
extern crate aligned_alloc;
extern crate rand;
extern crate fnv;
extern crate net2;
extern crate yaml_rust;
extern crate igd;
extern crate siphasher;
extern crate daemonize;
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
pub mod configfile;
pub mod port_forwarding;
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
use types::{Mode, Range, Table, Protocol, HeaderMagic};
use cloud::GenericCloud;
use crypto::{Crypto, CryptoMethod};
use port_forwarding::PortForwarding;
use util::Duration;
use config::Config;


const VERSION: u8 = 1;
const MAGIC: HeaderMagic = *b"vpn\x01";

static USAGE: &'static str = include_str!("usage.txt");

#[derive(RustcDecodable, Debug, Default)]
pub struct Args {
    flag_config: Option<String>,
    flag_type: Option<Type>,
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
    flag_dst_timeout: Option<Duration>,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_ifup: Option<String>,
    flag_ifdown: Option<String>,
    flag_version: bool,
    flag_no_port_forwarding: bool,
    flag_daemon: bool,
    flag_pid_file: Option<String>,
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
    fn enabled(&self, _metadata: &log::LogMetadata) -> bool {
        true
    }

    #[inline]
    fn log(&self, record: &log::LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
            let mut file = self.file.lock().expect("Lock poisoned");
            if let &mut Some(ref mut file) = &mut file as &mut Option<File> {
                let time = time::strftime("%F %T", &time::now()).expect("Failed to format timestamp");
                writeln!(file, "{} - {} - {}", time, record.level(), record.args()).expect("Failed to write to logfile");
            }
        }
    }
}

fn run_script(script: String, ifname: &str) {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&script).env("IFNAME", ifname);
    debug!("Running script: {:?}", cmd);
    match cmd.status() {
        Ok(status) => if status.success() {
            ()
        } else {
            error!("Script returned with error: {:?}", status.code())
        },
        Err(e) => error!("Failed to execute script {:?}: {}", script, e)
    }
}

fn run<T: Protocol> (config: Config) {
    let device = try_fail!(Device::new(&config.device_name, config.device_type),
        "Failed to open virtual {} interface {}: {}", config.device_type, config.device_name);
    info!("Opened device {}", device.ifname());
    let mut ranges = Vec::with_capacity(config.subnets.len());
    for s in &config.subnets {
        ranges.push(try_fail!(Range::from_str(s), "Invalid subnet format: {} ({})", s));
    }
    let dst_timeout = config.dst_timeout;
    let peer_timeout = config.peer_timeout;
    let (learning, broadcasting, table): (bool, bool, Box<Table>) = match config.mode {
        Mode::Normal => match config.device_type {
            Type::Tap => (true, true, Box::new(SwitchTable::new(dst_timeout))),
            Type::Tun => (false, false, Box::new(RoutingTable::new()))
        },
        Mode::Router => (false, false, Box::new(RoutingTable::new())),
        Mode::Switch => (true, true, Box::new(SwitchTable::new(dst_timeout))),
        Mode::Hub => (false, true, Box::new(SwitchTable::new(dst_timeout)))
    };
    let magic = config.get_magic();
    Crypto::init();
    let crypto = match config.shared_key {
        Some(key) => Crypto::from_shared_key(config.crypto, &key),
        None => Crypto::None
    };
    let port_forwarding = if config.port_forwarding {
        PortForwarding::new(config.port)
    } else {
        None
    };
    let mut cloud = GenericCloud::<T>::new(magic, device, config.port, table, peer_timeout, learning, broadcasting, ranges, crypto, port_forwarding);
    if let Some(script) = config.ifup {
        run_script(script, cloud.ifname());
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
        run_script(script, cloud.ifname());
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
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
    log::set_logger(|max_log_level| {
        assert!(!args.flag_verbose || !args.flag_quiet);
        if args.flag_verbose {
            max_log_level.set(log::LogLevelFilter::Debug);
        } else if args.flag_quiet {
            max_log_level.set(log::LogLevelFilter::Error);
        } else {
            max_log_level.set(log::LogLevelFilter::Info);
        }
        Box::new(try_fail!(DualLogger::new(args.flag_log_file.as_ref()), "Failed to open logfile: {}"))
    }).unwrap();
    let mut config = Config::default();
    if let Some(ref file) = args.flag_config {
        info!("Reading config file '{}'", file);
        let config_file = try_fail!(configfile::parse(file), "Failed to load config file: {:?}");
        config.merge_file(config_file)
    }
    config.merge_args(args);
    debug!("Config: {:?}", config);
    match config.device_type {
        Type::Tap => run::<ethernet::Frame>(config),
        Type::Tun => run::<ip::Packet>(config)
    }
}
