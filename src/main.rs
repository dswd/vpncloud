// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
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

use structopt::StructOpt;

use std::{
    fs::{self, File, Permissions},
    io::{self, Write},
    net::UdpSocket,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    str::FromStr,
    sync::Mutex,
    thread
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


#[derive(StructOpt, Debug, Default)]
pub struct Args {
    /// Read configuration options from the specified file.
    #[structopt(long)]
    config: Option<String>,

    /// Set the type of network ("tap" or "tun")
    #[structopt(name = "type", short, long)]
    type_: Option<Type>,

    /// Set the path of the base device
    #[structopt(long)]
    device_path: Option<String>,

    /// The mode of the VPN ("normal", "router", "switch", or "hub")
    #[structopt(short, long)]
    mode: Option<Mode>,

    /// The shared key to encrypt all traffic
    #[structopt(short, long, aliases=&["shared-key", "secret-key", "secret"])]
    key: Option<String>,

    /// The encryption method to use ("aes128", "aes256", or "chacha20")
    #[structopt(long)]
    crypto: Option<CryptoMethod>,

    /// The local subnets to use
    #[structopt(short, long)]
    subnets: Vec<String>,

    /// Name of the virtual device
    #[structopt(short, long)]
    device: Option<String>,

    /// The port number (or ip:port) on which to listen for data
    #[structopt(short, long)]
    listen: Option<String>,

    /// Optional token that identifies the network. (DEPRECATED)
    #[structopt(long)]
    network_id: Option<String>,

    /// Override the 4-byte magic header of each packet
    #[structopt(long)]
    magic: Option<String>,

    /// Address of a peer to connect to
    #[structopt(short, long)]
    connect: Vec<String>,

    /// Peer timeout in seconds
    #[structopt(long)]
    peer_timeout: Option<Duration>,
    /// Periodically send message to keep connections alive
    #[structopt(long)]
    keepalive: Option<Duration>,

    /// Switch table entry timeout in seconds
    #[structopt(long)]
    dst_timeout: Option<Duration>,

    /// The file path or |command to store the beacon
    #[structopt(long)]
    beacon_store: Option<String>,

    /// The file path or |command to load the beacon
    #[structopt(long)]
    beacon_load: Option<String>,

    /// Beacon store/load interval in seconds
    #[structopt(long)]
    beacon_interval: Option<Duration>,

    /// Print debug information
    #[structopt(short, long, conflicts_with = "quiet")]
    verbose: bool,

    /// Only print errors and warnings
    #[structopt(short, long)]
    quiet: bool,

    /// A command to setup the network interface
    #[structopt(long)]
    ifup: Option<String>,

    /// A command to bring down the network interface
    #[structopt(long)]
    ifdown: Option<String>,

    /// Print the version and exit
    #[structopt(long)]
    version: bool,

    /// Disable automatic port forwarding
    #[structopt(long)]
    no_port_forwarding: bool,

    /// Run the process in the background
    #[structopt(long)]
    daemon: bool,

    /// Store the process id in this file when daemonizing
    #[structopt(long)]
    pid_file: Option<String>,

    /// Print statistics to this file
    #[structopt(long)]
    stats_file: Option<String>,

    /// Send statistics to this statsd server
    #[structopt(long)]
    statsd_server: Option<String>,

    /// Use the given prefix for statsd records
    #[structopt(long)]
    statsd_prefix: Option<String>,

    /// Run as other user
    #[structopt(long)]
    user: Option<String>,

    /// Run as other group
    #[structopt(long)]
    group: Option<String>,

    /// Print logs also to this file
    #[structopt(long)]
    log_file: Option<String>
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
            // Give child process some time to write PID file
            daemonize = daemonize.exit_action(|| thread::sleep(std::time::Duration::from_millis(10)));
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
    let args: Args = Args::from_args();
    if args.version {
        println!("VpnCloud v{}, protocol version {}", env!("CARGO_PKG_VERSION"), VERSION);
        return
    }
    let logger = try_fail!(DualLogger::new(args.log_file.as_ref()), "Failed to open logfile: {}");
    log::set_boxed_logger(Box::new(logger)).unwrap();
    assert!(!args.verbose || !args.quiet);
    log::set_max_level(if args.verbose {
        log::LevelFilter::Debug
    } else if args.quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    });
    let mut config = Config::default();
    if let Some(ref file) = args.config {
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
