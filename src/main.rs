#[macro_use] extern crate log;
extern crate time;
extern crate docopt;
extern crate rustc_serialize;
extern crate epoll;
extern crate signal;
extern crate nix;
#[cfg(feature = "crypto")] extern crate libsodium_sys;

#[macro_use] mod util;
mod types;
mod crypto;
mod udpmessage;
mod ethernet;
mod ip;
mod cloud;
mod device;

use time::Duration;
use docopt::Docopt;

use std::hash::{Hash, SipHasher, Hasher};
use std::str::FromStr;
use std::process::Command;

use device::Device;
use ethernet::SwitchTable;
use ip::RoutingTable;
use types::{Error, Mode, Type, Range, Table, Protocol};
use cloud::GenericCloud;
use udpmessage::VERSION;
use crypto::Crypto;


struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _metadata: &log::LogMetadata) -> bool {
        true
    }

    fn log(&self, record: &log::LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}

static USAGE: &'static str = include_str!("usage.txt");

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_type: Type,
    flag_mode: Mode,
    flag_shared_key: Option<String>,
    flag_subnet: Vec<String>,
    flag_device: String,
    flag_listen: String,
    flag_network_id: Option<String>,
    flag_connect: Vec<String>,
    flag_peer_timeout: usize,
    flag_dst_timeout: usize,
    flag_verbose: bool,
    flag_quiet: bool,
    flag_ifup: Option<String>,
    flag_ifdown: Option<String>,
    flag_version: bool
}

fn run_script(script: String, ifname: &str) {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&script).env("IFNAME", ifname);
    debug!("Running script: {:?}", cmd);
    match cmd.status() {
        Ok(status) => match status.success() {
            true => (),
            false => error!("Script returned with error: {:?}", status.code())
        },
        Err(e) => error!("Failed to execute script {:?}: {}", script, e)
    }
}

fn run<T: Protocol> (args: Args) {
    let device = try_fail!(Device::new(&args.flag_device, args.flag_type),
        "Failed to open virtual {} interface {}: {}", args.flag_type, &args.flag_device);
    info!("Opened device {}", device.ifname());
    let mut ranges = Vec::with_capacity(args.flag_subnet.len());
    for s in args.flag_subnet {
        ranges.push(try_fail!(Range::from_str(&s), "Invalid subnet format: {} ({})", s));
    }
    let dst_timeout = Duration::seconds(args.flag_dst_timeout as i64);
    let peer_timeout = Duration::seconds(args.flag_peer_timeout as i64);
    let (learning, broadcasting, table): (bool, bool, Box<Table>) = match args.flag_mode {
        Mode::Normal => match args.flag_type {
            Type::Tap => (true, true, Box::new(SwitchTable::new(dst_timeout))),
            Type::Tun => (false, false, Box::new(RoutingTable::new()))
        },
        Mode::Router => (false, false, Box::new(RoutingTable::new())),
        Mode::Switch => (true, true, Box::new(SwitchTable::new(dst_timeout))),
        Mode::Hub => (false, true, Box::new(SwitchTable::new(dst_timeout)))
    };
    let network_id = args.flag_network_id.map(|name| {
        let mut s = SipHasher::new();
        name.hash(&mut s);
        s.finish()
    });
    let crypto = match args.flag_shared_key {
        Some(key) => Crypto::from_shared_key(&key),
        None => Crypto::None
    };
    let mut cloud = GenericCloud::<T>::new(device, args.flag_listen, network_id, table, peer_timeout, learning, broadcasting, ranges, crypto);
    if let Some(script) = args.flag_ifup {
        run_script(script, cloud.ifname());
    }
    for addr in &args.flag_connect {
        try_fail!(cloud.connect(&addr as &str, true), "Failed to send message to {}: {}", &addr);
    }
    cloud.run();
    if let Some(script) = args.flag_ifdown {
        run_script(script, cloud.ifname());
    }
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
    if args.flag_version {
        println!("VpnCloud v{} ({}, protocol version {})", env!("CARGO_PKG_VERSION"),
            if cfg!(feature = "crypto") { "with crypto support" } else { "without crypto support" },
            VERSION
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
        Box::new(SimpleLogger)
    }).unwrap();
    debug!("Args: {:?}", args);
    match args.flag_type {
        Type::Tap => run::<ethernet::Frame>(args),
        Type::Tun => run::<ip::Packet>(args),
    }
}
