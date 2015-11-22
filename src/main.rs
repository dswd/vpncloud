#[macro_use] extern crate log;
extern crate time;
extern crate docopt;
extern crate rustc_serialize;
extern crate epoll;

mod util;
mod udpmessage;
mod ethernet;
mod ip;
mod cloud;
mod device;

use time::Duration;
use docopt::Docopt;

use std::hash::{Hash, SipHasher, Hasher};

use cloud::{Error, TapCloud, TunCloud, Behavior};


//TODO: hub behavior
//TODO: L2 routing/L3 switching
//TODO: Implement IPv6
//TODO: Encryption
//TODO: Call close


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

static USAGE: &'static str = "
Usage:
    ethcloud [options] [-t <type>] [-d <device>] [-l <listen>] [-c <connect>...]

Options:
    -t <type>, --type <type>               Set the type of network [default: tap]
    --behavior <behavior>                  The behavior of the vpn [default: normal]
    -d <device>, --device <device>         Name of the virtual device [default: cloud%d]
    -l <listen>, --listen <listen>         Address to listen on [default: 0.0.0.0:3210]
    -c <connect>, --connect <connect>      List of peers (addr:port) to connect to
    --network-id <network_id>              Optional token that identifies the network
    --peer-timeout <peer_timeout>          Peer timeout in seconds [default: 1800]
    --subnet <subnet>...                   The local subnets to use (only for tun)
    --mac-timeout <mac_timeout>            Mac table entry timeout in seconds (only for tap) [default: 300]
    -v, --verbose                          Log verbosely
    -q, --quiet                            Only print error messages
    -h, --help                             Display the help
";

#[derive(RustcDecodable, Debug)]
enum Type {
    Tun, Tap
}

#[derive(RustcDecodable, Debug)]
struct Args {
    flag_type: Type,
    flag_behavior: Behavior,
    flag_subnet: Vec<String>,
    flag_device: String,
    flag_listen: String,
    flag_network_id: Option<String>,
    flag_connect: Vec<String>,
    flag_peer_timeout: usize,
    flag_mac_timeout: usize,
    flag_verbose: bool,
    flag_quiet: bool
}

fn tap_cloud(args: Args) {
    let mut tapcloud = TapCloud::new_tap_cloud(
        &args.flag_device,
        args.flag_listen,
        args.flag_behavior,
        args.flag_network_id.map(|name| {
            let mut s = SipHasher::new();
            name.hash(&mut s);
            s.finish()
        }),
        Duration::seconds(args.flag_mac_timeout as i64),
        Duration::seconds(args.flag_peer_timeout as i64)
    );
    for addr in args.flag_connect {
        tapcloud.connect(&addr as &str, true).expect("Failed to send");
    }
    tapcloud.run()
}

fn tun_cloud(args: Args) {
    let mut tuncloud = TunCloud::new_tun_cloud(
        &args.flag_device,
        args.flag_listen,
        args.flag_behavior,
        args.flag_network_id.map(|name| {
            let mut s = SipHasher::new();
            name.hash(&mut s);
            s.finish()
        }),
        args.flag_subnet,
        Duration::seconds(args.flag_peer_timeout as i64)
    );
    for addr in args.flag_connect {
        tuncloud.connect(&addr as &str, true).expect("Failed to send");
    }
    tuncloud.run()
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
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
        Type::Tap => tap_cloud(args),
        Type::Tun => tun_cloud(args)
    }
}
