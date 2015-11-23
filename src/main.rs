#[macro_use] extern crate log;
extern crate time;
extern crate docopt;
extern crate rustc_serialize;
extern crate epoll;

mod util;
mod types;
mod udpmessage;
mod ethernet;
mod ip;
mod cloud;
mod device;

use time::Duration;
use docopt::Docopt;

use std::hash::{Hash, SipHasher, Hasher};
use std::str::FromStr;

use device::Device;
use ethernet::SwitchTable;
use ip::RoutingTable;
use types::{Error, Behavior, Type, Range, Table};
use cloud::{TapCloud, TunCloud};


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
    --subnet <subnet>...                   The local subnets to use
    --dst-timeout <dst_timeout>            Switch table entry timeout in seconds [default: 300]
    -v, --verbose                          Log verbosely
    -q, --quiet                            Only print error messages
    -h, --help                             Display the help
";

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
    flag_dst_timeout: usize,
    flag_verbose: bool,
    flag_quiet: bool
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
    let device = Device::new(&args.flag_device, args.flag_type).expect("Failed to open virtual interface");
    info!("Opened device {}", device.ifname());
    let mut ranges = Vec::with_capacity(args.flag_subnet.len());
    for s in args.flag_subnet {
        ranges.push(Range::from_str(&s).expect("Invalid subnet"));
    }
    let dst_timeout = Duration::seconds(args.flag_dst_timeout as i64);
    let peer_timeout = Duration::seconds(args.flag_peer_timeout as i64);
    let (learning, broadcasting, table): (bool, bool, Box<Table>) = match args.flag_behavior {
        Behavior::Normal => match args.flag_type {
            Type::Tap => (true, true, Box::new(SwitchTable::new(dst_timeout))),
            Type::Tun => (false, false, Box::new(RoutingTable::new()))
        },
        Behavior::Router => (false, false, Box::new(RoutingTable::new())),
        Behavior::Switch => (true, true, Box::new(SwitchTable::new(dst_timeout))),
        Behavior::Hub => (false, true, Box::new(SwitchTable::new(dst_timeout)))
    };
    let network_id = args.flag_network_id.map(|name| {
        let mut s = SipHasher::new();
        name.hash(&mut s);
        s.finish()
    });
    match args.flag_type {
        Type::Tap => {
            let mut cloud = TapCloud::new(device, args.flag_listen, network_id, table, peer_timeout, learning, broadcasting, ranges);
            for addr in args.flag_connect {
                cloud.connect(&addr as &str, true).expect("Failed to send");
            }
            cloud.run()
        },
        Type::Tun => {
            let mut cloud = TunCloud::new(device, args.flag_listen, network_id, table, peer_timeout, learning, broadcasting, ranges);
            for addr in args.flag_connect {
                cloud.connect(&addr as &str, true).expect("Failed to send");
            }
            cloud.run()
        }
    };
}
