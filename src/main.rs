#![feature(libc)]

#[macro_use] extern crate log;
extern crate time;
extern crate libc;
extern crate docopt;
extern crate rustc_serialize;

mod udpmessage;
mod tapdev;
mod ethernet;
mod ethcloud;

use time::Duration;
use docopt::Docopt;

pub use ethcloud::{Error, Mac, Token, EthCloud};
pub use ethernet::{encode as eth_encode, decode as eth_decode, Frame as EthernetFrame};
pub use tapdev::TapDevice;
pub use udpmessage::{encode as udp_encode, decode as udp_decode, Message as UdpMessage};



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
  ethcloud [options]

Options:
  -d <device>, --device <device>         Name of the tap device [default: ethcloud%d]
  -l <listen>, --listen <listen>         Address to listen on [default: 0.0.0.0:3210]
  -t <token>, --token <token>            Token that identifies the network [default: 0]
  -c <connect>, --connect <connect>      List of peers (addr:port) to connect to
  --peer-timeout <peer_timeout>          Peer timeout in seconds [default: 300]
  --mac-timeout <mac_timeout>            Mac table entry timeout in seconds [default: 60]
  -v, --verbose                          Log verbosely
";

#[derive(RustcDecodable, Debug)]
struct Args {
  flag_device: String,
  flag_listen: String,
  flag_token: Token,
  flag_connect: Vec<String>,
  flag_peer_timeout: usize,
  flag_mac_timeout: usize,
  flag_verbose: bool
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());
    log::set_logger(|max_log_level| {
        if args.flag_verbose {
            max_log_level.set(log::LogLevelFilter::Debug);
        } else {
            max_log_level.set(log::LogLevelFilter::Info);
        }
        Box::new(SimpleLogger)
    }).unwrap();
    debug!("Args: {:?}", args);
    let mut tapcloud = EthCloud::new(
        &args.flag_device,
        args.flag_listen,
        args.flag_token,
        Duration::seconds(args.flag_mac_timeout as i64),
        Duration::seconds(args.flag_peer_timeout as i64)
    );
    for addr in args.flag_connect {
        tapcloud.connect(&addr as &str).expect("Failed to send");
    }
    tapcloud.run();
}
