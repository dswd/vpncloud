use std::{time::Duration, net::SocketAddr, cmp::{min, max}};

use smallvec::SmallVec;

use super::{common::SPACE_BEFORE, coms::Coms, shared::SharedConfig};
use crate::{
    error::Error,
    net::Socket,
    util::{MsgBuffer, TimeSource, Time, addr_nice},
    Protocol, messages::MESSAGE_TYPE_NODE_INFO, config::DEFAULT_PEER_TIMEOUT,
};

const MAX_RECONNECT_INTERVAL: u16 = 3600;
const RESOLVE_INTERVAL: Time = 300;
const OWN_ADDRESS_RESET_INTERVAL: Time = 300;
pub const STATS_INTERVAL: Time = 60;

pub struct HousekeepThread<S: Socket, P: Protocol, TS: TimeSource> {
    config: SharedConfig,
    coms: Coms<S, TS, P>,
    next_housekeep: Time,
    buffer: MsgBuffer,
    update_freq: u16,
    next_peers: Time,
    next_own_address_reset: Time,
}

impl<S: Socket, P: Protocol, TS: TimeSource> HousekeepThread<S, P, TS> {
    pub fn new(config: SharedConfig, coms: Coms<S, TS, P>) -> Self {
        let update_freq = config.get_config().get_keepalive() as u16;
        Self {
            config,
            coms,
            next_housekeep: TS::now(),
            buffer: MsgBuffer::new(SPACE_BEFORE),
            update_freq,
            next_peers: TS::now(),
            next_own_address_reset: TS::now(),
        }
    }

    pub fn housekeep(&mut self) -> Result<(), Error> {
        let now = TS::now();
        assert!(self.buffer.is_empty());
        Ok(())
    }

    pub fn iteration(&mut self) -> bool {
        std::thread::sleep(Duration::from_millis(100));
        let now = TS::now();
        if self.next_housekeep < now {
            if let Err(e) = self.housekeep() {
                error!("{}", e)
            }
            self.next_housekeep = now + 1;
            if !self.config.is_running() {
                debug!("Housekeep: end");
                return false;
            }
        }
        true
    }

    pub fn run(mut self) {
        while self.iteration() {}
    }
}
