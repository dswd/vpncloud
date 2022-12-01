use super::{common::SPACE_BEFORE, coms::Coms};
use crate::{
    device::Device,
    error::Error,
    net::Socket,
    util::{MsgBuffer, Time, TimeSource},
    Protocol,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct DeviceThread<S: Socket, D: Device, P: Protocol, TS: TimeSource> {
    // Device-only fields
    coms: Coms<S, TS, P>,
    pub device: D,
    next_housekeep: Time,
    buffer: MsgBuffer,
    // Shared fields
    running: Arc<AtomicBool>,
}

impl<S: Socket, D: Device, P: Protocol, TS: TimeSource> DeviceThread<S, D, P, TS> {
    pub fn new(device: D, coms: Coms<S, TS, P>, running: Arc<AtomicBool>) -> Self {
        Self {
            device,
            next_housekeep: TS::now(),
            buffer: MsgBuffer::new(SPACE_BEFORE),
            running,
            coms,
        }
    }

    pub fn housekeep(&mut self) -> Result<(), Error> {
        self.coms.sync()
    }

    pub fn iteration(&mut self) -> bool {
        if self.device.read(&mut self.buffer).is_ok() {
            //try_fail!(result, "Failed to read from device: {}");
            if let Err(e) = self.coms.forward_packet(&mut self.buffer) {
                error!("{}", e);
            }
        }
        let now = TS::now();
        if self.next_housekeep < now {
            if let Err(e) = self.housekeep() {
                error!("{}", e)
            }
            self.next_housekeep = now + 1;
            if !self.running.load(Ordering::SeqCst) {
                debug!("Device: end");
                return false;
            }
        }
        true
    }

    pub fn run(mut self) {
        while self.iteration() {}
    }
}
