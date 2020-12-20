use std::{marker::PhantomData, sync::Arc};

use super::SPACE_BEFORE;
use super::shared::SharedData;
use crate::{
    device::Device,
    error::Error,
    util::{MsgBuffer, Time, TimeSource}
};


const SYNC_INTERVAL: Time = 1;

pub struct DeviceThread<D: Device, T: TimeSource> {
    shared: Arc<SharedData>,
    device: D,
    next_sync: Time,
    _dummy: PhantomData<T>
}

impl<D: Device, T: TimeSource> DeviceThread<D, T> {
    fn sync(&mut self) {
        // TODO sync
    }

    fn read_device_packet(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // TODO: read data
        // use 5sec timeout
        unimplemented!();
    }

    fn forward_packet(&mut self, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // TODO: handle data
        unimplemented!();
    }

    pub fn run(mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        loop {
            try_fail!(self.read_device_packet(&mut buffer), "Failed to read from device: {}");
            if let Err(e) = self.forward_packet(&mut buffer) {
                error!("{}", e);
            }
            let now = T::now();
            if self.next_sync < now {
                self.sync();
                self.next_sync = now + SYNC_INTERVAL
            }
        }
    }
}
