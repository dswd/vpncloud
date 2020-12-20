use std::{marker::PhantomData, sync::Arc};

use super::shared::SharedData;
use crate::{
    device::Device,
    util::{Time, TimeSource}
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

    pub fn run(mut self) {
        loop {
            let now = T::now();
            if self.next_sync < now {
                self.sync();
                self.next_sync = now + SYNC_INTERVAL
            }
        }
    }
}
