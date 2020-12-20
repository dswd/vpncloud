use std::marker::PhantomData;
use std::sync::Arc;

use super::shared::SharedData;
use crate::net::Socket;
use crate::util::{Time, TimeSource};


const SYNC_INTERVAL: Time = 1;

pub struct SocketThread<S: Socket, T: TimeSource> {
    shared: Arc<SharedData>,
    socket: S,
    next_sync: Time,
    _dummy: PhantomData<T>
}

impl<S: Socket, T: TimeSource> SocketThread<S, T> {
    fn sync(&mut self) {
        //TODO sync
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