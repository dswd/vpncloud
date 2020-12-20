use crate::error::Error;
use std::{marker::PhantomData, net::SocketAddr, sync::Arc};

use super::{shared::SharedData, SPACE_BEFORE};
use crate::{
    net::Socket,
    util::{MsgBuffer, Time, TimeSource}
};


const SYNC_INTERVAL: Time = 1;

pub struct SocketThread<S: Socket, T: TimeSource> {
    shared: Arc<SharedData>,
    socket: S,
    next_sync: Time,
    _dummy: PhantomData<T>
}

impl<S: Socket, T: TimeSource> SocketThread<S, T> {
    fn sync(&mut self) {
        // TODO: sync
        unimplemented!();
    }

    fn read_socket_data(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, Error> {
        // TODO: read data
        // use 5sec timeout
        unimplemented!();
    }

    fn handle_message(&mut self, src: SocketAddr, buffer: &mut MsgBuffer) -> Result<(), Error> {
        // TODO: handle data
        unimplemented!();
    }

    pub fn run(mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        loop {
            let addr = try_fail!(self.read_socket_data(&mut buffer), "Failed to read from socket: {}");
            if let Err(e) = self.handle_message(addr, &mut buffer) {
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
