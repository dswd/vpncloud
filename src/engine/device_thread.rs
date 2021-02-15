use super::{
    shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
    SPACE_BEFORE
};
use crate::{
    device::Device,
    error::Error,
    messages::MESSAGE_TYPE_DATA,
    net::Socket,
    util::{MsgBuffer, Time, TimeSource},
    Protocol
};
use std::{marker::PhantomData, net::SocketAddr};

pub struct DeviceThread<S: Socket, D: Device, P: Protocol, TS: TimeSource> {
    // Read-only fields
    _dummy_ts: PhantomData<TS>,
    _dummy_p: PhantomData<P>,
    broadcast: bool,
    // Device-only fields
    socket: S,
    device: D,
    next_housekeep: Time,
    // Shared fields
    traffic: SharedTraffic,
    peer_crypto: SharedPeerCrypto,
    table: SharedTable<TS>
}

impl<S: Socket, D: Device, P: Protocol, TS: TimeSource> DeviceThread<S, D, P, TS> {
    #[inline]
    fn send_to(&mut self, addr: SocketAddr, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        self.traffic.count_out_traffic(addr, msg.len());
        match self.socket.send(msg.message(), addr) {
            Ok(written) if written == msg.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e))
        }
    }

    #[inline]
    fn send_msg(&mut self, addr: SocketAddr, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Sending msg with {} bytes to {}", msg.len(), addr);
        msg.prepend_byte(type_);
        self.peer_crypto.encrypt_for(addr, msg)?;
        self.send_to(addr, msg)
    }

    #[inline]
    fn broadcast_msg(&mut self, type_: u8, msg: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, msg.len(), self.peer_crypto.count());
        let mut msg_data = MsgBuffer::new(100);
        let traffic = &mut self.traffic;
        let socket = &mut self.socket;
        self.peer_crypto.for_each(|addr, crypto| {
            msg_data.set_start(msg.get_start());
            msg_data.set_length(msg.len());
            msg_data.message_mut().clone_from_slice(msg.message());
            msg_data.prepend_byte(type_);
            if let Some(crypto) = crypto {
                crypto.encrypt(&mut msg_data);
            }
            traffic.count_out_traffic(addr, msg_data.len());
            match socket.send(msg_data.message(), addr) {
                Ok(written) if written == msg_data.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e))
            }
        })
    }

    fn forward_packet(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        let (src, dst) = P::parse(data.message())?;
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, data.len());
        self.traffic.count_out_payload(dst, src, data.len());
        match self.table.lookup(dst) {
            Some(addr) => {
                // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                self.send_msg(addr, MESSAGE_TYPE_DATA, data)?;
            }
            None => {
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    self.broadcast_msg(MESSAGE_TYPE_DATA, data)?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                    self.traffic.count_dropped_payload(data.len());
                }
            }
        }
        Ok(())
    }

    fn housekeep(&mut self) -> Result<(), Error> {
        self.peer_crypto.sync();
        self.table.sync();
        self.traffic.sync();
        unimplemented!();
    }

    pub fn run(mut self) {
        let mut buffer = MsgBuffer::new(SPACE_BEFORE);
        loop {
            try_fail!(self.device.read(&mut buffer), "Failed to read from device: {}");
            if let Err(e) = self.forward_packet(&mut buffer) {
                error!("{}", e);
            }
            let now = TS::now();
            if self.next_housekeep < TS::now() {
                if let Err(e) = self.housekeep() {
                    error!("{}", e)
                }
                self.next_housekeep = TS::now() + 1
            }
        }
    }
}
