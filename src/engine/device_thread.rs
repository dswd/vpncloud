use super::{
    shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
    SPACE_BEFORE,
};
use crate::{
    config::Config,
    device::Device,
    error::Error,
    messages::MESSAGE_TYPE_DATA,
    net::Socket,
    util::{MsgBuffer, Time, TimeSource},
    Protocol,
};
use std::{marker::PhantomData, net::SocketAddr};
use tokio::time::timeout;

pub struct DeviceThread<S: Socket, D: Device, P: Protocol, TS: TimeSource> {
    // Read-only fields
    _dummy_ts: PhantomData<TS>,
    _dummy_p: PhantomData<P>,
    broadcast: bool,
    // Device-only fields
    socket: S,
    pub device: D,
    next_housekeep: Time,
    buffer: MsgBuffer,
    broadcast_buffer: MsgBuffer,
    // Shared fields
    traffic: SharedTraffic,
    peer_crypto: SharedPeerCrypto,
    table: SharedTable<TS>,
}

impl<S: Socket, D: Device, P: Protocol, TS: TimeSource> DeviceThread<S, D, P, TS> {
    pub fn new(
        config: Config, device: D, socket: S, traffic: SharedTraffic, peer_crypto: SharedPeerCrypto,
        table: SharedTable<TS>,
    ) -> Self {
        Self {
            _dummy_ts: PhantomData,
            _dummy_p: PhantomData,
            broadcast: config.is_broadcasting(),
            socket,
            device,
            next_housekeep: TS::now(),
            traffic,
            peer_crypto,
            table,
            buffer: MsgBuffer::new(SPACE_BEFORE),
            broadcast_buffer: MsgBuffer::new(SPACE_BEFORE)
        }
    }

    #[inline]
    async fn send_to(&mut self, addr: SocketAddr) -> Result<(), Error> {
        let size = self.buffer.len();
        debug!("Sending msg with {} bytes to {}", size, addr);
        self.traffic.count_out_traffic(addr, size);
        match self.socket.send(self.buffer.message(), addr).await {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e)),
        }
    }

    #[inline]
    async fn send_msg(&mut self, addr: SocketAddr, type_: u8) -> Result<(), Error> {
        debug!("Sending msg with {} bytes to {}", self.buffer.len(), addr);
        self.buffer.prepend_byte(type_);
        self.peer_crypto.encrypt_for(addr, &mut self.buffer)?;
        self.send_to(addr).await
    }

    #[inline]
    async fn broadcast_msg(&mut self, type_: u8) -> Result<(), Error> {
        let size = self.buffer.len();
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, size, self.peer_crypto.count());
        let traffic = &mut self.traffic;
        let socket = &mut self.socket;
        let peers = self.peer_crypto.get_snapshot();
        for (addr, crypto) in peers {
            self.broadcast_buffer.set_start(self.buffer.get_start());
            self.broadcast_buffer.set_length(self.buffer.len());
            self.broadcast_buffer.message_mut().clone_from_slice(self.buffer.message());
            self.broadcast_buffer.prepend_byte(type_);
            if let Some(crypto) = crypto {
                crypto.encrypt(&mut self.broadcast_buffer);
            }
            traffic.count_out_traffic(addr, self.broadcast_buffer.len());
            match socket.send(self.broadcast_buffer.message(), addr).await {
                Ok(written) if written == self.broadcast_buffer.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e)),
            }?
        }
        Ok(())
    }

    async fn forward_packet(&mut self) -> Result<(), Error> {
        let (src, dst) = P::parse(self.buffer.message())?;
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, self.buffer.len());
        self.traffic.count_out_payload(dst, src, self.buffer.len());
        match self.table.lookup(dst) {
            Some(addr) => {
                // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                self.send_msg(addr, MESSAGE_TYPE_DATA).await?;
            }
            None => {
                if self.broadcast {
                    debug!("No destination for {} found, broadcasting", dst);
                    self.broadcast_msg(MESSAGE_TYPE_DATA).await?;
                } else {
                    debug!("No destination for {} found, dropping", dst);
                    self.traffic.count_dropped_payload(self.buffer.len());
                }
            }
        }
        Ok(())
    }

    pub async fn housekeep(&mut self) -> Result<(), Error> {
        self.peer_crypto.sync();
        self.table.sync();
        self.traffic.sync();
        Ok(())
    }

    pub async fn iteration(&mut self) {
        if let Ok(result) = timeout(std::time::Duration::from_millis(1000), self.device.read(&mut self.buffer)).await {
            try_fail!(result, "Failed to read from device: {}");
            if let Err(e) = self.forward_packet().await {
                error!("{}", e);
            }
        }
        let now = TS::now();
        if self.next_housekeep < now {
            if let Err(e) = self.housekeep().await {
                error!("{}", e)
            }
            self.next_housekeep = now + 1
        }
    }

    pub async fn run(mut self) {
        loop {
            self.iteration().await
        }
    }
}
