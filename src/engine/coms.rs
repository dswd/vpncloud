use std::{net::SocketAddr, marker::PhantomData, io};

use crate::{
    config::Config,
    error::Error,
    messages::MESSAGE_TYPE_DATA,
    net::{Socket, mapped_addr},
    util::{MsgBuffer, TimeSource}, payload::Protocol,
};

use super::{
    common::{SPACE_BEFORE, PeerData},
    shared::{SharedPeerCrypto, SharedTable, SharedTraffic},
};

pub struct Coms<S: Socket, TS: TimeSource, P: Protocol> {
    _dummy_p: PhantomData<P>,
    broadcast: bool,
    broadcast_buffer: MsgBuffer,
    peer_crypto: SharedPeerCrypto,
    pub table: SharedTable<TS>,
    pub traffic: SharedTraffic,
    pub socket: S,
}

impl<S: Socket, TS: TimeSource, P: Protocol> Coms<S, TS, P> {
    pub fn new(config: &Config, socket: S) -> Self {
        Self {
            _dummy_p: PhantomData,
            broadcast: config.is_broadcasting(),
            broadcast_buffer: MsgBuffer::new(SPACE_BEFORE),
            traffic: SharedTraffic::new(),
            peer_crypto: SharedPeerCrypto::new(),
            table: SharedTable::<TS>::new(config),
            socket,
        }
    }

    pub fn try_clone(&self) -> Result<Self, Error> {
        Ok(Self {
            _dummy_p: PhantomData,
            broadcast: self.broadcast,
            broadcast_buffer: MsgBuffer::new(SPACE_BEFORE),
            traffic: self.traffic.clone(),
            peer_crypto: self.peer_crypto.clone(),
            table: self.table.clone(),
            socket: self.socket.try_clone().map_err(|e| Error::SocketIo("Failed to clone socket", e))?,
        })
    }

    pub fn sync(&mut self) -> Result<(), Error> {
        self.peer_crypto.load();
        self.table.sync();
        self.traffic.sync();
        Ok(())
    }

    pub fn get_address(&self) -> Result<SocketAddr, io::Error> {
        self.socket.address().map(mapped_addr)
    }

    pub fn send_raw(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), Error> {
        match self.socket.send(data, addr) {
            Ok(written) if written == data.len() => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e)),
        }
    }

    pub fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        self.socket.receive(buffer)
    }

    #[inline]
    pub fn send_to(&mut self, addr: SocketAddr, data: &mut MsgBuffer) -> Result<(), Error> {
        let size = data.len();
        debug!("Sending msg with {} bytes to {}", size, addr);
        self.traffic.count_out_traffic(addr, size);
        match self.socket.send(data.message(), addr) {
            Ok(written) if written == size => Ok(()),
            Ok(_) => Err(Error::Socket("Sent out truncated packet")),
            Err(e) => Err(Error::SocketIo("IOError when sending", e)),
        }
    }

    #[inline]
    pub fn send_msg(&mut self, addr: SocketAddr, type_: u8, data: &mut MsgBuffer) -> Result<(), Error> {
        debug!("Sending msg with {} bytes to {}", data.len(), addr);
        data.prepend_byte(type_);
        self.peer_crypto.encrypt_for(addr, data)?;
        self.send_to(addr, data)
    }

    #[inline]
    pub fn broadcast_msg(&mut self, type_: u8, data: &mut MsgBuffer) -> Result<(), Error> {
        let size = data.len();
        debug!("Broadcasting message type {}, {:?} bytes to {} peers", type_, size, self.peer_crypto.count());
        let traffic = &mut self.traffic;
        let socket = &mut self.socket;
        let peers = self.peer_crypto.get_snapshot();
        for (addr, crypto) in peers {
            self.broadcast_buffer.set_start(data.get_start());
            self.broadcast_buffer.set_length(data.len());
            self.broadcast_buffer.message_mut().clone_from_slice(data.message());
            self.broadcast_buffer.prepend_byte(type_);
            if let Some(crypto) = crypto {
                crypto.encrypt(&mut self.broadcast_buffer);
            }
            traffic.count_out_traffic(*addr, self.broadcast_buffer.len());
            match socket.send(self.broadcast_buffer.message(), *addr) {
                Ok(written) if written == self.broadcast_buffer.len() => Ok(()),
                Ok(_) => Err(Error::Socket("Sent out truncated packet")),
                Err(e) => Err(Error::SocketIo("IOError when sending", e)),
            }?
        }
        Ok(())
    }

    pub fn forward_packet(&mut self, data: &mut MsgBuffer) -> Result<(), Error> {
        let (src, dst) = P::parse(data.message())?;
        debug!("Read data from interface: src: {}, dst: {}, {} bytes", src, dst, data.len());
        self.traffic.count_out_payload(dst.clone(), src, data.len());
        match self.table.lookup(&dst) {
            Some(addr) => {
                // Peer found for destination
                debug!("Found destination for {} => {}", dst, addr);
                self.send_msg(addr, MESSAGE_TYPE_DATA, data)?;
            }
            //TODO: VIA: find relay peer and relay message
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

    pub fn add_peer(&mut self, addr: SocketAddr, peer: &PeerData) {
        self.peer_crypto.add(addr, peer.crypto.get_core());
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.table.remove_claims(*addr);
        self.peer_crypto.remove(addr);
    }

}
