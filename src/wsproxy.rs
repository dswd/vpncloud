use super::{
    net::{mapped_addr, Socket},
    port_forwarding::PortForwarding,
    util::MsgBuffer
};
use std::{
    io::{self, Write, Read, Cursor},
    net::{SocketAddr, TcpListener, SocketAddrV6, Ipv6Addr},
    os::unix::io::{AsRawFd, RawFd},
    thread::spawn,
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use tungstenite::{client::AutoStream, connect, protocol::WebSocket, server::accept, stream::Stream, Message};
use url::Url;

pub fn run_proxy() {
    let server = TcpListener::bind("127.0.0.1:9001").unwrap();
    for stream in server.incoming() {
        info!("connect");
        spawn(move || {
            let mut websocket = accept(stream.unwrap()).unwrap();
            loop {
                let msg = websocket.read_message().unwrap();
                // We do not want to send back ping/pong messages.
                if msg.is_binary() || msg.is_text() {
                    info!("msg");
                    websocket.write_message(msg).unwrap();
                }
            }
        });
    }
}

pub struct ProxyConnection {
    url: String,
    addr: SocketAddr,
    socket: WebSocket<AutoStream>
}

impl AsRawFd for ProxyConnection {
    fn as_raw_fd(&self) -> RawFd {
        match self.socket.get_ref() {
            Stream::Plain(sock) => sock.as_raw_fd(),
            Stream::Tls(sock) => sock.get_ref().as_raw_fd()
        }
    }
}

impl Socket for ProxyConnection {
    fn listen(url: &str) -> Result<Self, io::Error> {
        let (mut socket, _) = connect(Url::parse(url).unwrap()).unwrap();
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        Ok(ProxyConnection { url: addr.to_string(), addr, socket })
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        match self.socket.read_message().unwrap() {
            Message::Binary(data) => {
                let mut cursor = Cursor::new(&data);
                let mut ip = [0u8; 16];
                cursor.read_exact(&mut ip)?;
                let port = cursor.read_u16::<NetworkEndian>()?;
                let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
                buffer.clone_from(&data[18..]);
                Ok(addr)
            },
            _ => unimplemented!()
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let mut msg = Vec::with_capacity(data.len() + 18);
        let addr = mapped_addr(addr);
        match mapped_addr(addr) {
            SocketAddr::V6(addr) => {
                msg.write_all(&addr.ip().octets())?;
                msg.write_u16::<NetworkEndian>(addr.port())?;
            },
            _ => unreachable!()
        }
        msg.write_all(data)?;
        self.socket.write_message(Message::Binary(msg)).unwrap();
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }
}

pub fn run_client(url: String) {
    let (mut socket, _) = connect(Url::parse(&url).unwrap()).unwrap();
    socket.write_message(Message::Text("test".to_string())).unwrap();
    let msg = socket.read_message().unwrap();
    info!("msg: {}", msg);
    socket.close(None).unwrap();
}
