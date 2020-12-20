use super::{
    net::{mapped_addr, Socket},
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    util::MsgBuffer
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{self, Cursor, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    os::unix::io::{AsRawFd, RawFd},
    thread::spawn
};
use tungstenite::{client::AutoStream, connect, protocol::WebSocket, server::accept, stream::Stream, Message};
use url::Url;


macro_rules! io_error {
    ($val:expr, $format:expr) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, err)))
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, $( $arg ),+, err)))
    } );
}

fn write_addr<W: Write>(addr: SocketAddr, mut out: W) -> Result<(), io::Error> {
    let addr = mapped_addr(addr);
    match mapped_addr(addr) {
        SocketAddr::V6(addr) => {
            out.write_all(&addr.ip().octets())?;
            out.write_u16::<NetworkEndian>(addr.port())?;
        }
        _ => unreachable!()
    }
    Ok(())
}

fn read_addr<R: Read>(mut r: R) -> Result<SocketAddr, io::Error> {
    let mut ip = [0u8; 16];
    r.read_exact(&mut ip)?;
    let port = r.read_u16::<NetworkEndian>()?;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
    Ok(addr)
}

fn serve_proxy_connection(stream: TcpStream) -> Result<(), io::Error> {
    let peer = stream.peer_addr()?;
    info!("WS client {} connected", peer);
    let mut websocket = io_error!(accept(stream), "Failed to initialize websocket with {}: {}", peer)?;
    let udpsocket = UdpSocket::bind("[::]:0")?;
    let mut msg = Vec::with_capacity(18);
    let addr = udpsocket.local_addr()?;
    info!("Listening on {} for peer {}", addr, peer);
    write_addr(addr, &mut msg)?;
    io_error!(websocket.write_message(Message::Binary(msg)), "Failed to write to ws connection: {}")?;
    let websocketfd = websocket.get_ref().as_raw_fd();
    let poll = WaitImpl::new(websocketfd, udpsocket.as_raw_fd(), 60)?;
    let mut buffer = [0; 65535];
    for evt in poll {
        match evt {
            WaitResult::Socket => {
                info!("WS -> UDP");
                let msg = io_error!(websocket.read_message(), "Failed to read message on websocket {}: {}", peer)?;
                info!("MSG: {}", msg);
                match msg {
                    Message::Binary(data) => {
                        let dst = read_addr(Cursor::new(&data))?;
                        udpsocket.send_to(&data[18..], dst)?;
                    }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            WaitResult::Device => {
                info!("UDP -> WS");
                let (size, addr) = udpsocket.recv_from(&mut buffer)?;
                let mut data = Vec::with_capacity(18 + size);
                write_addr(addr, &mut data)?;
                data.write_all(&buffer[..size])?;
                io_error!(websocket.write_message(Message::Binary(data)), "Failed to write to {}: {}", peer)?;
            }
            WaitResult::Timeout => {
                info!("Sending ping");
                io_error!(websocket.write_message(Message::Ping(vec![])), "Failed to send ping: {}")?;
            }
            WaitResult::Error(err) => return Err(err)
        }
    }
    Ok(())
}

pub fn run_proxy() -> Result<(), io::Error> {
    // TODO: configurable listen
    let server = TcpListener::bind("127.0.0.1:9001")?;
    for stream in server.incoming() {
        let stream = stream?;
        let peer = stream.peer_addr()?;
        spawn(move || {
            if let Err(err) = serve_proxy_connection(stream) {
                error!("Error on connection {}: {}", peer, err);
            }
        });
    }
    Ok(())
}

pub struct ProxyConnection {
    addr: SocketAddr,
    socket: WebSocket<AutoStream>
}

impl ProxyConnection {
    fn read_message(&mut self) -> Result<Vec<u8>, io::Error> {
        loop {
            if let Message::Binary(data) = io_error!(self.socket.read_message(), "Failed to read from ws proxy: {}")? {
                return Ok(data)
            }
        }
    }
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
        let parsed_url = io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let (socket, _) = io_error!(connect(parsed_url), "Failed to connect to URL {}: {}", url)?;
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection { addr, socket };
        let addr_data = con.read_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let data = self.read_message()?;
        let addr = read_addr(Cursor::new(&data))?;
        buffer.clone_from(&data[18..]);
        Ok(addr)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let mut msg = Vec::with_capacity(data.len() + 18);
        write_addr(addr, &mut msg)?;
        msg.write_all(data)?;
        io_error!(self.socket.write_message(Message::Binary(msg)), "Failed to write to ws proxy: {}")?;
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
