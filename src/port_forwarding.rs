// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::net::{SocketAddrV4, UdpSocket, SocketAddr};
use std::io;

use igd::*;

use super::util::{SystemTimeSource, Time, TimeSource};

const LEASE_TIME: u32 = 300;
const DESCRIPTION: &str = "VpnCloud";


pub struct PortForwarding {
    pub internal_addr: SocketAddrV4,
    pub external_addr: SocketAddrV4,
    pub gateway: Gateway,
    pub next_extension: Option<Time>,
}

impl PortForwarding {
    pub fn new(port: u16) -> Option<Self> {
        // Get the gateway
        let gateway = match search_gateway() {
            Ok(gateway) => gateway,
            Err(err) => {
                if let SearchError::IoError(ref err) = err {
                    if err.kind() == io::ErrorKind::WouldBlock { // Why this code?
                        warn!("Port-forwarding: no router found");
                        return None
                    }
                }
                error!("Port-forwarding: failed to find router: {}", err);
                return None
            }
        };
        info!("Port-forwarding: found router at {}", gateway.addr);
        // Get the internal address (this trick gets the address by opening a UDP connection which
        // does not really open anything but returns the correct address)
        let dummy_sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");
        dummy_sock.connect(gateway.addr).expect("Failed to connect");
        let internal_addr;
        if let SocketAddr::V4(addr) = dummy_sock.local_addr().expect("Failed to get local address") {
            internal_addr = SocketAddrV4::new(*addr.ip(), port);
        } else {
            unreachable!()
        }
        // Query the external address
        let external_ip = match gateway.get_external_ip() {
            Ok(ip) => ip,
            Err(err) => {
                error!("Port-forwarding: failed to obtain external IP: {}", err);
                return None
            }
        };
        // Try to activate the port forwarding
        // - First with external port = internal port and timeout
        // - If the port is used, request any port
        // - If timeout is denied, try permanent forwarding
        info!("Port-forwarding: external IP is {}", external_ip);
        let (external_addr, timeout) = match gateway.add_port(PortMappingProtocol::UDP, internal_addr.port(), internal_addr, LEASE_TIME, DESCRIPTION) {
            Ok(()) => (SocketAddrV4::new(external_ip, internal_addr.port()), LEASE_TIME),
            Err(AddPortError::PortInUse) => match gateway.add_any_port(PortMappingProtocol::UDP, internal_addr, LEASE_TIME, DESCRIPTION) {
                Ok(port) => (SocketAddrV4::new(external_ip, port), LEASE_TIME),
                Err(AddAnyPortError::OnlyPermanentLeasesSupported) => match gateway.add_any_port(PortMappingProtocol::UDP, internal_addr, 0, DESCRIPTION) {
                    Ok(port) => (SocketAddrV4::new(external_ip, port), 0),
                    Err(err) => {
                        error!("Port-forwarding: failed to activate port forwarding: {}", err);
                        return None
                    }
                },
                Err(err) => {
                    error!("Port-forwarding: failed to activate port forwarding: {}", err);
                    return None
                }
            },
            Err(AddPortError::OnlyPermanentLeasesSupported) => match gateway.add_port(PortMappingProtocol::UDP, internal_addr.port(), internal_addr, 0, DESCRIPTION) {
                Ok(()) => (SocketAddrV4::new(external_ip, internal_addr.port()), 0),
                Err(err) => {
                    error!("Port-forwarding: failed to activate port forwarding: {}", err);
                    return None
                }
            },
            Err(err) => {
                error!("Port-forwarding: failed to activate port forwarding: {}", err);
                return None
            }
        };
        info!("Port-forwarding: sucessfully activated port forward on {}, timeout: {}", external_addr, timeout);
        let next_extension = if timeout > 0 {
            Some(SystemTimeSource::now() + Time::from(timeout) - 60)
        } else {
            None
        };
        Some(PortForwarding {
            internal_addr,
            external_addr,
            gateway,
            next_extension
        })
    }

    pub fn check_extend(&mut self) {
        if let Some(deadline) = self.next_extension {
            if deadline > SystemTimeSource::now() {
                return
            }
        } else {
            return
        }
        match self.gateway.add_port(PortMappingProtocol::UDP, self.external_addr.port(), self.internal_addr, LEASE_TIME, DESCRIPTION) {
            Ok(()) => debug!("Port-forwarding: extended port forwarding"),
            Err(err) => error!("Port-forwarding: failed to extend port forwarding: {}", err)
        };
        self.next_extension = Some(SystemTimeSource::now() + Time::from(LEASE_TIME) - 60);
    }

    fn deactivate(&self) {
        match self.gateway.remove_port(PortMappingProtocol::UDP, self.external_addr.port()) {
            Ok(()) => info!("Port-forwarding: successfully deactivated port forwarding"),
            Err(err) => error!("Port-forwarding: failed to deactivate port forwarding: {}", err)
        }
    }
}

impl Drop for PortForwarding {
    fn drop(&mut self) {
        self.deactivate()
    }
}
