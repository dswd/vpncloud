// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#[cfg(feature = "nat")]
mod internal {

    use std::{io, net::SocketAddrV4};

    use igd::{search_gateway, AddAnyPortError, AddPortError, Gateway, PortMappingProtocol, SearchError};

    use crate::util::{get_internal_ip, SystemTimeSource, Time, TimeSource};

    const LEASE_TIME: u32 = 1800;

    const DESCRIPTION: &str = "VpnCloud";

    pub struct PortForwarding {
        pub internal_addr: SocketAddrV4,
        pub external_addr: SocketAddrV4,
        gateway: Gateway,
        pub next_extension: Option<Time>,
    }

    impl PortForwarding {
        pub fn new(port: u16) -> Option<Self> {
            // Get the gateway
            let gateway = match search_gateway(Default::default()) {
                Ok(gateway) => gateway,
                Err(err) => {
                    if let SearchError::IoError(ref err) = err {
                        if err.kind() == io::ErrorKind::WouldBlock {
                            // Why this code?
                            info!("Port-forwarding: no router found");
                            return None;
                        }
                    }
                    error!("Port-forwarding: failed to find router: {}", err);
                    return None;
                }
            };
            debug!("Port-forwarding: found router at {}", gateway.addr);
            let internal_addr = SocketAddrV4::new(get_internal_ip(), port);
            // Query the external address
            let external_ip = match gateway.get_external_ip() {
                Ok(ip) => ip,
                Err(err) => {
                    error!("Port-forwarding: failed to obtain external IP: {}", err);
                    return None;
                }
            };
            if let Ok((port, timeout)) = Self::get_any_forwarding(&gateway, internal_addr, port) {
                debug!("Port-forwarding: external IP is {}", external_ip);
                let external_addr = SocketAddrV4::new(external_ip, port);
                debug!("Port-forwarding has timeout {}", timeout);
                info!("Port-forwarding: successfully activated port forward on {}", external_addr);
                let next_extension =
                    if timeout > 0 { Some(SystemTimeSource::now() + Time::from(timeout) - 60) } else { None };
                Some(PortForwarding { internal_addr, external_addr, gateway, next_extension })
            } else {
                None
            }
        }

        fn get_any_forwarding(gateway: &Gateway, addr: SocketAddrV4, port: u16) -> Result<(u16, u32), ()> {
            if let Ok(a) = Self::get_forwarding(gateway, addr, port) {
                return Ok(a);
            }
            if let Ok(a) = Self::get_forwarding(gateway, addr, 0) {
                return Ok(a);
            }
            for i in 1..5 {
                if let Ok(a) = Self::get_forwarding(gateway, addr, port + i) {
                    return Ok(a);
                }
            }
            for _ in 0..5 {
                if let Ok(a) = Self::get_forwarding(gateway, addr, rand::random()) {
                    return Ok(a);
                }
            }
            warn!("Failed to activate port forwarding");
            Err(())
        }

        fn get_forwarding(gateway: &Gateway, addr: SocketAddrV4, port: u16) -> Result<(u16, u32), ()> {
            debug!("Trying external port {}", port);
            if port == 0 {
                match gateway.add_any_port(PortMappingProtocol::UDP, addr, LEASE_TIME, DESCRIPTION) {
                    Ok(port) => Ok((port, LEASE_TIME)),
                    Err(AddAnyPortError::OnlyPermanentLeasesSupported) => {
                        match gateway.add_any_port(PortMappingProtocol::UDP, addr, 0, DESCRIPTION) {
                            Ok(port) => Ok((port, 0)),
                            Err(err) => {
                                debug!("Port-forwarding: failed to activate port forwarding: {}", err);
                                Err(())
                            }
                        }
                    }
                    Err(err) => {
                        debug!("Port-forwarding: failed to activate port forwarding: {}", err);
                        Err(())
                    }
                }
            } else {
                match gateway.add_port(PortMappingProtocol::UDP, port, addr, LEASE_TIME, DESCRIPTION) {
                    Ok(()) => Ok((port, LEASE_TIME)),
                    Err(AddPortError::OnlyPermanentLeasesSupported) => {
                        match gateway.add_port(PortMappingProtocol::UDP, port, addr, 0, DESCRIPTION) {
                            Ok(()) => Ok((port, 0)),
                            Err(err) => {
                                debug!("Port-forwarding: failed to activate port forwarding: {}", err);
                                Err(())
                            }
                        }
                    }
                    Err(err) => {
                        debug!("Port-forwarding: failed to activate port forwarding: {}", err);
                        Err(())
                    }
                }
            }
        }

        pub fn check_extend(&mut self) {
            if let Some(deadline) = self.next_extension {
                if deadline > SystemTimeSource::now() {
                    return;
                }
            } else {
                return;
            }
            match self.gateway.add_port(
                PortMappingProtocol::UDP,
                self.external_addr.port(),
                self.internal_addr,
                LEASE_TIME,
                DESCRIPTION,
            ) {
                Ok(()) => debug!("Port-forwarding: extended port forwarding"),
                Err(err) => debug!("Port-forwarding: failed to extend port forwarding: {}", err),
            };
            self.next_extension = Some(SystemTimeSource::now() + Time::from(LEASE_TIME) - 60);
        }

        fn deactivate(&self) {
            match self.gateway.remove_port(PortMappingProtocol::UDP, self.external_addr.port()) {
                Ok(()) => info!("Port-forwarding: successfully deactivated port forwarding"),
                Err(err) => debug!("Port-forwarding: failed to deactivate port forwarding: {}", err),
            }
        }

        pub fn get_internal_ip(&self) -> SocketAddrV4 {
            self.internal_addr
        }

        pub fn get_external_ip(&self) -> SocketAddrV4 {
            self.external_addr
        }
    }

    impl Drop for PortForwarding {
        fn drop(&mut self) {
            self.deactivate()
        }
    }
}

#[cfg(not(feature = "nat"))]
mod internal {
    pub struct PortForwarding;

    impl PortForwarding {
        pub fn new(_port: u16) -> Option<Self> {
            warn!("Compiled without feature 'nat', skipping port forwarding.");
            None
        }

        pub fn check_extend(&mut self) {
            unreachable!()
        }
    }
}

pub use internal::*;
