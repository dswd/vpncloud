// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2017  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

extern crate cc;

fn main() {
    cc::Build::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
}
