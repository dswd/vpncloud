// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2019  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

extern crate cc;

use std::process::Command;
use std::env;
use std::path::Path;
use std::fs;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Compile tun/tap C code
    println!("rerun-if-changed=src/c/tuntap.c");
    cc::Build::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");

    // Process manpage using ronn command
    println!("rerun-if-changed=vpncloud.md");
    fs::copy("vpncloud.md", Path::new(&out_dir).join("vpncloud.1.ronn")).unwrap();
    Command::new("ronn").args(&["-r", "vpncloud.1.ronn"]).current_dir(&Path::new(&out_dir)).status().expect("Failed to process manpage, ronn command missing?");
    Command::new("gzip").args(&["vpncloud.1"]).current_dir(&Path::new(&out_dir)).status().unwrap();
    fs::copy(Path::new(&out_dir).join("vpncloud.1.gz"), "target/vpncloud.1.gz").unwrap();
}
