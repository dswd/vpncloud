// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

extern crate cc;

use std::{env, fs, path::Path, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Compile tun/tap C code
    println!("cargo:rerun-if-changed=src/c/tuntap.c");
    cc::Build::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");

    // Process manpage using asciidoctor command
    println!("cargo:rerun-if-changed=vpncloud.adoc");
    fs::copy("vpncloud.adoc", Path::new(&out_dir).join("vpncloud.adoc")).unwrap();
    match Command::new("asciidoctor")
        .args(&["-b", "manpage", "vpncloud.adoc"])
        .current_dir(&Path::new(&out_dir))
        .status()
    {
        Ok(_) => {
            Command::new("gzip").args(&["vpncloud.1"]).current_dir(&Path::new(&out_dir)).status().unwrap();
            fs::copy(Path::new(&out_dir).join("vpncloud.1.gz"), "target/vpncloud.1.gz").unwrap();
        }
        Err(err) => {
            println!("cargo:warning=Error building manpage: {}", err);
            println!("cargo:warning=The manpage will not be build. Do you have 'asciidoctor'?");
        }
    }
}
