extern crate gcc;
extern crate pkg_config;

use std::process::Command;
use std::path::Path;

fn main() {
    if ! Path::new("libsodium/src/libsodium/.libs/libsodium.a").exists() {
        Command::new("sh").arg("autogen.sh").current_dir("libsodium").status().unwrap();
        Command::new("sh").arg("configure").current_dir("libsodium").status().unwrap();
        Command::new("make").current_dir("libsodium").status().unwrap();
    }
    gcc::Config::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
    println!("cargo:rustc-link-search={}", "libsodium/src/libsodium/.libs");
}
