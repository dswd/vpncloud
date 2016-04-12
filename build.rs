extern crate gcc;
extern crate pkg_config;

use std::process::Command;
use std::path::Path;
use std::env;

fn main() {
    if ! Path::new("libsodium/src/libsodium/.libs/libsodium.a").exists() {
        let target = env::var("TARGET").unwrap();
        Command::new("sh").arg("autogen.sh").current_dir("libsodium").status().unwrap();
        let mut args = vec!["configure", "--host", &target];
        if target.starts_with("i686-") {
            args.extend(vec!["CFLAGS=-m32", "CXXFLAGS=-m32", "LDFLAGS=-m32"]);
        }
        Command::new("sh").args(&args).current_dir("libsodium").status().unwrap();
        Command::new("make").current_dir("libsodium").status().unwrap();
    }
    gcc::Config::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
    println!("cargo:rustc-link-search={}", "libsodium/src/libsodium/.libs");
}
