extern crate gcc;
extern crate pkg_config;

use std::process::Command;
use std::path::PathBuf;
use std::env;
use std::fs;

fn main() {
    gcc::Config::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
    if cfg!(feature = "system-libsodium") {
        pkg_config::Config::new().atleast_version("1.0.8").probe("libsodium").expect("Libsodium >= 1.0.8 missing");
        return
    } else {
        let target = env::var("TARGET").unwrap();
        let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let libsodium_dir = dir.join("libsodium");
        let libsodium_target_dir = dir.join("target/sodium-build").join(&target);
        let libsodium_target_file = libsodium_target_dir.join("libsodium.a");
        if ! libsodium_target_file.exists() {
            fs::create_dir_all(&libsodium_target_dir).unwrap();
            Command::new("make").arg("clean").current_dir(&libsodium_dir).status().unwrap();
            Command::new("sh").arg("autogen.sh").current_dir(&libsodium_dir).status().unwrap();
            let mut args = vec!["configure", "--host", &target];
            if target.starts_with("i686-") {
                args.extend(vec!["CFLAGS=-m32", "CXXFLAGS=-m32", "LDFLAGS=-m32"]);
            }
            if target.ends_with("-musl") {
                args.extend(vec!["CC=musl-gcc"]);
            }
            if target == "arm-unknown-linux-gnueabihf" || target == "armv7-unknown-linux-gnueabihf" {
                args.extend(vec!["CC=arm-linux-gnueabihf-gcc"]);
            }
            Command::new("sh").args(&args).current_dir(&libsodium_dir).status().unwrap();
            Command::new("make").current_dir(&libsodium_dir).status().unwrap();
            fs::copy(libsodium_dir.join("src/libsodium/.libs/libsodium.a"), libsodium_target_file).unwrap();
        }
        println!("cargo:rustc-link-search={}", libsodium_target_dir.to_str().unwrap());
    }
}
