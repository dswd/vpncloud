extern crate gcc;
extern crate pkg_config;

fn main() {
    pkg_config::find_library("libsodium").unwrap();
    gcc::Config::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
}
