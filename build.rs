extern crate gcc;

fn main() {
    gcc::Config::new().file("src/c/tuntap.c").include("src").compile("libtuntap.a");
}
