extern crate gcc;

fn main() {
    gcc::Config::new().file("src/c/tapdev.c").include("src").compile("libtapdev.a");
}