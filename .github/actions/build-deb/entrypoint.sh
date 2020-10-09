#!/bin/bash

set -e

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST}
source $HOME/.cargo/env

rustup target add i686-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf
rustup target add aarch64-unknown-linux-gnu

cargo install cargo-deb

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')

mkdir dist

cargo deb
cp target/debian/vpncloud_${DEB_VERSION}_amd64.deb dist/vpncloud_${DEB_VERSION}_amd64.deb

# i386 deb
cargo deb --target i686-unknown-linux-gnu
cp target/i686-unknown-linux-gnu/debian/vpncloud_${DEB_VERSION}_i386.deb dist/vpncloud_${DEB_VERSION}_i386.deb

# arm7hf deb
cargo deb --target armv7-unknown-linux-gnueabihf
cp target/armv7-unknown-linux-gnueabihf/debian/vpncloud_${DEB_VERSION}_armhf.deb dist/vpncloud_${DEB_VERSION}_armhf.deb

# aarch64 deb
cargo deb --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/debian/vpncloud_${DEB_VERSION}_arm64.deb dist/vpncloud_${DEB_VERSION}_arm64.debllll