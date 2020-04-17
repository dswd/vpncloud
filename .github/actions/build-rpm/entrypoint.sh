#!/bin/bash

set -e

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST}
source $HOME/.cargo/env

rustup target add i686-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf

cargo install cargo-rpm

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')

mkdir dist

cargo build --release
cargo rpm build
cp target/release/rpmbuild/RPMS/x86_64/vpncloud-${VERSION}-1.x86_64.rpm dist/vpncloud_${VERSION}.x86_64.rpm
