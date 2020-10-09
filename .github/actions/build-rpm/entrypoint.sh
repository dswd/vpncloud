#!/bin/bash

set -e

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST}
source $HOME/.cargo/env

rustup target add i686-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf

cargo install cargo-rpm

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
if echo "$VERSION" | fgrep -q "-"; then
  RPM_VERSION=$(echo "$VERSION" | sed -e 's/-/-0./g')
else
  RPM_VERSION="$VERSION-1"
fi

mkdir dist

cargo build --release
cargo rpm build
cp target/release/rpmbuild/RPMS/x86_64/vpncloud-${RPM_VERSION}.x86_64.rpm dist/vpncloud_${RPM_VERSION}.x86_64.rpm
