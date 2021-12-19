#!/bin/bash

set -e

TOOLCHAIN=$(grep -e '^toolchain =' Cargo.toml | sed -e 's/toolchain = "\(.*\)"/\1/')

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')

ln -s asm-generic/ /usr/include/asm

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${TOOLCHAIN}
source $HOME/.cargo/env

rustup target add i686-unknown-linux-gnu
rustup target add armv5te-unknown-linux-gnueabi
rustup target add armv7-unknown-linux-gnueabihf
rustup target add aarch64-unknown-linux-gnu

cargo install cargo-deb

mkdir dist

build_deb() {
  ARCH=$1
  TARGET=$2
  cargo deb --target ${TARGET}
  cp target/${TARGET}/debian/vpncloud_${DEB_VERSION}_${ARCH}.deb dist/vpncloud_${DEB_VERSION}_${ARCH}.deb
}

cargo deb
cp target/debian/vpncloud_${DEB_VERSION}_amd64.deb dist/vpncloud_${DEB_VERSION}_amd64.deb

build_deb i386 i686-unknown-linux-gnu
build_deb armhf armv7-unknown-linux-gnueabihf
build_deb armel armv5te-unknown-linux-gnueabi
build_deb arm64 aarch64-unknown-linux-gnu