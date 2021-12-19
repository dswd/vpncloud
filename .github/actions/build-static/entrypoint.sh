#!/bin/bash

set -e

TOOLCHAIN=$(grep -e '^toolchain =' Cargo.toml | sed -e 's/toolchain = "\(.*\)"/\1/')
UPX_VERSION=$(grep -e '^upx_version =' Cargo.toml | sed -e 's/upx_version = "\(.*\)"/\1/')

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')

ln -s asm-generic/ /usr/include/asm
ln -s /usr/bin/aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-musl-gcc
ln -s /usr/bin/arm-linux-gnueabihf-gcc /usr/bin/arm-linux-musleabihf-gcc

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${TOOLCHAIN}
source $HOME/.cargo/env

rustup target add x86_64-unknown-linux-musl
rustup target add i686-unknown-linux-musl
rustup target add armv5te-unknown-linux-musleabi
rustup target add armv7-unknown-linux-musleabihf
rustup target add aarch64-unknown-linux-musl

curl https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz -Lf | tar -xJ --strip-components=1 -C /opt/rust/cargo/bin

mkdir dist

build_static() {
  ARCH=$1
  TARGET=$2
  cargo build --release --features installer --target ${TARGET} && upx --lzma target/${TARGET}/release/vpncloud
  cp target/${TARGET}/release/vpncloud ../dist/vpncloud_${VERSION}_static_${ARCH}
}

build_static amd64 x86_64-unknown-linux-musl
#build_static i386 i686-unknown-linux-musl
build_static armhf armv7-unknown-linux-musleabihf
build_static armel armv5te-unknown-linux-musleabi
build_static arm64 aarch64-unknown-linux-musl