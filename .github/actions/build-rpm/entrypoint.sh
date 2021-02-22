#!/bin/bash

set -e

TOOLCHAIN=$(grep -e '^toolchain =' Cargo.toml | sed -e 's/toolchain = "\(.*\)"/\1/')

VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
if echo "$VERSION" | fgrep -q "-"; then
  RPM_VERSION=$(echo "$VERSION" | sed -e 's/-/-0./g')
else
  RPM_VERSION="$VERSION-1"
fi

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${TOOLCHAIN}
source $HOME/.cargo/env

rustup target add i686-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf

cargo install cargo-rpm

mkdir dist

cargo build --release
cargo rpm build
cp target/release/rpmbuild/RPMS/x86_64/vpncloud-${RPM_VERSION}.x86_64.rpm dist/vpncloud_${RPM_VERSION}.x86_64.rpm


build_rpm() {
  ARCH=$1
  TARGET=$2
  if ! [ -f dist/vpncloud_${RPM_VERSION}.${ARCH}.rpm ]; then
    mkdir -p target
    [ -L target/assets ] || ln -s ../assets target/assets
    [ -L target/target ] || ln -s ../target target/target
    cargo rpm build --target ${TARGET}
    cp target/${TARGET}/release/rpmbuild/RPMS/${ARCH}/vpncloud-${RPM_VERSION}.${ARCH}.rpm dist/vpncloud_${RPM_VERSION}.${ARCH}.rpm
  fi
}

build_rpm i686 i686-unknown-linux-gnu