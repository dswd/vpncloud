#!/bin/bash

function docker_cmd() {
  DIST=$1
  CMD=$2
  mkdir -p $CACHE/$DIST/{target,registry,git,tmp}
  docker run -it --rm -v $(pwd)/..:/home/user/code \
    -v $CACHE/$DIST/target:/home/user/code/target \
    -v $CACHE/$DIST/registry:/home/user/.cargo/registry \
    -v $CACHE/$DIST/git:/home/user/.cargo/git \
    -v $CACHE/$DIST/tmp:/home/user/.cargo/tmp \
    vpncloud-builder-$DIST bash -c "$CMD"
}

set -e

cd $(dirname $0)

VERSION=$(grep -e '^version =' ../Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')
if echo "$VERSION" | fgrep -q "-"; then
  RPM_VERSION=$(echo "$VERSION" | sed -e 's/-/-0./g')
else
  RPM_VERSION="$VERSION-1"
fi

mkdir -p cache/{rpm,deb}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t vpncloud-builder-deb .

# x86_64 deb
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_amd64.deb ]; then
  docker_cmd deb 'cd code && cargo deb'
  cp $CACHE/deb/target/debian/vpncloud_${DEB_VERSION}_amd64.deb ../dist/vpncloud_${DEB_VERSION}_amd64.deb
fi

build_deb() {
  ARCH=$1
  TARGET=$2
  if ! [ -f ../dist/vpncloud_${DEB_VERSION}_${ARCH}.deb ]; then
    docker_cmd deb "cd code && cargo deb --target ${TARGET}"
    cp $CACHE/deb/target/${TARGET}/debian/vpncloud_${DEB_VERSION}_${ARCH}.deb ../dist/vpncloud_${DEB_VERSION}_${ARCH}.deb
  fi
}

build_deb i386 i686-unknown-linux-gnu
build_deb armhf armv7-unknown-linux-gnueabihf
build_deb arm64 aarch64-unknown-linux-gnu


build_static() {
  ARCH=$1
  TARGET=$2
  if ! [ -f ../dist/vpncloud_${VERSION}_static_${ARCH} ]; then
    docker_cmd deb "cd code && cargo build --release --features installer --target ${TARGET} && upx --lzma target/${TARGET}/release/vpncloud"
    cp $CACHE/deb/target/${TARGET}/release/vpncloud ../dist/vpncloud_${VERSION}_static_${ARCH}
  fi
}

build_static amd64 x86_64-unknown-linux-musl
build_static i386 i686-unknown-linux-gnu
build_static armhf armv7-unknown-linux-musleabihf
#build_static arm64 aarch64-unknown-linux-musl # fails for unknown reason


docker build --rm -f=Dockerfile-rpm -t vpncloud-builder-rpm .

if ! [ -f ../dist/vpncloud_${RPM_VERSION}.x86_64.rpm ]; then
  # x86_64 rpm
  docker_cmd rpm 'cd code && cargo rpm build'
  cp $CACHE/rpm/target/release/rpmbuild/RPMS/x86_64/vpncloud-${RPM_VERSION}.x86_64.rpm ../dist/vpncloud_${RPM_VERSION}.x86_64.rpm
fi