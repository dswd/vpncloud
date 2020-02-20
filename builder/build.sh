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

mkdir -p cache/{rpm,deb}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t vpncloud-builder-deb .

# x86_64 deb
docker_cmd deb 'cd code && cargo deb'
cp $CACHE/deb/target/debian/vpncloud_${VERSION}_amd64.deb ../dist/vpncloud_${VERSION}_amd64.deb

# i386 deb
docker_cmd deb 'cd code && cargo deb --target i686-unknown-linux-gnu'
cp $CACHE/deb/target/i686-unknown-linux-gnu/debian/vpncloud_${VERSION}_i386.deb ../dist/vpncloud_${VERSION}_i386.deb

# arm7hf deb
docker_cmd deb 'cd code && cargo deb --target armv7-unknown-linux-gnueabihf'
cp $CACHE/deb/target/armv7-unknown-linux-gnueabihf/debian/vpncloud_${VERSION}_armhf.deb ../dist/vpncloud_${VERSION}_armhf.deb

# aarch64 deb
docker_cmd deb 'cd code && cargo deb --target aarch64-unknown-linux-gnu'
cp $CACHE/deb/target/aarch64-unknown-linux-gnu/debian/vpncloud_${VERSION}_arm64.deb ../dist/vpncloud_${VERSION}_arm64.deb


docker build --rm -f=Dockerfile-rpm -t vpncloud-builder-rpm .

# x86_64 rpm
docker_cmd rpm 'cd code && cargo rpm build'
cp $CACHE/rpm/target/release/rpmbuild/RPMS/x86_64/vpncloud-${VERSION}-1.x86_64.rpm ../dist/vpncloud_${VERSION}.x86_64.rpm
