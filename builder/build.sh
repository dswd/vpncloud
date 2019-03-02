#!/bin/bash

function docker_cmd() {
  DIST=$1
  CMD=$2
  docker run -it --rm -v $(pwd)/..:/home/user/code \
    -v $CACHE/registry:/home/user/.cargo/registry \
    -v $CACHE/git:/home/user/.cargo/git \
    -v $CACHE/tmp:/home/user/.cargo/tmp \
    vpncloud-builder-$DIST bash -c "$CMD"
}

set -e

cd $(dirname $0)

VERSION=$(grep -e '^version =' ../Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')

mkdir -p cache/{git,tmp,registry}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t vpncloud-builder-deb .

# x86_64 deb
docker_cmd deb 'cd code && cargo deb'
cp ../target/debian/vpncloud_${VERSION}_amd64.deb ../dist/vpncloud_${VERSION}_amd64.deb

# arm7hf deb
docker_cmd deb 'cd code && cargo deb --target armv7-unknown-linux-gnueabihf'
cp ../target/armv7-unknown-linux-gnueabihf/debian/vpncloud_${VERSION}_armhf.deb ../dist/vpncloud_${VERSION}_armhf.deb


docker build --rm -f=Dockerfile-rpm -t vpncloud-builder-rpm .

# x86_64 rpm
docker_cmd rpm 'cd code && cargo rpm build'
cp ../target/release/rpmbuild/RPMS/x86_64/vpncloud-${VERSION}-1.x86_64.rpm ../dist/vpncloud_${VERSION}.x86_64.rpm
