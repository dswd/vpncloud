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

mkdir -p cache/{rpm,deb,snap}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t vpncloud-builder-deb .

# x86_64 deb
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_amd64.deb ]; then
  docker_cmd deb 'cd code && cargo deb'
  cp $CACHE/deb/target/debian/vpncloud_${DEB_VERSION}_amd64.deb ../dist/vpncloud_${DEB_VERSION}_amd64.deb
fi

# i386 deb
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_i386.deb ]; then
  docker_cmd deb 'cd code && cargo deb --target i686-unknown-linux-gnu'
  cp $CACHE/deb/target/i686-unknown-linux-gnu/debian/vpncloud_${DEB_VERSION}_i386.deb ../dist/vpncloud_${DEB_VERSION}_i386.deb
fi

# arm7hf deb
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_armhf.deb ]; then
  docker_cmd deb 'cd code && cargo deb --target armv7-unknown-linux-gnueabihf'
  cp $CACHE/deb/target/armv7-unknown-linux-gnueabihf/debian/vpncloud_${DEB_VERSION}_armhf.deb ../dist/vpncloud_${DEB_VERSION}_armhf.deb
fi

# aarch64 deb
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_arm64.deb ]; then
  docker_cmd deb 'cd code && cargo deb --target aarch64-unknown-linux-gnu'
  cp $CACHE/deb/target/aarch64-unknown-linux-gnu/debian/vpncloud_${DEB_VERSION}_arm64.deb ../dist/vpncloud_${DEB_VERSION}_arm64.deb
fi


docker build --rm -f=Dockerfile-rpm -t vpncloud-builder-rpm .

# x86_64 rpm
if ! [ -f ../dist/vpncloud_${RPM_VERSION}.x86_64.rpm ]; then
  docker_cmd rpm 'cd code && cargo rpm build'
  cp $CACHE/rpm/target/release/rpmbuild/RPMS/x86_64/vpncloud-${RPM_VERSION}.x86_64.rpm ../dist/vpncloud_${RPM_VERSION}.x86_64.rpm
fi


docker build --rm -f=Dockerfile-snap -t vpncloud-builder-snap .

# x86_64 snap
if ! [ -f ../dist/vpncloud_${DEB_VERSION}_amd64.snap ]; then
  cp ../assets/snapcraft.yaml ../dist/vpncloud_${DEB_VERSION}_amd64.deb $CACHE/snap
  docker run -v "$CACHE/snap":/build -w /build vpncloud-builder-snap bash -c 'snapcraft; chown -R user: *'
  cp $CACHE/snap/vpncloud_${DEB_VERSION}_amd64.snap ../dist/vpncloud_${DEB_VERSION}_amd64.snap
fi