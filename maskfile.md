# Commands

Needs [mask](https://github.com/jacobdeichert/mask) to run.


## install-tools

> Install tools.

```sh
set -e
apt-get install -y asciidoctor
cargo install cargo-binstall
cargo binstall cross cargo-deb cargo-generate-rpm
UPX_VERSION=$(grep -e '^upx_version =' Cargo.toml | sed -e 's/upx_version = "\(.*\)"/\1/')
curl https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz -Lf | tar -xJ --strip-components=1 -C /usr/local/bin
```

## manpage

> Generate manpage.

```sh
set -e
echo >&2 "Generating manpage"
if [ ! -f target/vpncloud.1.gz -o vpncloud.adoc -nt target/vpncloud.1.gz ]; then
  asciidoctor -b manpage -o target/vpncloud.1 vpncloud.adoc
  gzip -f target/vpncloud.1
fi
```

## build-packages-cross (target) (target_name) (target_name_rpm)

> Build the project packages for a given target.

```sh
set -e
VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
TARGET=$target
TARGET_DIR=target/$target_name

# compile
echo >&2 "Compiling for $target_name"
cross build --release --target $TARGET --target-dir $TARGET_DIR
mkdir -p target/$TARGET/release
cp $TARGET_DIR/$TARGET/release/vpncloud target/$TARGET/release/

# build deb
echo >&2 "Building deb package"
cargo deb --no-build --no-strip --target $TARGET
mv target/$TARGET/debian/vpncloud_${VERSION}-1_$target_name.deb dist/vpncloud_${VERSION}_$target_name.deb

# build rpm
if [ -n "$target_name_rpm" ]; then
  echo >&2 "Building rpm package"
  cargo generate-rpm --target $TARGET --target-dir $TARGET_DIR
  mv $TARGET_DIR/$TARGET/generate-rpm/vpncloud-${VERSION}-1.$target_name_rpm.rpm dist/vpncloud_${VERSION}-1.$target_name_rpm.rpm
fi
```

## build-amd64-packages

```sh
$MASK build-packages-cross x86_64-unknown-linux-gnu amd64 x86_64
```

## build-i386-packages

```sh
$MASK build-packages-cross i686-unknown-linux-gnu i386 i686
```

## build-arm64-packages

```sh
$MASK build-packages-cross aarch64-unknown-linux-gnu arm64 aarch64
```

## build-armhf-packages

```sh
$MASK build-packages-cross armv7-unknown-linux-gnueabihf armhf ""
```

## build-armel-packages

```sh
$MASK build-packages-cross armv5te-unknown-linux-gnueabi armel ""
```



## build-static-cross (target) (target_name)

> Build the project statically for a given target.

```sh
set -e
VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
TARGET=$target
TARGET_DIR=target/$target_name-musl
BIN=$TARGET_DIR/$TARGET/release/vpncloud

echo >&2 "Compiling for $target_name musl"
cross build --release --features installer --target $TARGET --target-dir $TARGET_DIR
upx --lzma $BIN
cp $BIN dist/vpncloud_${VERSION}_static_$target_name
```

## build-amd64-static

```sh
$MASK build-static-cross x86_64-unknown-linux-musl amd64
```


## build-i386-static

```sh
$MASK build-static-cross i686-unknown-linux-musl i386
```


## build-arm64-static

```sh
$MASK build-static-cross aarch64-unknown-linux-musl arm64
```

## build-armhf-static

```sh
$MASK build-static-cross armv7-unknown-linux-musleabihf armhf
```

## build-armel-static

```sh
$MASK build-static-cross armv5te-unknown-linux-musleabi armel
```


## build

> Build the project for all architectures.

```sh
set -e
$MASK manpage
$MASK build-amd64-packages
$MASK build-amd64-static
$MASK build-i386-packages
$MASK build-i386-static
$MASK build-arm64-packages
$MASK build-arm64-static
$MASK build-armhf-packages
$MASK build-armhf-static
$MASK build-armel-packages
$MASK build-armel-static
```

## sign

> Sign the packages.

```sh
set -e
VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
cd dist
sha256sum vpncloud_${VERSION}_static_* vpncloud_${VERSION}*.rpm vpncloud_${VERSION}*.deb  > vpncloud_${VERSION}_SHA256SUMS.txt
gpg --armor --output vpncloud_${VERSION}_SHA256SUMS.txt.asc --detach-sig vpncloud_${VERSION}_SHA256SUMS.txt
```

## test

> Test the project.

```sh
cargo test --all-features
```

## release

> Release the project.

```sh
set -e

$MASK test
nano Cargo.toml
VERSION=$(grep -e '^version =' Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
nano CHANGELOG.md
nano assets/changelog.txt
$MASK build
$MASK sign
git commit -a
cargo publish
git tag v$VERSION
git push --tags
```


## count

> Count the lines of code.

```sh
tokei
```