FROM ubuntu:16.04

ARG TOOLCHAIN=stable
ARG UPX_VERSION=3.96

RUN apt-get update \
 && apt-get install -y --no-install-recommends --no-install-suggests \
    build-essential \
    curl \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    gcc-arm-linux-gnueabi \
    libc6-dev-arm64-cross \
    libc6-dev-armhf-cross \
    libc6-dev-armel-cross \
    libc6-dev-i386 \
    gcc-5-multilib \
    asciidoctor \
    musl musl-dev musl-tools \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rust/rustup \
    PATH=/opt/rust/cargo/bin:/home/user/.cargo/bin:/usr/local/musl/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN curl https://sh.rustup.rs -sSf | env CARGO_HOME=/opt/rust/cargo sh -s -- -y --default-toolchain ${TOOLCHAIN} --profile minimal --no-modify-path

RUN env CARGO_HOME=/opt/rust/cargo rustup target add x86_64-unknown-linux-musl \
 && env CARGO_HOME=/opt/rust/cargo rustup target add i686-unknown-linux-musl \
 && env CARGO_HOME=/opt/rust/cargo rustup target add armv5te-unknown-linux-musleabi \
 && env CARGO_HOME=/opt/rust/cargo rustup target add armv7-unknown-linux-musleabihf \
 && env CARGO_HOME=/opt/rust/cargo rustup target add aarch64-unknown-linux-musl

RUN curl https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz -Lf | tar -xJ --strip-components=1 -C /opt/rust/cargo/bin

RUN ln -s asm-generic/ /usr/include/asm \
 && ln -s /usr/bin/g++ /usr/bin/musl-g++ \
 && ln -s /usr/bin/aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-musl-gcc \
 && ln -s /usr/bin/arm-linux-gnueabihf-gcc /usr/bin/arm-linux-musleabihf-gcc

RUN useradd -ms /bin/bash user
USER user
WORKDIR /home/user

RUN mkdir -p /home/user/.cargo \
 && ln -s /opt/rust/cargo/config /home/user/.cargo/config

VOLUME /home/user/.cargo/tmp
VOLUME /home/user/.cargo/git
VOLUME /home/user/.cargo/registry