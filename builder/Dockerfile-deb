FROM debian:stable

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl ruby-ronn build-essential gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
 && rm -rf /var/cache/dpkg

RUN useradd -ms /bin/bash user
USER user
WORKDIR /home/user

ENV RUST=1.33.0

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST}

ENV PATH=/home/user/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN rustup target add i686-unknown-linux-gnu \
 && rustup target add armv7-unknown-linux-gnueabihf

RUN cargo install cargo-deb \
 && rm -rf /home/user/.cargo/{git,tmp,registry}

VOLUME /home/user/.cargo/tmp
VOLUME /home/user/.cargo/git
VOLUME /home/user/.cargo/registry

