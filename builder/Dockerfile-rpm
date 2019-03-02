FROM centos:latest

RUN yum groupinstall -y 'Development Tools'

RUN useradd -ms /bin/bash user
USER user
WORKDIR /home/user

ENV RUST=1.33.0

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST}

ENV PATH=/home/user/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN rustup target add i686-unknown-linux-gnu \
 && rustup target add armv7-unknown-linux-gnueabihf

RUN cargo install cargo-rpm \
 && rm -rf /home/user/.cargo/{git,tmp,registry}

VOLUME /home/user/.cargo/tmp
VOLUME /home/user/.cargo/git
VOLUME /home/user/.cargo/registry

