FROM ubuntu:16.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    libc6-dev-arm64-cross \
    libc6-dev-armhf-cross \
    libc6-dev-i386 \
    gcc-5-multilib \
    asciidoctor \
 && rm -rf /var/cache/dpkg

RUN ln -s asm-generic/ /usr/include/asm

ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
