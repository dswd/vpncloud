# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.148.1/containers/rust/.devcontainer/base.Dockerfile

FROM mcr.microsoft.com/vscode/devcontainers/rust:1

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
     && apt-get -y install --no-install-recommends asciidoctor

RUN rm /etc/localtime && ln -s /usr/share/zoneinfo/Europe/Berlin /etc/localtime

RUN chown vscode: -R /usr/local/rustup /usr/local/cargo

USER vscode

RUN rustup default 1.57.0 \
 && rustup component add clippy rust-src rustfmt

RUN cargo install cargo-outdated cargo-cache cargo-criterion \
 && cargo cache -a