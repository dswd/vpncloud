# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.148.1/containers/rust/.devcontainer/base.Dockerfile

FROM mcr.microsoft.com/vscode/devcontainers/rust:0-1

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
     && apt-get -y install --no-install-recommends asciidoctor

RUN rm /etc/localtime && ln -s /usr/share/zoneinfo/Europe/Berlin /etc/localtime