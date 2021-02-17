FROM ubuntu

RUN apt-get update && apt-get install -y asciinema
RUN mkdir /root/.asciinema
RUN mkdir /etc/vpncloud

WORKDIR /data
ADD config /root/.asciinema/config
RUN echo 'PS1="\[\e[00;34m\]\[\e[01;31m\]\u\[\e[00;01;34m\]@\[\e[00;34m\]node\[\e[01;31m\]:\[\e[00;34m\]\w\[\e[01;31m\]> \[\e[00m\]"' >> /root/.bashrc