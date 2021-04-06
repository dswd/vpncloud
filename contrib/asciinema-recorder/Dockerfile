FROM ubuntu

RUN apt-get update && apt-get install -y asciinema locales bash iputils-ping
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8
RUN mkdir /root/.asciinema
RUN mkdir /etc/vpncloud

WORKDIR /data
ADD config /root/.asciinema/config
RUN echo 'PS1="\[\e[00;34m\]\[\e[01;31m\]\u\[\e[00;01;34m\]@\[\e[00;34m\]node\[\e[01;31m\]:\[\e[00;34m\]\w\[\e[01;31m\]> \[\e[00m\]"' >> /root/.bashrc
