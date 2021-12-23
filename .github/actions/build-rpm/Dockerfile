FROM centos:7

RUN yum groupinstall -y 'Development Tools'
RUN yum install -y ruby && gem install asciidoctor -v 2.0.10
RUN yum install -y libstdc++-*.i686 \
 && yum install -y glibc-*.i686 \
 && yum install -y libgcc.i686

RUN ln -s /usr/bin/gcc /usr/bin/i686-linux-gnu-gcc

ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
