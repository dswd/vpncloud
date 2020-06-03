FROM centos:7

RUN yum groupinstall -y 'Development Tools'
RUN yum install -y ruby && gem install asciidoctor

ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
