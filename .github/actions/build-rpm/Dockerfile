FROM centos:7

RUN yum groupinstall -y 'Development Tools'
RUN yum install -y ruby && gem install asciidoctor -v 2.0.10

ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
