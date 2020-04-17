FROM centos:7

RUN yum groupinstall -y 'Development Tools'

RUN yum-config-manager --add-repo http://springdale.math.ias.edu/data/puias/computational/7/x86_64 \
 && yum install --nogpgcheck -y rubygem-ronn

ADD entrypoint.sh /entrypoint.sh

ENTRYPOINT /entrypoint.sh
