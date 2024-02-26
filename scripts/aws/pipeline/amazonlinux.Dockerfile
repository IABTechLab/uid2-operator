# https://gist.github.com/toricls/e17c7f2f1c024cc368dcd860804194f5
FROM amazonlinux:2

RUN yum -y update
    # systemd is not a hard requirement for Amazon ECS Anywhere, but the installation script currently only supports systemd to run.
    # Amazon ECS Anywhere can be used without systemd, if you set up your nodes and register them into your ECS cluster **without** the installation script.
RUN yum -y groupinstall "Development Tools"
RUN yum -y install systemd vim-common wget git tar
RUN yum clean all

RUN yum -y install cmake cmake3
RUN alternatives --install /usr/local/bin/cmake cmake /usr/bin/cmake 10 \
--slave /usr/local/bin/ctest ctest /usr/bin/ctest \
--slave /usr/local/bin/cpack cpack /usr/bin/cpack \
--slave /usr/local/bin/ccmake ccmake /usr/bin/ccmake \
--family cmake
RUN alternatives --install /usr/local/bin/cmake cmake /usr/bin/cmake3 20 \
    --slave /usr/local/bin/ctest ctest /usr/bin/ctest3 \
    --slave /usr/local/bin/cpack cpack /usr/bin/cpack3 \
    --slave /usr/local/bin/ccmake ccmake /usr/bin/ccmake3 \
    --family cmake

RUN cd /lib/systemd/system/sysinit.target.wants/; \
    for i in *; do [ $i = systemd-tmpfiles-setup.service ] || rm -f $i; done
RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
    /etc/systemd/system/*.wants/* \
    /lib/systemd/system/local-fs.target.wants/* \
    /lib/systemd/system/sockets.target.wants/*udev* \
    /lib/systemd/system/sockets.target.wants/*initctl* \
    /lib/systemd/system/basic.target.wants/* \
    /lib/systemd/system/anaconda.target.wants/*

RUN amazon-linux-extras install -y epel docker aws-nitro-enclaves-cli
RUN yum -y install aws-nitro-enclaves-cli-devel

RUN systemctl enable docker

RUN wget https://www.inet.no/dante/files/dante-1.4.3.tar.gz \
    && echo "418a065fe1a4b8ace8fbf77c2da269a98f376e7115902e76cda7e741e4846a5d dante-1.4.3.tar.gz" > dante_checksum \
    && sha256sum --check dante_checksum \
    && tar -xf dante-1.4.3.tar.gz \
    && cd dante-1.4.3; ./configure; make; cd .. \
    && cp dante-1.4.3/sockd/sockd ./

RUN git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git \
    && mkdir uid2-aws-enclave-vsockproxy/build \
    && cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../.. \
    && cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx

COPY ./scripts/aws/pipeline/aws_nitro_eif.sh /aws_nitro_eif.sh

CMD ["/usr/sbin/init"]
