# https://gist.github.com/toricls/e17c7f2f1c024cc368dcd860804194f5
FROM amazonlinux:2023

RUN dnf update -y
    # systemd is not a hard requirement for Amazon ECS Anywhere, but the installation script currently only supports systemd to run.
    # Amazon ECS Anywhere can be used without systemd, if you set up your nodes and register them into your ECS cluster **without** the installation script.
RUN dnf -y groupinstall "Development Tools" \
    && dnf -y install systemd vim-common wget git tar libstdc++-static.x86_64 cmake cmake3 aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
    && dnf clean all

RUN systemctl enable docker

RUN wget https://www.inet.no/dante/files/dante-1.4.3.tar.gz \
    && echo "418a065fe1a4b8ace8fbf77c2da269a98f376e7115902e76cda7e741e4846a5d dante-1.4.3.tar.gz" > dante_checksum \
    && sha256sum --check dante_checksum \
    && tar -xf dante-1.4.3.tar.gz \
    && cd dante-1.4.3; ./configure; make; cd .. \
    && cp dante-1.4.3/sockd/sockd ./ \
    && rm -rf dante-1.4.3 dante-1.4.3.tar.gz

RUN git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git \
    && mkdir uid2-aws-enclave-vsockproxy/build \
    && cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../.. \
    && cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx \
    && rm -rf uid2-aws-enclave-vsockproxy

COPY ./scripts/aws/pipeline/aws_nitro_eif.sh /aws_nitro_eif.sh

CMD ["/usr/sbin/init"]
