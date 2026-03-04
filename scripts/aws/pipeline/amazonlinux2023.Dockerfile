# https://gist.github.com/toricls/e17c7f2f1c024cc368dcd860804194f5
FROM amazonlinux:2023

RUN dnf update -y
    # systemd is not a hard requirement for Amazon ECS Anywhere, but the installation script currently only supports systemd to run.
    # Amazon ECS Anywhere can be used without systemd, if you set up your nodes and register them into your ECS cluster **without** the installation script.
RUN dnf -y groupinstall "Development Tools" \
    && dnf -y install systemd vim-common wget git tar libstdc++-static.x86_64 cmake cmake3 aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
    && dnf clean all

RUN systemctl enable docker

# inet.no has expired their SSL certificate, so we need to use a different source.
# https://www.inet.no/dante/download.html Got the sha255 from the official website.
RUN wget https://fossies.org/linux/misc/dante-1.4.4.tar.gz \
    && echo "1973c7732f1f9f0a4c0ccf2c1ce462c7c25060b25643ea90f9b98f53a813faec dante-1.4.4.tar.gz" > dante_checksum \
    && sha256sum --check dante_checksum \
    && tar -xf dante-1.4.4.tar.gz \
    && cd dante-1.4.4; ./configure; make; cd .. \
    && cp dante-1.4.4/sockd/sockd ./ \
    && rm -rf dante-1.4.4 dante-1.4.4.tar.gz

RUN git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git \
    && mkdir uid2-aws-enclave-vsockproxy/build \
    && cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../.. \
    && cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx \
    && rm -rf uid2-aws-enclave-vsockproxy

COPY ./scripts/aws/pipeline/aws_nitro_eif.sh /aws_nitro_eif.sh

CMD ["/usr/sbin/init"]
