FROM amazonlinux:2023
RUN dnf check-update && dnf update && dnf install nmap-ncat libxcrypt-compat python3 aws-nitro-enclaves-cli logrotate iproute net-tools python3.11 python3.11-pip shadow-utils -y

ARG IVYKIS_RPM="ivykis-0.43-1.amzn2023.x86_64.rpm"
ARG LIBNET_RPM="libnet-1.2-2.amzn2023.0.2.x86_64.rpm"
ARG PUBKEY="pubkey.gpg"
ARG SYSLOG_NG_RPM="syslog-ng-4.7.1.104.gcc5a7d9-1.amzn2023.x86_64.rpm"
ARG SYSLOG_NG_LOGROTATE_RPM="syslog-ng-logrotate-4.7.1.104.gcc5a7d9-1.amzn2023.x86_64.rpm"

COPY ./sockd /home/
COPY ./sockd_eks.conf /etc/sockd.conf
COPY ./vsockpx /home
COPY ./${IVYKIS_RPM} /home/syslog-ng/
COPY ./${LIBNET_RPM} /home/syslog-ng/
COPY ./${PUBKEY} /home/syslog-ng/
COPY ./${SYSLOG_NG_RPM} /home/syslog-ng/
COPY ./${SYSLOG_NG_LOGROTATE_RPM} /home/syslog-ng/

# Install syslog-ng
RUN rpmkeys --import /home/syslog-ng/${PUBKEY} && \
    rpm -U /home/syslog-ng/${IVYKIS_RPM} && \
    rpm -U /home/syslog-ng/${LIBNET_RPM} && \
    rpm -U /home/syslog-ng/${SYSLOG_NG_RPM} && \
    rpm -U /home/syslog-ng/${SYSLOG_NG_LOGROTATE_RPM} && \
    rpm -e gpg-pubkey-2c519859-6630e289 && \
    rm -r /home/syslog-ng 

COPY ./syslog-ng-server.conf /etc/syslog-ng/syslog-ng.conf

COPY ./entrypoint.sh /home/
COPY ./uid2operator.eif /home/
COPY ./proxies.host.yaml /home/proxies.host.yaml

RUN chmod +x /home/vsockpx && chmod +x /home/entrypoint.sh

COPY ./app.py /home/config-server/
COPY ./requirements.txt /home/config-server/
RUN python3 -m venv config-server
RUN config-server/bin/pip3 install -r /home/config-server/requirements.txt

RUN useradd ec2-user

CMD ["/home/entrypoint.sh > /home/start.txt 2>&1"]