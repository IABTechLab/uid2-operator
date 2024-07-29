FROM amazonlinux:2023
RUN dnf check-update && dnf update && dnf install nmap-ncat libxcrypt-compat python3 aws-nitro-enclaves-cli logrotate iproute net-tools python3.11 python3.11-pip -y

COPY ./sockd /home/
COPY ./sockd_eks.conf /etc/sockd.conf
COPY ./vsockpx /home
COPY ./server_al_2023/*.* /home/syslog-ng/

# Install syslog-ng
RUN rpmkeys --import /home/syslog-ng/pubkey.gpg && \
    rpm -U /home/syslog-ng/ivykis-0.43-1.amzn2023.x86_64.rpm && \
    rpm -U /home/syslog-ng/libnet-1.2-2.amzn2023.0.2.x86_64.rpm && \
    rpm -U /home/syslog-ng/syslog-ng-4.7.1.104.gcc5a7d9-1.amzn2023.x86_64.rpm && \
    rpm -U /home/syslog-ng/syslog-ng-logrotate-4.7.1.104.gcc5a7d9-1.amzn2023.x86_64.rpm && \
    rpm -e gpg-pubkey-2c519859-6630e289

COPY ./server_al_2023/syslog-ng-server.conf /etc/syslog-ng/syslog-ng.conf

COPY ./entrypoint.sh /home/
COPY ./uid2operator.eif /home/
COPY ./proxies.host.yaml /home/proxies.host.yaml

RUN chmod +x /home/vsockpx && chmod +x /home/entrypoint.sh

COPY ./app.py /home/config-server/
COPY ./requirements.txt /home/config-server/
RUN python3 -m venv config-server
RUN config-server/bin/pip3 install -r /home/config-server/requirements.txt

RUN dnf -y install shadow-utils
RUN useradd ec2-user

CMD ["/home/entrypoint.sh"]