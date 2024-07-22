FROM amazonlinux:2023
RUN dnf check-update && dnf update && dnf install nmap-ncat libxcrypt-compat python3 aws-nitro-enclaves-cli logrotate -y

#COPY ./sockd /home/
#COPY ./sockd.conf /etc/
#COPY ./vsockpx /home

#COPY ./uid2operator.eif /home/
#COPY ./proxies.host.yaml /home/proxies.host.yaml

#RUN chmod +x /home/vsockpx && chmod +x /home/entrypoint.sh
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
RUN chmod +x /home/entrypoint.sh
# RUN yum install net-tools -y

CMD ["/home/entrypoint.sh"]