FROM amazonlinux:2023

EXPOSE 27015

RUN adduser -D ec2-user
USER ec2-user

RUN dnf install aws-nitro-enclaves-cli-devel jq -y
RUN dnf install aws-nitro-enclaves-cli -y
# RUN yum install -y libxcrypt-compat
RUN dnf -y install amazon-ec2-net-utils
RUN dnf -y install iproute
RUN dnf -y install systemd-networkd

RUN dnf install python3.11 -y
RUN dnf install python3.11-pip -y

COPY ./sockd /home/
COPY ./sockd_eks.conf /etc/sockd.conf
COPY ./vsockpx /home

COPY ./entrypoint.sh /home/
COPY ./uid2operator.eif /home/
COPY ./proxies.host.yaml /home/proxies.host.yaml

RUN chmod +x /home/vsockpx && chmod +x /home/entrypoint.sh
# RUN yum install net-tools -y

COPY ./app.py /home/config-server/
COPY ./requirements.txt /home/config-server/
RUN python3 -m venv config-server
RUN config-server/bin/pip3 install -r /home/config-server/requirements.txt

RUN dnf -y install shadow-utils
RUN useradd ec2-user
USER ec2-user

CMD ["/home/entrypoint.sh"]