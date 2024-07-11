FROM amazonlinux:2023
RUN yum install aws-nitro-enclaves-cli-devel jq -y
RUN dnf install aws-nitro-enclaves-cli -y
RUN yum install -y libxcrypt-compat

RUN yum install -y python3

COPY ./sockd /home/
COPY ./sockd.conf /etc/
COPY ./python_enclave/uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge /home/vsockpx

COPY ./entrypoint.sh /home/
COPY ./uid2operator.eif /home/
COPY ./proxies.host.yaml /home/proxies.host.yaml

RUN chmod +x /home/vsockpx && chmod +x /home/entrypoint.sh
RUN yum install net-tools -y

CMD ["/home/entrypoint.sh"]