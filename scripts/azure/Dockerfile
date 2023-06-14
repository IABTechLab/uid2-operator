FROM ghcr.io/iabtechlab/uid2-operator-azure-occlum-build:dev
COPY build/uid2-operator/uid2-operator.tar.gz /root
RUN tar xvf /root/uid2-operator.tar.gz
COPY files/run.sh /root/run.sh
RUN chmod a+x /root/run.sh
ENTRYPOINT ["/bin/bash", "/root/run.sh"]
CMD ["occlum", "run", "/bin/launcher"]
