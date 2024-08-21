# https://hub.docker.com/layers/library/eclipse-temurin/21-jre-jammy/images/sha256-3186dd88a59659929855a6bb785b0528c812eb0b03d97fd6e2221526547ed322?context=explore
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0
ARG IMAGE_VERSION=1.0.0.unknownhash
ARG IDENTITY_SCOPE=UID2

ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV IDENTITY_SCOPE=${IDENTITY_SCOPE}
ENV ENCLAVE_ENVIRONMENT="aws-nitro"
ENV UID2_CONFIG_SECRET_KEY="uid2-operator-config-key"

COPY ./syslog-ng-core_4.6.0-1_amd64.deb /app/dep/
COPY ./syslog-ng-ose-pub.asc /app/dep/

RUN echo "deb http://security.ubuntu.com/ubuntu focal-security main" | tee -a /etc/apt/sources.list \
    && apt update -y \
    && apt install -y pkg-config libssl-dev libssl1.1 net-tools curl jq netcat python3 python3-pip libcap2 libivykis0 libjson-c5 libnet1 libwrap0 \
    && apt-key add /app/dep/syslog-ng-ose-pub.asc \
    && apt-get install /app/dep/syslog-ng-core_4.6.0-1_amd64.deb \
    && rm -rf /var/lib/apt/lists/* \
    && apt-key del 6694369F 
RUN pip3 install boto3==1.16.9

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./static             /app/static
COPY ./libjnsm.so         /app/lib/
COPY ./vsockpx            /app/
COPY ./make_config.py     /app/
COPY ./entrypoint.sh      /app/
COPY ./proxies.nitro.yaml /app/
COPY ./conf/default-config.json    /app/conf/
COPY ./conf/prod-uid2-config.json  /app/conf/
COPY ./conf/integ-uid2-config.json /app/conf/
COPY ./conf/prod-euid-config.json  /app/conf/
COPY ./conf/integ-euid-config.json /app/conf/
COPY ./conf/*.xml                  /app/conf/
COPY ./syslog-ng-client.conf       /etc/syslog-ng/syslog-ng.conf

RUN chmod +x /app/vsockpx && chmod +x /app/entrypoint.sh


CMD "/app/entrypoint.sh"
