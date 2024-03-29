FROM openjdk:11.0-jre-slim-bullseye

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

RUN apt update -y \
    && apt install -y pkg-config libssl-dev net-tools curl jq netcat python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install boto3==1.16.9

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./static             /app/static
COPY ./libjnsm.so         /app/lib/
COPY ./vsockpx            /app/
COPY ./load_config.py     /app/
COPY ./make_config.py     /app/
COPY ./entrypoint.sh      /app/
COPY ./proxies.nitro.yaml /app/
COPY ./conf/default-config.json    /app/conf/
COPY ./conf/prod-uid2-config.json  /app/conf/
COPY ./conf/integ-uid2-config.json /app/conf/
COPY ./conf/prod-euid-config.json  /app/conf/
COPY ./conf/integ-euid-config.json /app/conf/
COPY ./conf/*.xml                  /app/conf/

RUN chmod +x /app/vsockpx && chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
