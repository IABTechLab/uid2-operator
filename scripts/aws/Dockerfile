# sha from https://hub.docker.com/layers/library/eclipse-temurin/21.0.13_9-jre-resolute/images/sha256-6e994f194cdbcb1372486c2210c7e6381a9b2ad7a813ba96cd7f2c9abec799e9
FROM eclipse-temurin@sha256:6e994f194cdbcb1372486c2210c7e6381a9b2ad7a813ba96cd7f2c9abec799e9

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

# GNU coreutils replaces uutils: the uutils multi-call binary rejects its tools inside the enclave.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends net-tools curl jq cron syslog-ng-core \
    && apt-get install -y --allow-remove-essential coreutils-from-gnu coreutils-from-uutils- rust-coreutils- \
    && apt-get purge -y --autoremove fontconfig fonts-dejavu-core fonts-dejavu-mono \
    && rm -rf /var/lib/apt/lists/*

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./static             /app/static
COPY ./libjnsm.so         /app/lib/
COPY ./vsockpx            /app/
COPY ./entrypoint.sh      /app/
COPY ./proxies.nitro.yaml /app/
COPY ./conf/*.json              /app/conf/
COPY ./conf/*.xml               /app/conf/
COPY ./syslog-ng-client.conf    /etc/syslog-ng/syslog-ng.conf

RUN chmod +x /app/vsockpx && chmod +x /app/entrypoint.sh


CMD ["/app/entrypoint.sh"]
