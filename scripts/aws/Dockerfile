FROM eclipse-temurin:21-jre-noble

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

# apt is purged because nothing uses it at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends net-tools curl jq cron syslog-ng-core \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg --purge --force-remove-essential --force-remove-protected --force-depends apt libapt-pkg6.0t64

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
