# sha from https://hub.docker.com/layers/library/eclipse-temurin/11.0.22_7-jre-alpine/images/sha256-9f5cc9ce5648d8cb873a04cf48e2ab4947dd358c58ec92d4e7645c4c270e889c?context=explore
FROM eclipse-temurin@sha256:2d2275fc2c1e9d507ec2a74df6e925e7eb1a7b633f81e642091673d6b673bfc8

# Install Packages
RUN apk update && apk add jq

WORKDIR /app
EXPOSE 8080

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV REGION=default
ENV LOKI_HOSTNAME=loki

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/*.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

COPY ./entrypoint.sh /app/
RUN chmod a+x /app/entrypoint.sh

RUN adduser -D uid2-operator && mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads
USER uid2-operator

CMD ["/app/entrypoint.sh"]
