# sha from https://hub.docker.com/layers/library/eclipse-temurin/21-jre-alpine-3.23/images/sha256-693c22ea458d62395bac47a2da405d0d18c77b205211ceec4846a550a37684b6
FROM eclipse-temurin:21-jdk-alpine

# For Amazon Corretto Crypto Provider
RUN apk add --no-cache gcompat

WORKDIR /app
EXPOSE 8080

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV REGION=us-east-2

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/default-config.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

RUN useradd -r uid2-operator && mkdir -p /opt/uid2 && chmod -R 777 /opt/uid2 && mkdir -p /app && chmod -R 705 /app && mkdir -p /app/file-uploads && chmod -R 777 /app/file-uploads && mkdir -p /app/pod_terminating && chmod -R 777 /app/pod_terminating
USER uid2-operator

CMD java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal -XX:-OmitStackTraceInFastThrow \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar