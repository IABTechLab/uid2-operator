# sha from https://hub.docker.com/layers/amd64/eclipse-temurin/21-jre-alpine-3.20/images/sha256-8f44829b456f0185dbc21b3f76bd8798cd6721eacf886fe2881d58326a9e487f
FROM eclipse-temurin@sha256:0f5a0c4a33c7aacf22db45ceed54c4fdfb3b7507d0ff105dd2ee3ebf6469fea3

WORKDIR /app
EXPOSE 8080

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ARG EXTRA_CONFIG
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV REGION=us-east-2

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/default-config.json ${EXTRA_CONFIG} /app/conf/
COPY ./conf/*.xml /app/conf/
COPY ./conf/runtime-config-defaults.json /app/conf/
COPY ./conf/feat-flag/feat-flag.json    /app/conf/feat-flag/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

RUN adduser -D uid2-operator && mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads
USER uid2-operator

CMD java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal -XX:-OmitStackTraceInFastThrow \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
