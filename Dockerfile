# sha from https://hub.docker.com/layers/library/eclipse-temurin/21.0.8_9-jre-alpine-3.22/images/sha256-3408c45e1faee20e4e68808939a75f87efa469b927d20e12309689ead053daba
FROM eclipse-temurin@sha256:89517925fa675c6c4b770bee7c44d38a7763212741b0d6fca5a5103caab21a97

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

RUN adduser -D uid2-operator && mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads && mkdir -p /app/pod_terminating && chmod 777 -R /app/pod_terminating
USER uid2-operator

CMD java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal -XX:-OmitStackTraceInFastThrow \
    -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints \
    -XX:FlightRecorderOptions=stackdepth=512 \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
