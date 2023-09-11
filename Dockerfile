FROM eclipse-temurin@sha256:dbd4a0ae12008221aac0c6cac9d7afd4d376de2481f9fe234dfa1e06b6a499a0

WORKDIR /app
EXPOSE 8080

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV LOGBACK_CONF=${LOGBACK_CONF:-./conf/logback.xml}

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/default-config.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

RUN adduser -D uid2-operator && mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads
USER uid2-operator

CMD java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=${LOGBACK_CONF} \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
