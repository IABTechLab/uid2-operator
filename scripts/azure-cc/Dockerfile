# sha from https://hub.docker.com/layers/amd64/eclipse-temurin/21.0.4_7-jre-alpine/images/sha256-8179ddc8a6c5ac9af935020628763b9a5a671e0914976715d2b61b21881cefca
FROM eclipse-temurin@sha256:8179ddc8a6c5ac9af935020628763b9a5a671e0914976715d2b61b21881cefca

# Install Packages
RUN apk update && apk add jq

WORKDIR /app
EXPOSE 8080
EXPOSE 9080

ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV REGION=default
ENV LOKI_HOSTNAME=loki

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip

RUN pip install --no-cache-dir \
    azure-identity \
    azure-keyvault-secrets

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/*.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

COPY ./azure.py /app/
RUN chmod a+x /app/azure.py

RUN adduser -D uid2-operator && mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads
USER uid2-operator

CMD ["/app/azure.py"]
