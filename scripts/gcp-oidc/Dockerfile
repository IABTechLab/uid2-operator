# sha from https://hub.docker.com/layers/library/eclipse-temurin/21.0.9_10-jre-alpine-3.23/images/sha256-f599f6fa11f007b6dcf6e85ec2c372c1eba2b6940a7828eb6e665665ea5edd1c
FROM eclipse-temurin@sha256:243e711289b0f17e05a4df60454bbb1b8ed7b126db4de2d5535da994b7417111

LABEL "tee.launch_policy.allow_env_override"="API_TOKEN_SECRET_NAME,DEPLOYMENT_ENVIRONMENT,CORE_BASE_URL,OPTOUT_BASE_URL,DEBUG_MODE,SKIP_VALIDATIONS"
LABEL "tee.launch_policy.log_redirect"="always"

# Install Packages
RUN apk update && apk add --no-cache jq python3 py3-pip && \
    python3 -m venv /venv && \
    . /venv/bin/activate && \
    pip install --no-cache-dir google-cloud-secret-manager google-auth google-api-core packaging && \
    rm -rf /var/cache/apk/*

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

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/*.json /app/conf/
COPY ./conf/*.xml /app/conf/

RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && rm -f /app/static.tar.gz

COPY ./gcp.py /app/
COPY ./confidential_compute.py /app
RUN chmod a+x /app/gcp.py

RUN mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && mkdir -p /app && chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads

CMD ["/venv/bin/python", "/app/gcp.py"]
