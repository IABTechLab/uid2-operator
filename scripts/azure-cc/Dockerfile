# sha from https://hub.docker.com/layers/library/eclipse-temurin/21.0.9_10-jre-alpine-3.23/images/sha256-f599f6fa11f007b6dcf6e85ec2c372c1eba2b6940a7828eb6e665665ea5edd1c
FROM eclipse-temurin@sha256:243e711289b0f17e05a4df60454bbb1b8ed7b126db4de2d5535da994b7417111

# Install necessary packages and set up virtual environment
RUN apk update && apk add --no-cache jq python3 py3-pip && \
    python3 -m venv /venv && \
    . /venv/bin/activate && \
    pip install --no-cache-dir requests azure-identity azure-keyvault-secrets && \
    rm -rf /var/cache/apk/*

# Set virtual environment path
ENV PATH="/venv/bin:$PATH"

# Working directory
WORKDIR /app

# Expose necessary ports
EXPOSE 8080
EXPOSE 9080

# ARG and ENV variables
ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0-SNAPSHOT
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV REGION=default

# Copy application files
COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./target/${JAR_NAME}-${JAR_VERSION}-sources.jar /app
COPY ./target/${JAR_NAME}-${JAR_VERSION}-static.tar.gz /app/static.tar.gz
COPY ./conf/*.json /app/conf/
COPY ./conf/*.xml /app/conf/

# Extract and clean up tar.gz
RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && \
    rm -f /app/static.tar.gz

COPY ./azr.py /app
COPY ./confidential_compute.py /app
RUN chmod a+x /app/*.py

# Create and configure non-root user
RUN adduser -D uid2-operator && \
    mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && \
    chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads

# Switch to non-root user
USER uid2-operator

# Run the Python entry point
CMD python3 /app/azr.py