# sha from https://hub.docker.com/layers/library/eclipse-temurin/21.0.9_10-jre-alpine-3.23/images/sha256-79f8eb45e1219ce03b48d045b1ee920ea529acceb7ff2be6fad7b0b5cb6f07e0
FROM eclipse-temurin@sha256:79f8eb45e1219ce03b48d045b1ee920ea529acceb7ff2be6fad7b0b5cb6f07e0

# Install necessary packages and set up virtual environment
RUN apk update && apk add --no-cache --upgrade libpng && apk add --no-cache jq python3 py3-pip && \
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