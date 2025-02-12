# sha from https://hub.docker.com/layers/amd64/eclipse-temurin/21.0.6_7-jre-ubi9-minimal/images/sha256-8ec9c77b1d5979fec8da633da7a66fa5cd26b8b02a96458cecf2809f54c7391e
FROM eclipse-temurin@sha256:5f204213149c5f988b7d8b5532973e13437e23240ed996612d92e25d0e5b782f

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
COPY ./conf/feat-flag/feat-flag.json    /app/conf/feat-flag/

# Extract and clean up tar.gz
RUN tar xzvf /app/static.tar.gz --no-same-owner --no-same-permissions && \
    rm -f /app/static.tar.gz

COPY ./azureEntryPoint.py /app
COPY ./confidential_compute.py /app
RUN chmod a+x /app/*.py

# Create and configure non-root user
RUN adduser -D uid2-operator && \
    mkdir -p /opt/uid2 && chmod 777 -R /opt/uid2 && \
    chmod 705 -R /app && mkdir -p /app/file-uploads && chmod 777 -R /app/file-uploads

# Switch to non-root user
USER uid2-operator

# Run the Python entry point
CMD python3 /app/azureEntryPoint.py