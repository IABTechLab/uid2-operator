FROM ubuntu:18.04

ENV GITHUB_ACCESS_TOKEN=${GITHUB_ACCESS_TOKEN}
ENV enclave_platform="aws-nitro"

# install openjdk & maven
RUN apt update -y && apt install openjdk-11-jdk -y && apt install maven -y
# install rust
RUN curl https://sh.rustup.rs -sSf | sh

WORKDIR /build
COPY conf .
COPY src .
COPY static .
COPY setup_dependencies.sh .
COPY ./scripts/aws/pom.nitro.xml ./pom.xml
RUN chmod +x ./setup_dependencies.sh
RUN mvn package