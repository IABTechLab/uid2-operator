FROM ubuntu:18.04

ARG GITHUB_ACCESS_TOKEN
ENV GITHUB_ACCESS_TOKEN=${GITHUB_ACCESS_TOKEN}
ENV enclave_platform="aws-nitro"

RUN apt update -y
RUN apt install curl -y && apt install build-essential -y && apt install pkg-config libssl-dev -y
# install openjdk & maven
RUN apt install openjdk-11-jdk -y && apt install maven -y
# install rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
# install git
RUN apt install git -y

WORKDIR /build
COPY conf .
COPY src .
COPY static .
COPY setup_dependencies.sh .
COPY ./scripts/aws/pom.nitro.xml ./pom.xml
RUN chmod +x ./setup_dependencies.sh
RUN ./setup_dependencies.sh
RUN mvn package
