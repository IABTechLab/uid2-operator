FROM maven:3.9.6-eclipse-temurin-11 AS build-operator
WORKDIR /build
COPY src ./src
COPY static ./static
COPY ./pom.xml ./pom.xml

# build operator jar and save package version
RUN mvn package -B -Paws -DskipTests=true \
    && (mvn help:evaluate -Dexpression=project.version | grep -e '^[1-9][^\[]' > ./package.version)

FROM alpine/git AS clone-attestation-aws
WORKDIR /src
RUN git clone https://github.com/IABTechLab/uid2-attestation-aws.git

FROM rust:1.74.1 AS build-attestation-aws
COPY --from=clone-attestation-aws /src/uid2-attestation-aws /build/uid2-attestation-aws
WORKDIR /build
# build libjnsm.so
RUN (cd uid2-attestation-aws/jnsm; cargo build --lib --release; cd ../..) \
    && cp uid2-attestation-aws/jnsm/target/release/libjnsm.so .

FROM alpine/git AS clone-vsockproxy
WORKDIR /src
RUN git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git

FROM debian:bullseye AS build-vsockproxy
RUN apt-get update -y && apt-get install -y build-essential cmake
COPY --from=clone-vsockproxy /src/uid2-aws-enclave-vsockproxy /build/uid2-aws-enclave-vsockproxy
WORKDIR /build
ENV enclave_platform="aws-nitro"
# build vsockpx
RUN mkdir uid2-aws-enclave-vsockproxy/build \
    && (cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../..) \
    && cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx

FROM scratch
COPY --from=build-operator /build/src /src
COPY --from=build-operator /build/static /static
COPY --from=build-operator /build/target /target
COPY --from=build-attestation-aws /build/uid2-attestation-aws /uid2-attestation-aws
COPY --from=build-vsockproxy /build/uid2-aws-enclave-vsockproxy /uid2-aws-enclave-vsockproxy