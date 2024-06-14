FROM alpine:3.20

ENV enclave_platform="aws-nitro"

# install build-essential, openjdk, maven, git
RUN apt-get update -y \
    && apt-get install -y curl -y build-essential pkg-config libssl-dev cmake openjdk-21-jdk maven git \
    && rm -rf /var/lib/apt/lists/*

# install rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY src ./src
COPY static ./static
COPY ./pom.xml ./pom.xml

# build operator jar and save package version
RUN mvn package -B -Paws -DskipTests=true \
    && (mvn help:evaluate -Dexpression=project.version | grep -e '^[1-9][^\[]' > ./package.version)

# build libjnsm.so
RUN git clone https://github.com/IABTechLab/uid2-attestation-aws.git \
    && (cd uid2-attestation-aws/jnsm; cargo build --lib --release; cd ../..) \
    && cp uid2-attestation-aws/jnsm/target/release/libjnsm.so .

# build vsockpx
RUN git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git \
    && mkdir uid2-aws-enclave-vsockproxy/build \
    && (cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../..) \
    && cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx
