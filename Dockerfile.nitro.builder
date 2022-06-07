FROM ubuntu:22.04

ENV enclave_platform="aws-nitro"
ARG nsm_java_version=1.0.0
ARG vsock_version=1.0.0

# install build-essential, openjdk, maven, git
RUN apt-get update -y \
    && apt install -y curl -y build-essential pkg-config libssl-dev cmake openjdk-11-jdk maven git \
    && rm -rf /var/lib/apt/lists/*

# install rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
ADD conf ./conf
ADD src ./src
ADD static ./static
COPY ./pom.xml ./pom.xml

# build operator jar and save package version
RUN mvn package -B -Paws -DskipTests=true \
    && (mvn help:evaluate -Dexpression=project.version | grep -e '^[1-9][^\[]' > ./package.version)

# build libjnsm.so
RUN git clone -b v${nsm_java_version} https://github.com/IABTechLab/nsm-java.git \
    && (cd nsm-java/jnsm; cargo build --lib --release; cd ../..) \
    && cp nsm-java/jnsm/target/release/libjnsm.so .

# build vsockpx
RUN git clone -b v${vsock_version} https://github.com/IABTechLab/vsock-skeleton-key.git \
    && mkdir vsock-skeleton-key/build \
    && (cd vsock-skeleton-key/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../..) \
    && cp vsock-skeleton-key/build/vsock-bridge/src/vsock-bridge ./vsockpx
