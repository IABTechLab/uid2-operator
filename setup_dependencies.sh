#!/bin/bash

mkdir dependencies
cd dependencies

echo 'enclave-attestation-api: download'
git clone https://$GITHUB_ACCESS_TOKEN@github.com/UnifiedID2/enclave-attestation-api-java.git

VERSION=${1:-"1.0.0"}
GROUP_ID="com.uid2"
ARTIFACT_ID="enclave-attestation-api"

echo 'enclave-attestation-api: build & install'
pushd enclave-attestation-api-java || exit
mvn package && mvn install:install-file -Dfile="./target/$ARTIFACT_ID-$VERSION.jar" -DgroupId="$GROUP_ID" -DartifactId="$ARTIFACT_ID" -Dpackaging=jar -DpomFile="./pom.xml" -Dversion="$VERSION"
popd

echo 'uid2-shared: download'
git clone https://github.com/IABTechLab/uid2-shared.git

VERSION=${1:-"1.0.0"}
GROUP_ID="com.uid2"
ARTIFACT_ID="uid2-shared"

echo 'uid2-shared: build & install'
pushd uid2-shared || exit
mvn package && mvn install:install-file -Dfile="./target/$ARTIFACT_ID-$VERSION.jar" -DgroupId="$GROUP_ID" -DartifactId="$ARTIFACT_ID" -Dpackaging=jar -DpomFile="./pom.xml" -Dversion="$VERSION"
popd

if [ "$enclave_platform" = "aws-nitro" ]
then
    echo 'uid2-attestation-aws: download'
    git clone https://$GITHUB_ACCESS_TOKEN@github.com/UnifiedID2/nsm-java.git

    VERSION=${1:-"1.0.0"}
    GROUP_ID="com.uid2"
    ARTIFACT_ID="attestation-aws"

    echo 'uid2-attestation-aws: build & install'
    pushd nsm-java/attestation-aws || exit
    mvn package && mvn install:install-file -Dfile="./target/$ARTIFACT_ID-$VERSION.jar" -DgroupId="$GROUP_ID" -DartifactId="$ARTIFACT_ID" -Dpackaging=jar -DpomFile="./pom.xml" -Dversion="$VERSION"
    popd

    pushd nsm-java/jnsm || exit
    cargo build --lib --release
    popd

    git clone https://$GITHUB_ACCESS_TOKEN@github.com/UnifiedID2/vsock-skeleton-key.git
    pushd vsock-skeleton-key || exit
    mkdir build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
    make
    popd
    cp vsock-skeleton-key/build/vsock-bridge/src/vsock-bridge vsockpx

elif [ "$enclave_platform" = "gcp-vmid" ]
then
    echo 'uid2-attestation-gcp: download'
    git clone https://$GITHUB_ACCESS_TOKEN@github.com/UnifiedID2/uid2-attestation-gcp.git

    VERSION=${1:-"1.0.0"}
    GROUP_ID="com.uid2"
    ARTIFACT_ID="attestation-gcp"

    echo 'uid2-attestation-gcp: build & install'
    pushd uid2-attestation-gcp || exit
    mvn package && mvn install:install-file -Dfile="./target/$ARTIFACT_ID-$VERSION.jar" -DgroupId="$GROUP_ID" -DartifactId="$ARTIFACT_ID" -Dpackaging=jar -DpomFile="./pom.xml" -Dversion="$VERSION"
    popd
elif [ "$enclave_platform" = "azure-sgx" ]
then
    echo 'uid2-attestation-azure: download'
    git clone https://$GITHUB_ACCESS_TOKEN@github.com/UnifiedID2/uid2-attestation-azure.git

    VERSION=${1:-"1.0.0"}
    GROUP_ID="com.uid2"
    ARTIFACT_ID="attestation-azure"

    echo 'uid2-attestation-azure: build & install'
    pushd uid2-attestation-azure || exit
    ./build.sh
    mvn install:install-file -Dfile="./target/$ARTIFACT_ID-$VERSION.jar" -DgroupId="$GROUP_ID" -DartifactId="$ARTIFACT_ID" -Dpackaging=jar -DpomFile="./pom.xml" -Dversion="$VERSION"
    popd
fi
