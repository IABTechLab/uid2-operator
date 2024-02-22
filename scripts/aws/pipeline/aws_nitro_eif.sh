#!/usr/bin/env bash

set -x

cd /

# Build dante
wget https://www.inet.no/dante/files/dante-1.4.3.tar.gz
echo "418a065fe1a4b8ace8fbf77c2da269a98f376e7115902e76cda7e741e4846a5d dante-1.4.3.tar.gz" > dante_checksum
sha256sum --check dante_checksum
tar -xf dante-1.4.3.tar.gz
cd dante-1.4.3; ./configure; make; cd ..
cp dante-1.4.3/sockd/sockd ./

# Build vsockpx
git clone https://github.com/IABTechLab/uid2-aws-enclave-vsockproxy.git
mkdir uid2-aws-enclave-vsockproxy/build
cd uid2-aws-enclave-vsockproxy/build; cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo; make; cd ../..
cp uid2-aws-enclave-vsockproxy/build/vsock-bridge/src/vsock-bridge ./vsockpx

# Build EIF
dockerd &
while (! docker stats --no-stream >/dev/null 2>&1); do
    # Docker takes a few seconds to initialize
    echo -n "."
    sleep 1
done
docker load -i $1.tar
nitro-cli build-enclave --docker-uri $1 --output-file $1.eif
nitro-cli describe-eif --eif-path $1.eif | jq -r '.Measurements.PCR0' | xxd -r -p | base64 > pcr0.txt
