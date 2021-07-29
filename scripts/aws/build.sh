#!/bin/bash

set -o xtrace

rm *.eif
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)

CONTAINER_NAME=$1
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME
docker rmi -f $CONTAINER_NAME

docker build -t $CONTAINER_NAME .
nitro-cli build-enclave --docker-uri $CONTAINER_NAME --output-file $CONTAINER_NAME.eif
