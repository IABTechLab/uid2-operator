#!/usr/bin/env bash

set -x

dockerd &
while (! docker stats --no-stream >/dev/null 2>&1); do
    # Docker takes a few seconds to initialize
    echo -n "."
    sleep 1
done

docker load -i /$1.tar
nitro-cli build-enclave --docker-uri $1 --output-file $1.eif
