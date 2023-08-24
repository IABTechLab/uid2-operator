#!/usr/bin/env bash
set -x
# to facilitate local test

NGROK_TOKEN=
IMAGE_HASH=

# copy to a different folder in local to avoid data pollution
cp -rf "./e2e/" "./e2e-target"

cd ./e2e-target

killall ngrok
docker compose down

source ./setup_ngrok.sh
source ./prepare_gcp_enclave_metadata.sh
source ./start_docker.sh
