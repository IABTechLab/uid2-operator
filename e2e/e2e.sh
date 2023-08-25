#!/usr/bin/env bash
set -x
# to facilitate local test

NGROK_TOKEN=
IMAGE_HASH=
CORE_VERSION=2.9.0-46b2d8519f-master-default
OPTOUT_VERSION=2.5.0-80ad3156c0-default

# copy to a different folder in local to avoid data pollution
cp -rf "./e2e/" "./e2e-target"

cd ./e2e-target

killall ngrok
docker compose down

source ./setup_ngrok.sh
source ./prepare_gcp_enclave_metadata.sh
source ./start_docker.sh
#source ./start_gcp_enclave.sh
#source ./stop_gcp_enclave.sh
