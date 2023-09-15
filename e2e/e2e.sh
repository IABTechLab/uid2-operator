#!/usr/bin/env bash
set -x
# to facilitate local test

NGROK_TOKEN=2U9hyPLFDbc8nTny7woMOudqAAN_7HiFVXjjcNiVYcXBD1k5w
IMAGE_HASH=sha256:39274ed4cc3d696bae16183614780617f7bd8b241aa53dac1017ed88b4b6282b
CORE_VERSION=2.12.0-a9d204eec0-default
OPTOUT_VERSION=2.6.18-60727cf243-default

# replace below with your local repo root of uid2-core and uid2-optout
CORE_ROOT="../../uid2-core"
OPTOUT_ROOT="../../uid2-optout"

# copy to a different folder in local to avoid data pollution
cp -rf "./e2e/" "./e2e-target"

cd ./e2e-target

killall ngrok
docker compose down

source ./prepare_conf.sh
source ./setup_ngrok.sh
source ./prepare_gcp_enclave_metadata.sh
source ./start_docker.sh
#source ./start_gcp_enclave.sh
#source ./stop_gcp_enclave.sh
