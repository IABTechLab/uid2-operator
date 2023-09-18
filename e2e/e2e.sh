#!/usr/bin/env bash
set -x
# to facilitate local test

NGROK_TOKEN=
IMAGE_HASH=sha256:ef7291336d10f864e9b4c8bb8aed676127c22df4fa3c14a9f4523811e787902d
CORE_VERSION=2.12.0-a9d204eec0-default
OPTOUT_VERSION=2.6.18-60727cf243-default
SERVICE_ACCOUNT='gcp-oidc-test@uid2-test.iam.gserviceaccount.com'

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
source ./start_gcp_enclave.sh
#source ./stop_gcp_enclave.sh
