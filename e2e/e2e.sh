#!/usr/bin/env bash
set -x
# to facilitate local test

# common configs for all enclaves
NGROK_TOKEN=2U9hyPLFDbc8nTny7woMOudqAAN_7HiFVXjjcNiVYcXBD1k5w
CORE_VERSION=2.14.5-SNAPSHOT-default
OPTOUT_VERSION=2.6.18-60727cf243-default

# GCP OIDC enclave configs
TEST_GCP_OIDC=false
IMAGE_HASH=

# Azure CC enclave configs
TEST_AZURE_CC=true
# TODO(lun.wang) eventually digest may be derived via IMAGE_HASH, and no need to be explicitly set
AZURE_CC_POLICY_DIGEST=3e1f6eb87bd7b73c618cd1522abbb2d3a8a1baf50c10c78a186db347b962e331

# replace below with your local repo root of uid2-core and uid2-optout
CORE_ROOT="../../uid2-core"
OPTOUT_ROOT="../../uid2-optout"

# copy to a different folder in local to avoid data pollution
rm -rf "./e2e-target"
cp -rf "./e2e/" "./e2e-target"

cd ./e2e-target

killall ngrok
docker compose down

source ./prepare_conf.sh
source ./setup_ngrok.sh

if [ "$TEST_GCP_OIDC" = true ]; then
    source ./prepare_gcp_enclave_metadata.sh
fi

if [ "$TEST_AZURE_CC" = true ]; then
    source ./prepare_azure_cc_enclave_metadata.sh
fi

source ./start_docker.sh

if [ "$TEST_GCP_OIDC" = true ]; then
    source ./start_gcp_enclave.sh
    #source ./stop_gcp_enclave.sh
fi

if [ "$TEST_AZURE_CC" = true ]; then
    source ./start_azure_cc_enclave.sh
    #source ./stop_azure_cc_enclave.sh
fi
