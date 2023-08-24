#!/usr/bin/env bash
# to facilitate local test

NGROK_TOKEN=2U9hyPLFDbc8nTny7woMOudqAAN_7HiFVXjjcNiVYcXBD1k5w
IMAGE_HASH=sha256:e9ecef00af3e2040cc6746bb107174e7c91cf797596c16132e6686e8c7fcfd52

# copy to a different folder in local to avoid data pollution
cp -rf "./e2e/" "./e2e-target"

cd ./e2e-target

killall ngrok
docker compose down

source ./setup_ngrok.sh
source ./prepare_gcp_enclave_metadata.sh
source ./start_docker.sh
