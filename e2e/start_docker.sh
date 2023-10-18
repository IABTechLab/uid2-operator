#!/usr/bin/env bash
set -ex

ROOT="."
CORE_CONFIG_FILE="$ROOT/docker/uid2-core/conf/local-e2e-docker-config.json"
OPTOUT_CONFIG_FILE="$ROOT/docker/uid2-optout/conf/local-e2e-docker-config.json"
COMPOSE_FILE="$ROOT/docker-compose.yml"
OPTOUT_MOUNT="$ROOT/docker/uid2-optout/mount"
OPTOUT_HEALTHCHECK_URL="$NGROK_URL_OPTOUT/ops/healthcheck"

if [ -z "$CORE_VERSION" ]; then
  echo "CORE_VERSION can not be empty"
  exit 1
fi

if [ -z "$OPTOUT_VERSION" ]; then
  echo "OPTOUT_VERSION can not be empty"
  exit 1
fi

if [ -z "$NGROK_URL_LOCALSTACK" ]; then
  echo "NGROK_URL_LOCALSTACK can not be empty"
  exit 1
fi

if [ -z "$NGROK_URL_CORE" ]; then
  echo "NGROK_URL_CORE can not be empty"
  exit 1
fi

if [ -z "$NGROK_URL_OPTOUT" ]; then
  echo "NGROK_URL_OPTOUT can not be empty"
  exit 1
fi

# replace placeholders
sed -i.bak "s#<CORE_VERSION>#$CORE_VERSION#g" $COMPOSE_FILE
sed -i.bak "s#<OPTOUT_VERSION>#$OPTOUT_VERSION#g" $COMPOSE_FILE

source ./jq_helper.sh

# set provide_private_site_data to false to workaround the private site path
jq_inplace_update $CORE_CONFIG_FILE aws_s3_endpoint "$NGROK_URL_LOCALSTACK"
jq_inplace_update $CORE_CONFIG_FILE kms_aws_endpoint "$NGROK_URL_LOCALSTACK"
jq_inplace_update $CORE_CONFIG_FILE core_public_url "$NGROK_URL_CORE"
jq_inplace_update $CORE_CONFIG_FILE optout_url "$NGROK_URL_OPTOUT"
jq_inplace_update_json $CORE_CONFIG_FILE provide_private_site_data false

jq_inplace_update $OPTOUT_CONFIG_FILE aws_s3_endpoint "$NGROK_URL_LOCALSTACK"
jq_inplace_update $OPTOUT_CONFIG_FILE partners_metadata_path "$NGROK_URL_CORE/partners/refresh"
jq_inplace_update $OPTOUT_CONFIG_FILE operators_metadata_path "$NGROK_URL_CORE/operators/refresh"
jq_inplace_update $OPTOUT_CONFIG_FILE core_attest_url "$NGROK_URL_CORE/attest"
jq_inplace_update $OPTOUT_CONFIG_FILE core_public_url "$NGROK_URL_CORE"
jq_inplace_update $OPTOUT_CONFIG_FILE optout_url "$NGROK_URL_OPTOUT"

cat $CORE_CONFIG_FILE
cat $OPTOUT_CONFIG_FILE

mkdir -p "$OPTOUT_MOUNT" && chmod 777 "$OPTOUT_MOUNT"

docker compose -f "$ROOT/docker-compose.yml" up -d
docker ps -a

source "$ROOT/healthcheck.sh"

# health check - for 5 mins
healthcheck "$OPTOUT_HEALTHCHECK_URL" 60 1
