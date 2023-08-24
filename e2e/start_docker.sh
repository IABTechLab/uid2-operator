#!/usr/bin/env bash
source ./e2e/healthcheck.sh

if [ -z "$NGROK_URL_LOCALSTACK" ]; then
  echo "NGROK_URL_LOCALSTACK can not be empty"
  exit 1
fi

if [ -z "$NGROK_URL_OPTOUT" ]; then
  echo "NGROK_URL_OPTOUT can not be empty"
  exit 1
fi

# TODO: made it configurable
CORE_VERSION=2.9.0-46b2d8519f-master-default
OPTOUT_VERSION=2.5.0-80ad3156c0-default

ROOT="."

# replace placeholders
COMPOSE_FILE="$ROOT/docker-compose.yml"
gsed -i "s#<CORE_VERSION>#$CORE_VERSION#g" $COMPOSE_FILE
gsed -i "s#<OPTOUT_VERSION>#$OPTOUT_VERSION#g" $COMPOSE_FILE

CORE_CONFIG_FILE="$ROOT/docker/uid2-core/conf/local-e2e-docker-config.json"
OPTOUT_CONFIG_FILE="$ROOT/docker/uid2-optout/conf/local-e2e-docker-config.json"

#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $CORE_CONFIG_FILE) > $CORE_CONFIG_FILE
#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $OPTOUT_CONFIG_FILE) > $OPTOUT_CONFIG_FILE

echo $NGROK_URL_LOCALSTACK

gsed -i "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $CORE_CONFIG_FILE
gsed -i "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $OPTOUT_CONFIG_FILE

docker compose -f "$ROOT/docker-compose.yml" up -d

OPT_OUT_HEALTHCHECK_URL="$NGROK_URL_OPTOUT/ops/healthcheck"

healthcheck "$OPT_OUT_HEALTHCHECK_URL" 20
