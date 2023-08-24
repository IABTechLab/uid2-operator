#!/usr/bin/env bash
set -ex

# TODO: made it configurable
CORE_VERSION=2.9.0-46b2d8519f-master-default
OPTOUT_VERSION=2.5.0-80ad3156c0-default
ROOT="."
CORE_CONFIG_FILE="$ROOT/docker/uid2-core/conf/local-e2e-docker-config.json"
OPTOUT_CONFIG_FILE="$ROOT/docker/uid2-optout/conf/local-e2e-docker-config.json"
COMPOSE_FILE="$ROOT/docker-compose.yml"
OPTOUT_HEALTHCHECK_URL="$NGROK_URL_OPTOUT/ops/healthcheck"

if [ -z "$NGROK_URL_LOCALSTACK" ]; then
  echo "NGROK_URL_LOCALSTACK can not be empty"
  exit 1
fi

if [ -z "$NGROK_URL_OPTOUT" ]; then
  echo "NGROK_URL_OPTOUT can not be empty"
  exit 1
fi

# replace placeholders
sed -i.bak "s#<CORE_VERSION>#$CORE_VERSION#g" $COMPOSE_FILE
sed -i.bak "s#<OPTOUT_VERSION>#$OPTOUT_VERSION#g" $COMPOSE_FILE

#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $CORE_CONFIG_FILE) > $CORE_CONFIG_FILE
#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $OPTOUT_CONFIG_FILE) > $OPTOUT_CONFIG_FILE

sed -i.bak "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $CORE_CONFIG_FILE
sed -i.bak "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $OPTOUT_CONFIG_FILE

OPTOUT_MOUNT="$ROOT/docker/uid2-optout/mount"
ls -l $(dirname $OPTOUT_MOUNT)
chmod 777 $OPTOUT_MOUNT
ls -l $(dirname $OPTOUT_MOUNT)

docker compose -f "$ROOT/docker-compose.yml" up -d
docker ps -a

source "$ROOT/healthcheck.sh"
healthcheck "$OPTOUT_HEALTHCHECK_URL" 20
