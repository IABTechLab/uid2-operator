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

#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $CORE_CONFIG_FILE) > $CORE_CONFIG_FILE
#cat <<< $(jq '(.aws_s3_endpoint) |='\"$NGROK_URL_LOCALSTACK\"'' $OPTOUT_CONFIG_FILE) > $OPTOUT_CONFIG_FILE

sed -i.bak "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $CORE_CONFIG_FILE
sed -i.bak "s#<NGROK_URL_LOCALSTACK>#$NGROK_URL_LOCALSTACK#g" $OPTOUT_CONFIG_FILE
sed -i.bak "s#<NGROK_URL_CORE>#$NGROK_URL_CORE#g" $OPTOUT_CONFIG_FILE

chmod 777 $OPTOUT_MOUNT

docker compose -f "$ROOT/docker-compose.yml" up -d
docker ps -a

source "$ROOT/healthcheck.sh"
healthcheck "$OPTOUT_HEALTHCHECK_URL" 20
