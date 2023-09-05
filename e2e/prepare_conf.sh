#!/usr/bin/env bash
set -ex

ROOT="."
CORE_CONFIG_FILE="$ROOT/docker/uid2-core/conf/local-e2e-docker-config.json"
OPTOUT_CONFIG_FILE="$ROOT/docker/uid2-optout/conf/local-e2e-docker-config.json"

if [ -z "$CORE_ROOT" ]; then
  echo "CORE_ROOT can not be empty"
  exit 1
fi

if [ -z "$OPTOUT_ROOT" ]; then
  echo "CORE_ROOT can not be empty"
  exit 1
fi

cp "$CORE_ROOT/conf/local-e2e-docker-config.json" "$CORE_CONFIG_FILE"
cp "$OPTOUT_ROOT/conf/local-e2e-docker-config.json" "$OPTOUT_CONFIG_FILE"
