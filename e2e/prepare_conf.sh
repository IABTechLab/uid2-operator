#!/usr/bin/env bash
set -ex

ROOT="."
CORE_CONFIG_FILE_DIR="$ROOT/docker/uid2-core/conf"
OPTOUT_CONFIG_FILE_DIR="$ROOT/docker/uid2-optout/conf"

if [ -z "$CORE_ROOT" ]; then
  echo "CORE_ROOT can not be empty"
  exit 1
fi

if [ -z "$OPTOUT_ROOT" ]; then
  echo "$OPTOUT_ROOT can not be empty"
  exit 1
fi

mkdir -p "$CORE_CONFIG_FILE_DIR" && cp "$CORE_ROOT/conf/local-e2e-docker-config.json" "$CORE_CONFIG_FILE_DIR"
mkdir -p "$OPTOUT_CONFIG_FILE_DIR" && cp "$OPTOUT_ROOT/conf/local-e2e-docker-config.json" "$OPTOUT_CONFIG_FILE_DIR"
