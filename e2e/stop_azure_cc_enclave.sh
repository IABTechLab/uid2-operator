#!/usr/bin/env bash
set -ex

RESOURCE_GROUP=uid-enclave-test

if [ -z "$CONTAINER_GROUP_NAME" ]; then
  echo "CONTAINER_GROUP_NAME can not be empty"
  exit 1
fi

az container delete \
  -g $RESOURCE_GROUP \
  -n $CONTAINER_GROUP_NAME -y
