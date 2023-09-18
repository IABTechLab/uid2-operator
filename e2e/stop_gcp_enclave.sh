#!/usr/bin/env bash
set -ex

ZONE='asia-southeast1-a'

if [ -z "$SERVICE_ACCOUNT" ]; then
  echo "SERVICE_ACCOUNT can not be empty"
  exit 1
fi

if [ -z "$ZONE_OVERRIDE" ]; then
  ZONE=$ZONE_OVERRIDE
fi

if [ -z "$GCP_INSTANCE_NAME" ]; then
  echo "GCP_INSTANCE_NAME can not be empty"
  exit 1
fi

gcloud config set compute/zone $ZONE

gcloud compute instances delete $GCP_INSTANCE_NAME \
    --quiet
