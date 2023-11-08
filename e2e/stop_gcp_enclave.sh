#!/usr/bin/env bash
set -ex

PROJECT=uid2-test

if [ -z "$GCP_INSTANCE_NAME" ]; then
  echo "GCP_INSTANCE_NAME can not be empty"
  exit 1
fi

if [ -z "$SERVICE_ACCOUNT" ]; then
  echo "SERVICE_ACCOUNT can not be empty"
  exit 1
fi

gcloud config set project $PROJECT

gcloud config set compute/zone asia-southeast1-a

gcloud compute instances delete $GCP_INSTANCE_NAME \
    --quiet
