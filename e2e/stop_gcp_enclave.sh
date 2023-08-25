#!/usr/bin/env bash
set -ex

SERVICE_ACCOUNT='github-ci@uid2-test.iam.gserviceaccount.com'

if [ -z "$GCP_INSTANCE_NAME" ]; then
  echo "GCP_INSTANCE_NAME can not be empty"
  exit 1
fi

gcloud config set compute/zone us-west1-b

gcloud compute instances delete $GCP_INSTANCE_NAME \
    --quiet
