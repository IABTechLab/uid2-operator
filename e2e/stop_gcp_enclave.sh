#!/usr/bin/env bash
set -ex

if [ -z "$GCP_PROJECT" ]; then
  echo "GCP_PROJECT can not be empty"
  exit 1
fi

if [ -z "$SERVICE_ACCOUNT" ]; then
  echo "SERVICE_ACCOUNT can not be empty"
  exit 1
fi

if [ -z "$GCP_INSTANCE_NAME" ]; then
  echo "GCP_INSTANCE_NAME can not be empty"
  exit 1
fi

OPERATOR_KEY_SECRET_NAME=$GCP_INSTANCE_NAME

gcloud config set project $GCP_PROJECT

gcloud config set compute/zone asia-southeast1-a

gcloud compute instances delete $GCP_INSTANCE_NAME --quiet

gcloud secrets delete $OPERATOR_KEY_SECRET_NAME --quiet
