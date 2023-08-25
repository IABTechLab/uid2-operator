#!/usr/bin/env bash
set -ex

SERVICE_ACCOUNT='github-ci@uid2-test.iam.gserviceaccount.com'
GCP_INSTANCE_NAME="ci-test-$RANDOM"
ROOT="."

source "$ROOT/healthcheck.sh"

if [ -z "$IMAGE_HASH" ]; then
  echo "IMAGE_HASH can not be empty"
  exit 1
fi

if [ -z "$OPERATOR_KEY" ]; then
  echo "OPERATOR_KEY can not be empty"
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

gcloud config set compute/zone us-west1-b

gcloud compute instances create $GCP_INSTANCE_NAME \
    --confidential-compute \
    --shielded-secure-boot \
    --maintenance-policy Terminate \
    --scopes cloud-platform \
    --image-project confidential-space-images \
    --image-family confidential-space-debug \
    --service-account $SERVICE_ACCOUNT \
    --metadata ^~^tee-image-reference=ghcr.io/iabtechlab/uid2-operator@$IMAGE_HASH\~tee-container-log-redirect=true~tee-restart-policy=Never~tee-env-DEPLOYMENT_ENVIRONMENT=integ~tee-env-API_TOKEN=$OPERATOR_KEY~tee-env-CORE_BASE_URL=$NGROK_URL_CORE~tee-env-OPTOUT_BASE_URL=$NGROK_URL_OPTOUT

ip=$(gcloud compute instances describe $GCP_INSTANCE_NAME \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo "instance ip: $ip"

healthcheck_url="http://$ip:8080/ops/healthcheck"

# health check
healthcheck "$healthcheck_url" 20


# export to Github output
echo "GCP_INSTANCE_NAME=$GCP_INSTANCE_NAME"

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "GCP_INSTANCE_NAME=$GCP_INSTANCE_NAME" >> $GITHUB_OUTPUT
fi
