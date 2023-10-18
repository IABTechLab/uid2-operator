#!/usr/bin/env bash
set -ex

# below resources should be prepared ahead
RESOURCE_GROUP=uid-enclave-test
IDENTITY=uid-operator
VAULT_NAME=uid-operator
OPERATOR_KEY_NAME=operator-key-ci

LOCATION="East US"
DEPLOYMENT_ENV="integ"
CONTAINER_GROUP_NAME="ci-test-$RANDOM"
DEPLOYMENT_NAME=$CONTAINER_GROUP_NAME

if [ -z "$IDENTITY" ]; then
  echo "IDENTITY can not be empty"
  exit 1
fi

if [ -z "$VAULT_NAME" ]; then
  echo "VAULT_NAME can not be empty"
  exit 1
fi

if [ -z "$OPERATOR_KEY_NAME" ]; then
  echo "OPERATOR_KEY_NAME can not be empty"
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

cat "$AZURE_OUTPUT_PARAMETERS" \
| jq '(.parameters.containerGroupName.value) |='\"$CONTAINER_GROUP_NAME\"'' \
| jq '(.parameters.location.value) |='\""$LOCATION"\"'' \
| jq '(.parameters.identity.value) |='\"$IDENTITY\"'' \
| jq '(.parameters.vaultName.value) |='\"$VAULT_NAME\"'' \
| jq '(.parameters.operatorKeySecretName.value) |='\"$OPERATOR_KEY_NAME\"'' \
| jq '(.parameters.deploymentEnvironment.value) |='\"$DEPLOYMENT_ENV\"'' \
| jq '(.parameters.coreBaseUrl.value) |='\""$NGROK_URL_CORE"\"'' \
| jq '(.parameters.optoutBaseUrl.value) |='\""$NGROK_URL_OPTOUT"\"'' \
| tee "$AZURE_OUTPUT_PARAMETERS"

az deployment group create \
    -g $RESOURCE_GROUP \
    -n $DEPLOYMENT_NAME \
    --template-file "$AZURE_OUTPUT_TEMPLATE"  \
    --parameters "$AZURE_OUTPUT_PARAMETERS"

# export to Github output
echo "CONTAINER_GROUP_NAME=$CONTAINER_GROUP_NAME"

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "CONTAINER_GROUP_NAME=$CONTAINER_GROUP_NAME" >> $GITHUB_OUTPUT
fi

# get public IP, need to trim quotes
ip=$(az deployment group show \
       -g $RESOURCE_GROUP \
       -n $DEPLOYMENT_NAME \
       --query properties.outputs.containerIPv4Address.value | tr -d '"')

echo "instance ip: $ip"

healthcheck_url="http://$ip:8080/ops/healthcheck"

# health check - for 5 mins
healthcheck "$healthcheck_url" 60
