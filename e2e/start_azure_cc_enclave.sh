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

if [[ ! -f $OUTPUT_TEMPLATE_FILE ]]; then
  echo "OUTPUT_TEMPLATE_FILE does not exist"
  exit 1
fi

if [[ ! -f $OUTPUT_PARAMETERS_FILE ]]; then
  echo "OUTPUT_PARAMETERS_FILE does not exist"
  exit 1
fi

source ./jq_helper.sh
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.containerGroupName.value "$CONTAINER_GROUP_NAME"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.location.value "$LOCATION"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.identity.value "$IDENTITY"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.vaultName.value "$VAULT_NAME"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.operatorKeySecretName.value "$OPERATOR_KEY_NAME"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.deploymentEnvironment.value "$DEPLOYMENT_ENV"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.coreBaseUrl.value "$NGROK_URL_CORE"
jq_inplace_update $OUTPUT_PARAMETERS_FILE parameters.optoutBaseUrl.value "$NGROK_URL_OPTOUT"

cat $OUTPUT_PARAMETERS_FILE

az deployment group create \
    -g $RESOURCE_GROUP \
    -n $DEPLOYMENT_NAME \
    --template-file "$OUTPUT_TEMPLATE_FILE"  \
    --parameters @"$OUTPUT_PARAMETERS_FILE"

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
