#!/usr/bin/env bash
set -ex

ROOT="."
METADATA_ROOT="$ROOT/docker/localstack/s3/core"
OPERATOR_FILE="$METADATA_ROOT/operators/operators.json"
ENCLAVE_FILE="$METADATA_ROOT/enclaves/enclaves.json"

if [ -z "$AZURE_CC_POLICY_DIGEST" ]; then
  echo "AZURE_CC_POLICY_DIGEST can not be empty"
  exit 1
fi

# generate enclave id
enclave_id=$AZURE_CC_POLICY_DIGEST

# fetch operator key
OPERATOR_KEY=$(jq -r '.[] | select(.protocol=="azure-cc") | .key' $OPERATOR_FILE)

# update azure-cc enclave id
cat <<< $(jq '(.[] | select(.protocol=="azure-cc") | .identifier) |='\"$enclave_id\"'' $ENCLAVE_FILE) > $ENCLAVE_FILE

# export to Github output
echo "OPERATOR_KEY=$OPERATOR_KEY"

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "OPERATOR_KEY=$OPERATOR_KEY" >> $GITHUB_OUTPUT
fi
