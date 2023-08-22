#!/usr/bin/env bash
if [ -z "$IMAGE_HASH" ]; then
  echo "IMAGE_HASH can not be empty"
  exit 1
fi

# generate enclave id
enclave_str="V1,true,$IMAGE_HASH"
enclave_id=$(echo -n $full | openssl dgst -sha256 -binary | openssl base64)

METADATA_ROOT="./e2e/docker/localstack/s3/core"

# fetch operator key
OPERATOR_FILE="$METADATA_ROOT/operators/operators.json"
operator_key=$(jq -r '.[] | select(.protocol=="gcp-oidc") | .key' $OPERATOR_FILE)

# update gcp-oidc enclave id
ENCLAVE_FILE="$METADATA_ROOT/enclaves/enclaves.json"
cat <<< $(jq '(.[] | select(.protocol=="gcp-oidc") | .identifier) |='\"$enclave_id\"'' $ENCLAVE_FILE) > $ENCLAVE_FILE

# export to Github output
echo "OPERATOR_KEY=$operator_key" >> $GITHUB_OUTPUT
echo "ENCLAVE_ID=$enclave_id" >> $GITHUB_OUTPUT
