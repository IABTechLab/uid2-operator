#!/usr/bin/env bash
set -x

# Following environment variables must be set
# - IMAGE: uid2-operator image
# - IMAGE_DIGEST: uid2-operator image digest
# - OUTPUT_DIR: output directory to store the artifacts
# - MANIFEST_DIR: output directory to store the manifest for the enclave Id
# - VERSION_NUMBER: the version number of the build

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INPUT_DIR=${SCRIPT_DIR}/terraform

if [[ -z ${IMAGE} ]]; then
  echo "IMAGE cannot be empty"
  exit 1
fi

if [[ -z ${IMAGE_DIGEST} ]]; then
  echo "IMAGE_DIGEST cannot be empty"
  exit 1
fi

if [[ -z ${OUTPUT_DIR} ]]; then
  echo "OUTPUT_DIR cannot be empty"
  exit 1
fi

mkdir -p ${OUTPUT_DIR}
if [[ $? -ne 0 ]]; then
  echo "Failed to create ${OUTPUT_DIR}"
  exit 1
fi

mkdir -p ${MANIFEST_DIR}
if [[ $? -ne 0 ]]; then
  echo "Failed to create ${MANIFEST_DIR}"
  exit 1
fi

# Input files
INPUT_FILES=(
  main.tf outputs.tf variables.tf terraform.tfvars
)

# Copy input files to output dir
for f in ${INPUT_FILES[@]}; do
    cp ${INPUT_DIR}/${f} ${OUTPUT_DIR}/${f}
    if [[ $? -ne 0 ]]; then
        echo "Failed to copy ${INPUT_DIR}/${f} to ${OUTPUT_DIR}"
        exit 1
    fi
done

# Update operator tfvars
sed -i "s#IMAGE_PLACEHOLDER#${IMAGE}#g" ${OUTPUT_DIR}/terraform.tfvars
if [[ $? -ne 0 ]]; then
  echo "Failed to pre-process tfvars file"
  exit 1
fi

# Enclave ID file
echo -n "V1,false,$IMAGE_DIGEST" | openssl dgst -sha256 -binary | openssl base64 > ${MANIFEST_DIR}/gcp-oidc-enclave-id-$VERSION_NUMBER.txt
if [[ $? -ne 0 ]]; then
  echo "Failed to generate non-debug enclave ID file"
  exit 1
fi

# Enclave ID file for debug
echo -n "V1,true,$IMAGE_DIGEST" | openssl dgst -sha256 -binary | openssl base64 > ${MANIFEST_DIR}/gcp-oidc-enclave-id-debug-$VERSION_NUMBER.txt
if [[ $? -ne 0 ]]; then
  echo "Failed to generate debug enclave ID file"
  exit 1
fi
