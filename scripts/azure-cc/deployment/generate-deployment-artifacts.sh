#!/usr/bin/env bash
set -x

# Following environment variables must be set
# - IMAGE: uid2-operator image
# - OUTPUT_DIR: output directory to store the artifacts
# - MANIFEST_DIR: output directory to store the manifest for the enclave Id

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INPUT_DIR=${SCRIPT_DIR}

if [[ -z ${IMAGE} ]]; then
  echo "IMAGE cannot be empty"
  exit 1
fi
IMAGE_VERSION=$(echo $IMAGE | awk -F':' '{print $2}')
if [[ -z ${IMAGE_VERSION} ]]; then
  echo "Failed to extract image version from ${IMAGE}"
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

# Input files
INPUT_FILES=(
    operator.json operator.parameters.json
    vault.json vault.parameters.json
    vnet.json vnet.parameters.json
    gateway.json gateway.parameters.json
)

# Copy input files to output dir
for f in ${INPUT_FILES[@]}; do
    cp ${INPUT_DIR}/${f} ${OUTPUT_DIR}/${f}
    if [[ $? -ne 0 ]]; then
        echo "Failed to copy ${INPUT_DIR}/${f} to ${OUTPUT_DIR}"
        exit 1
    fi
done

# Install confcom extension, az is originally available in GitHub workflow environment
az extension add --name confcom
if [[ $? -ne 0 ]]; then
  echo "Failed to install Azure confcom extension"
  exit 1
fi

# Required by az confcom
sudo usermod -aG docker ${USER}
if [[ $? -ne 0 ]]; then
  echo "Failed to add current user to docker group"
  exit 1
fi

# Generate operator template
sed -i "s#IMAGE_PLACEHOLDER#${IMAGE}#g" ${OUTPUT_DIR}/operator.json && \
  sed -i "s#IMAGE_VERSION_PLACEHOLDER#${IMAGE_VERSION}#g" ${OUTPUT_DIR}/operator.json
if [[ $? -ne 0 ]]; then
  echo "Failed to pre-process operator template file"
  exit 1
fi

POLICY_DIGEST_FILE=azure-cc-operator-digest.txt
az confcom acipolicygen --approve-wildcards --template-file ${OUTPUT_DIR}/operator.json > ${MANIFEST_DIR}/${POLICY_DIGEST_FILE}
if [[ $? -ne 0 ]]; then
  echo "Failed to generate operator template file"
  exit 1
fi
