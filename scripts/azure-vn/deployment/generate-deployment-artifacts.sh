#!/usr/bin/env bash
set -x

# Following environment variables must be set
# - IMAGE: uid2-operator image
# - OUTPUT_DIR: output directory to store the artifacts
# - MANIFEST_DIR: output directory to store the manifest for the enclave Id
# - VERSION_NUMBER: the version number of the build

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

mkdir -p ${MANIFEST_DIR}
if [[ $? -ne 0 ]]; then
  echo "Failed to create ${MANIFEST_DIR}"
  exit 1
fi

# Input files
INPUT_FILES=(
    operator.yaml
)

# Copy input files to output dir
for f in ${INPUT_FILES[@]}; do
    cp ${INPUT_DIR}/${f} ${OUTPUT_DIR}/${f}
    if [[ $? -ne 0 ]]; then
        echo "Failed to copy ${INPUT_DIR}/${f} to ${OUTPUT_DIR}"
        exit 1
    fi
done

az version
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
sed -i "s#IMAGE_PLACEHOLDER#${IMAGE}#g" ${OUTPUT_DIR}/operator.yaml
# && \
#   sed -i "s#IMAGE_VERSION_PLACEHOLDER#${IMAGE_VERSION}#g" ${OUTPUT_DIR}/operator.yaml
if [[ $? -ne 0 ]]; then
  echo "Failed to pre-process operator template file"
  exit 1
fi

# Export the policy, update it to turn off allow_environment_variable_dropping, and then insert it into the template
# note that the EnclaveId is generated by generate.py on the raw policy, not the base64 version
POLICY_DIGEST_FILE=azure-vn-operator-digest-$VERSION_NUMBER.txt
az confcom acipolicygen --virtual-node-yaml ${OUTPUT_DIR}/operator.yaml --print-policy > ${INPUT_DIR}/policy.base64
if [[ $? -ne 0 ]]; then
  echo "Failed to generate ACI policy"
  exit 1
fi

base64 -di < ${INPUT_DIR}/policy.base64 > ${INPUT_DIR}/generated.rego
sed -i "s#allow_environment_variable_dropping := true#allow_environment_variable_dropping := false#g" ${INPUT_DIR}/generated.rego
sed -i 's#{"pattern":"DEPLOYMENT_ENVIRONMENT=DEPLOYMENT_ENVIRONMENT_PLACEHOLDER","required":false,"strategy":"string"}#{"pattern":"DEPLOYMENT_ENVIRONMENT=.+","required":false,"strategy":"re2"}#g' generated.rego
sed -i 's#{"pattern":"VAULT_NAME=VAULT_NAME_PLACEHOLDER","required":false,"strategy":"string"}#{"pattern":"VAULT_NAME=.+","required":false,"strategy":"re2"}#g' generated.rego
sed -i 's#{"pattern":"OPERATOR_KEY_SECRET_NAME=OPERATOR_KEY_SECRET_NAME_PLACEHOLDER","required":false,"strategy":"string"}#{"pattern":"OPERATOR_KEY_SECRET_NAME=.+","required":false,"strategy":"re2"}#g' generated.rego
base64 -w0 < ${INPUT_DIR}/generated.rego > ${INPUT_DIR}/generated.rego.base64
python3 ${SCRIPT_DIR}/generate.py ${INPUT_DIR}/generated.rego > ${MANIFEST_DIR}/${POLICY_DIGEST_FILE}

sed -i "s#CCE_POLICY_PLACEHOLDER#$(cat ${INPUT_DIR}/generated.rego.base64)#g" ${OUTPUT_DIR}/operator.yaml
# cp ${OUTPUT_DIR}/operator.json ${INPUT_DIR}/source.json
# jq --arg policy "$(cat ${INPUT_DIR}/generated.rego.base64)" '.resources[].properties.confidentialComputeProperties.ccePolicy = $policy' ${INPUT_DIR}/source.json > ${OUTPUT_DIR}/operator.json

