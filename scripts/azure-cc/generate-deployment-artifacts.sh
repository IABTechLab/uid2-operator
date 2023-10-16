#!/usr/bin/env bash
set -x

# Following environment variables must be set
# - IMAGE: uid2-operator image

# Following environment variables may be set
# - INPUT_TEMPLATE_FILE: deployment template file, default is deployment-template.json in this script's directory
# - OUTPUT_TEMPLATE_FILE: generated deployment template file, default is uid2-operator-deployment-template.json
# - OUTPUT_PARAMETERS_FILE: generated deployment parameters file, default is uid2-operator-deployment-parameters.json
# - OUTPUT_POLICY_DIGEST_FILE: generated policy digest file, default is uid2-operator-deployment-digest.txt

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [[ -z ${IMAGE} ]]; then
  echo "IMAGE cannot be empty"
  exit 1
fi

if [[ -z ${INPUT_TEMPLATE_FILE} ]]; then
  INPUT_TEMPLATE_FILE=${SCRIPT_DIR}/deployment-template.json
fi
if [[ ! -f ${INPUT_TEMPLATE_FILE} ]]; then
  echo "INPUT_TEMPLATE_FILE does not exist"
  exit 1
fi

if [[ -z ${OUTPUT_TEMPLATE_FILE} ]]; then
  OUTPUT_TEMPLATE_FILE=uid2-operator-deployment-template.json
fi

if [[ -z ${OUTPUT_PARAMETERS_FILE} ]]; then
  OUTPUT_PARAMETERS_FILE=uid2-operator-deployment-parameters.json
fi

if [[ -z ${OUTPUT_POLICY_DIGEST_FILE} ]]; then
  OUTPUT_POLICY_DIGEST_FILE=uid2-operator-deployment-digest.txt
fi

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

# Generate deployment template
sed "s#IMAGE_PLACEHOLDER#${IMAGE}#g" ${INPUT_TEMPLATE_FILE} > ${OUTPUT_TEMPLATE_FILE}
if [[ $? -ne 0 ]]; then
  echo "Failed to pre-process template file"
  exit 1
fi

az confcom acipolicygen --approve-wildcards --template-file ${OUTPUT_TEMPLATE_FILE} > ${OUTPUT_POLICY_DIGEST_FILE}
if [[ $? -ne 0 ]]; then
  echo "Failed to generate template file"
  exit 1
fi

cp ${SCRIPT_DIR}/deployment-parameters.json ${OUTPUT_PARAMETERS_FILE}
