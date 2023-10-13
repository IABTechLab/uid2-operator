#!/usr/bin/env bash
set -x

# Following environment variables must be set
# - IMAGE: uid2-operator image
# - INPUT_TEMPLATE_FILE: input deployment template file
# - OUTPUT_TEMPLATE_FILE: generated deployment template file
# - OUTPUT_POLICY_DIGEST_FILE: generated policy digest file

if [[ -z ${IMAGE} ]]; then
  echo "IMAGE cannot be empty"
  exit 1
fi

if [[ -z ${INPUT_TEMPLATE_FILE} || ! -f ${INPUT_TEMPLATE_FILE} ]]; then
  echo "INPUT_TEMPLATE_FILE is empty or not exist"
  exit 1
fi

if [[ -z ${OUTPUT_TEMPLATE_FILE} ]]; then
  echo "OUTPUT_TEMPLATE_FILE cannot be empty"
  exit 1
fi

if [[ -z ${OUTPUT_POLICY_DIGEST_FILE} ]]; then
  echo "OUTPUT_POLICY_DIGEST_FILE cannot be empty"
  exit 1
fi

# Install Azure cli
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
if [[ $? -ne 0 ]]; then
  echo "Failed to install Azure cli"
  exit 1
fi

# Install confcom extension
az extension add --name confcom
if [[ $? -ne 0 ]]; then
  echo "Failed to install Azure confcom extension"
  exit 1
fi

sudo usermod -aG docker ${USER} # required by confcom
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
