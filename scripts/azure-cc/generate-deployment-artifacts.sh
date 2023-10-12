#!/usr/bin/env bash
set -x

# Install Azure cli
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install confcom extension
az extension add --name confcom

# Generate deployment template
sed "s#IMAGE_PLACEHOLDER#${IMAGE}#g" ${INPUT_TEMPLATE_FILE} > ${OUTPUT_TEMPLATE_FILE}
az confcom acipolicygen --approve-wildcards --template-file ${OUTPUT_TEMPLATE_FILE}
