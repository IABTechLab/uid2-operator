#!/usr/bin/env bash
set -ex

INPUT_DIR="./azure"
OUT_PUT_DIR="./azure-artifacts"

if [ -z "$IMAGE_VERSION" ]; then
  echo "IMAGE_VERSION can not be empty"
  exit 1
fi

IMAGE="ghcr.io/iabtechlab/uid2-operator:$IMAGE_VERSION"

mkdir -p $OUT_PUT_DIR

INPUT_TEMPLATE_FILE="$INPUT_DIR/template.json"
INPUT_PARAMETERS_FILE="$INPUT_DIR/template.json"
OUTPUT_TEMPLATE_FILE="$OUT_PUT_DIR/template.json"
OUTPUT_PARAMETERS_FILE="$OUT_PUT_DIR/parameters.json"
OUTPUT_POLICY_DIGEST_FILE="$OUT_PUT_DIR/digest.txt"

source ../scripts/azure-cc/generate-deployment-artifacts.sh

if [ -z "$GITHUB_OUTPUT" ]; then
  echo "not in github action"
else
  echo "OUTPUT_TEMPLATE_FILE=$OUTPUT_TEMPLATE_FILE" >> $GITHUB_OUTPUT
  echo "OUTPUT_PARAMETERS_FILE=$OUTPUT_PARAMETERS_FILE" >> $GITHUB_OUTPUT
  echo "OUTPUT_POLICY_DIGEST_FILE=$OUTPUT_POLICY_DIGEST_FILE" >> $GITHUB_OUTPUT
fi