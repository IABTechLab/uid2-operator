#!/bin/sh
#
# This script must be compatible with Ash (provided in eclipse-temurin Docker image) and Bash

# -- set API tokens
if [ -z "${API_TOKEN_SECRET_NAME}" ]; then
  echo "API_TOKEN_SECRET_NAME cannot be empty"
  exit 1
fi

GCP_TOKEN=$(wget "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -q --header "Metadata-Flavor: Google" -O - | jq -e -r ".access_token")
if [ $? -ne 0 -o -z "${GCP_TOKEN}" ]; then
  echo "Failed to get GCP token"
  exit 1
fi

API_TOKEN=$(wget "https://secretmanager.googleapis.com/v1/${API_TOKEN_SECRET_NAME}:access" -q --header "authorization: Bearer ${GCP_TOKEN}" --header "content-type: application/json" -O - | jq -e -r ".payload.data" | base64 -d)
if [ $? -ne 0 -o -z "${API_TOKEN}" ]; then
  echo "Failed to get API token"
  exit 1
fi

export core_api_token="${API_TOKEN}"
export optout_api_token="${API_TOKEN}"

# -- locate config file
if [ -z "${DEPLOYMENT_ENVIRONMENT}" ]; then
  echo "DEPLOYMENT_ENVIRONMENT cannot be empty"
  exit 1
fi
if [ "${DEPLOYMENT_ENVIRONMENT}" != 'prod' -a "${DEPLOYMENT_ENVIRONMENT}" != 'integ' ]; then
  echo "Unrecognized DEPLOYMENT_ENVIRONMENT ${DEPLOYMENT_ENVIRONMENT}"
  exit 1
fi

TARGET_CONFIG="/app/conf/${DEPLOYMENT_ENVIRONMENT}-uid2-config.json"
if [ ! -f "${TARGET_CONFIG}" ]; then
  echo "Unrecognized config ${TARGET_CONFIG}"
  exit 1
fi

FINAL_CONFIG="/tmp/final-config.json"
echo "-- copying ${TARGET_CONFIG} to ${FINAL_CONFIG}"
cp ${TARGET_CONFIG} ${FINAL_CONFIG}
if [ $? -ne 0 ]; then
  echo "Failed to create ${FINAL_CONFIG} with error code $?"
  exit 1
fi

# -- replace base URLs if both CORE_BASE_URL and OPTOUT_BASE_URL are provided
# -- using hardcoded domains is fine because they should not be changed frequently
if [ -n "${CORE_BASE_URL}" -a -n "${OPTOUT_BASE_URL}" -a "${DEPLOYMENT_ENVIRONMENT}" != 'prod' ]; then
    echo "-- replacing URLs by ${CORE_BASE_URL} and ${OPTOUT_BASE_URL}"
    sed -i "s#https://core-integ.uidapi.com#${CORE_BASE_URL}#g" ${FINAL_CONFIG}

    sed -i "s#https://optout-integ.uidapi.com#${OPTOUT_BASE_URL}#g" ${FINAL_CONFIG}
fi

# -- start operator
echo "-- starting java application"
java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=${LOGBACK_CONF} \
    -Dvertx-config-path=${FINAL_CONFIG} \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
