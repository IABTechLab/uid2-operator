#!/bin/sh
#
# This script must be compatible with Ash (provided in eclipse-temurin Docker image) and Bash

function wait_for_sidecar() {
  url="http://169.254.169.254/ping"
  delay=1

  while true; do
    if wget -q --spider --tries=1 --timeout 5 "$url" > /dev/null; then
      echo "side car started"
      break
    else
      echo "side car not started. Retrying in $delay seconds..."
      sleep $delay
      delay=$((delay + 1))
    fi
  done
}

TMP_FINAL_CONFIG="/tmp/final-config.tmp"

if [ -z "${VAULT_NAME}" ]; then
  echo "VAULT_NAME cannot be empty"
  exit 1
fi

if [ -z "${OPERATOR_KEY_SECRET_NAME}" ]; then
  echo "OPERATOR_KEY_SECRET_NAME cannot be empty"
  exit 1
fi

export azure_vault_name="${VAULT_NAME}"
export azure_secret_name="${OPERATOR_KEY_SECRET_NAME}"

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

cat $FINAL_CONFIG

# delay the start of the operator until the side car has started correctly
wait_for_sidecar

# -- start operator
echo "-- starting java application"
java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -Dvertx-config-path=${FINAL_CONFIG} \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
