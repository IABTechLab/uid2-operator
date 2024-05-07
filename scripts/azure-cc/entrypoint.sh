#!/bin/sh
#
# This script must be compatible with Ash (provided in eclipse-temurin Docker image) and Bash

function wait_for_sidecar() {
  url="http://169.254.169.254/ping"
  delay=0
  max_retries=15

  while true; do
    if wget -q --spider --tries=1 --timeout 5 "$url" > /dev/null; then
      echo "side car started"
      break
    else
      echo "side car not started. Retrying in $delay seconds..."
      sleep $delay
      if [ $delay -gt $max_retries ]; then
        echo "side car failed to start"
        break
      fi
      delay=$((delay + 1))
    fi
  done
}

get_key_vault_secret() {

  while true; do
    # Get the access token from IMDS
    response=$(wget -q -O - --header="Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net")
    
    # Check if we got a response
    if [ -z "$response" ]; then
      echo "Failed to obtain access token. Retrying..."
      sleep 1
      continue
    fi

    # Extract the access token from the response
    access_token=$(echo $response | jq -r '.access_token')

    # Check if we got an access token
    if [ -z "$access_token" ]; then
      echo "Failed to parse access token. Retrying..."
      sleep 1
      continue
    fi

    # Use the access token to call the Key Vault service
    secret_response=$(wget -q -O - --header="Authorization: Bearer $access_token" "https://${VAULT_NAME}.vault.azure.net/secrets/$export azure_secret_name=${OPERATOR_KEY_SECRET_NAME}?api-version=7.0")
    
    # Check if we got a secret response
    if [ -z "$secret_response" ]; then
      echo "Failed to retrieve secret. Retrying..."
      sleep 1
      continue
    fi

    # Extract the secret value from the response
    secret_value=$(echo $secret_response | jq -r '.value')

    # Check if we got a secret value
    if [ -z "$secret_value" ]; then
      echo "Failed to parse secret value. Retrying..."
      sleep 1
      continue
    fi

    echo "Secret Value: $secret_value"
    break
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
get_key_vault_secret

# -- start operator
echo "-- starting java application"
java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=/app/conf/logback.xml \
    -Dvertx-config-path=${FINAL_CONFIG} \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
