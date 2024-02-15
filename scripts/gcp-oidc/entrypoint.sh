#!/bin/sh
#
# This script must be compatible with Ash (provided in eclipse-temurin Docker image) and Bash

# for number/boolean
# https://jqlang.github.io/jq/manual/
# --argjson foo 123 will bind $foo to 123.
function jq_inplace_update_json() {
    local file=$1
    local field=$2
    local value=$3
    jq --argjson v "$value" ".$field = \$v" "$file" > tmp.json && mv tmp.json "$file"
}


# -- set API tokens
if [ -z "${API_TOKEN_SECRET_NAME}" ]; then
  echo "API_TOKEN_SECRET_NAME cannot be empty"
  exit 1
fi

export gcp_secret_version_name="${API_TOKEN_SECRET_NAME}"

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

    # -- replace `enforce_https` value to ENFORCE_HTTPS if provided
    if [ "${ENFORCE_HTTPS}" == false ]; then
        echo "-- replacing enforce_https by ${ENFORCE_HTTPS}"
        jq_inplace_update_json $FINAL_CONFIG enforce_https false
    fi

fi


cat $FINAL_CONFIG

# -- start operator
echo "-- starting java application"
java \
    -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
    -Djava.security.egd=file:/dev/./urandom \
    -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
    -Dlogback.configurationFile=${LOGBACK_CONF} \
    -Dvertx-config-path=${FINAL_CONFIG} \
    -jar ${JAR_NAME}-${JAR_VERSION}.jar
