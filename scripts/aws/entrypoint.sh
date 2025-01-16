#!/bin/bash -eufx

# This is the entrypoint for the Enclave. It is executed in all enclaves - EC2 and EKS

LOG_FILE="/home/start.txt"

set -x
exec &> >(tee -a "$LOG_FILE")

set -o pipefail
ulimit -n 65536

# -- setup loopback device
echo "Setting up loopback device..."
ifconfig lo 127.0.0.1

# -- start vsock proxy
echo "Starting vsock proxy..."
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( ( $(nproc) + 3 ) / 4 )) --log-level 3

/usr/sbin/syslog-ng --verbose

PARAMETERIZED_CONFIG="/app/conf/config-overrides.json"
OPERATOR_CONFIG="/tmp/final-config.json"

build_parameterized_config() {
  curl -s -f -o "${PARAMETERIZED_CONFIG}" -x socks5h://127.0.0.1:3305 http://127.0.0.1:27015/getConfig
  REQUIRED_KEYS=("optout_base_url" "core_base_url" "api_token" "environment")
  for key in "${REQUIRED_KEYS[@]}"; do
    if ! jq -e "has(\"${key}\")" "${PARAMETERIZED_CONFIG}" > /dev/null; then
      echo "Error: Key '${key}' is missing. Please add it to flask config server"
      exit 1
    fi
  done
  FILTER=$(printf '. | {')
  for key in "${REQUIRED_KEYS[@]}"; do
    FILTER+="$key: .${key}, "
  done
  FILTER+="debug_mode: .debug_mode, "
  FILTER=${FILTER%, }'}'
  jq "${FILTER}" "${PARAMETERIZED_CONFIG}" > "${PARAMETERIZED_CONFIG}.tmp" && mv "${PARAMETERIZED_CONFIG}.tmp" "${PARAMETERIZED_CONFIG}"
}

build_operator_config() {
  CORE_BASE_URL=$(jq -r ".core_base_url" < "${PARAMETERIZED_CONFIG}")
  OPTOUT_BASE_URL=$(jq -r ".optout_base_url" < "${PARAMETERIZED_CONFIG}")
  DEPLOYMENT_ENVIRONMENT=$(jq -r ".environment" < "${OPERATOR_CONFIG}")
  DEBUG_MODE=$(jq -r ".debug_mode" < "${OPERATOR_CONFIG}")

  if [[ "$DEPLOYMENT_ENVIRONMENT" == "prod" ]]; then
    if [[ "${IDENTITY_SCOPE}" == "UID2" ]]; then
      CORE_BASE_URL="https://core-prod.uidapi.com"
      OPTOUT_BASE_URL="https://optout-prod.uidapi.com"
    else
      CORE_BASE_URL="https://core.prod.euid.eu"
      OPTOUT_BASE_URL="https://core-prod.uidapi.com"
    fi
    if [[ "$DEPLOYMENT_ENVIRONMENT" == "prod" ]]; then
      echo "Cannot run in DEBUG_MODE in production environment. Exiting."
      exit 1
    fi
  fi

  DEFAULT_CONFIG="/app/conf/uid2-config.json"

  jq -s '.[0] * .[1]' "${DEFAULT_CONFIG}" "${PARAMETERIZED_CONFIG}" > "${OPERATOR_CONFIG}"
  echo "-- replacing URLs by ${CORE_BASE_URL} and ${OPTOUT_BASE_URL}"
  sed -i "s#https://core.uidapi.com#${CORE_BASE_URL}#g" ${OPERATOR_CONFIG}
  sed -i "s#https://optout.uidapi.com#${OPTOUT_BASE_URL}#g" ${OPERATOR_CONFIG}
}

build_parameterized_config
build_operator_config

DEBUG_MODE=$(jq -r ".debug_mode" < "${OPERATOR_CONFIG}")
LOGBACK_CONF="./conf/logback.xml"

if [[ "$DEBUG_MODE" == "true" ]]; then
  LOGBACK_CONF="./conf/logback-debug.xml"
fi

# -- set pwd to /app so we can find default configs
cd /app

# -- start operator
echo "Starting Java application..."

java \
  -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
  -Djava.security.egd=file:/dev/./urandom \
  -Djava.library.path=/app/lib \
  -Dvertx-config-path="${OPERATOR_CONFIG}" \
  -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
  -Dlogback.configurationFile=${LOGBACK_CONF} \
  -Dhttp_proxy=socks5://127.0.0.1:3305 \
  -jar /app/"${JAR_NAME}"-"${JAR_VERSION}".jar
