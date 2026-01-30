#!/bin/bash -eufx

# This is the entrypoint for the Enclave. It is executed in all enclaves - EC2 and EKS

LOG_FILE="/home/start.txt"

set -x
exec &> >(tee -a "$LOG_FILE")

PARAMETERIZED_CONFIG="/app/conf/config-overrides.json"
OPERATOR_CONFIG="/tmp/final-config.json"

set -o pipefail
ulimit -n 65536

# -- setup loopback device
echo "Setting up loopback device..."
ifconfig lo 127.0.0.1
/usr/sbin/syslog-ng --verbose

# -- start vsock proxy
echo "Starting vsock proxy..."
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( ( $(nproc) + 3 ) / 4 )) --log-level 3

TIME_SYNC_URL="http://127.0.0.1:27015/getCurrentTime"
TIME_SYNC_PROXY="socks5h://127.0.0.1:3305"

TIME_SYNC_OFFSET_SECONDS="${TIME_SYNC_OFFSET_SECONDS:-30}"

sync_enclave_time_with_offset_once() {
  local current_time
  local parent_epoch
  if current_time=$(curl -s -f -x socks5h://127.0.0.1:3305 "${TIME_SYNC_URL}"); then
    parent_epoch=$(date -u -d "${current_time}" +%s 2>/dev/null || true)
    if [[ -n "${parent_epoch}" ]]; then
      parent_epoch=$((parent_epoch + TIME_SYNC_OFFSET_SECONDS))
      if ! date -u -s "@${parent_epoch}"; then
        echo "Time sync: failed to set enclave time from '${current_time}' with offset ${TIME_SYNC_OFFSET_SECONDS}s"
        return 1
      fi
      echo "Time sync: updated enclave time to ${current_time} + ${TIME_SYNC_OFFSET_SECONDS}s"
    fi
  else
    echo "Time sync: failed to fetch time from parent instance"
    return 1
  fi
}

sync_enclave_time_with_offset_once || true

install_time_sync_cron() {
  mkdir -p /etc/cron.d
  cat > /etc/cron.d/uid-time-sync <<EOF
*/5 * * * * root current_time=\$(curl -sSf -x "${TIME_SYNC_PROXY}" "${TIME_SYNC_URL}") && date -u -s "\${current_time}" && echo "Time sync: updated enclave time to \${current_time}" >>/home/start.txt 2>&1
EOF
  chmod 0644 /etc/cron.d/uid-time-sync
  cron
}

install_time_sync_cron

build_parameterized_config() {
  curl -s -f -o "${PARAMETERIZED_CONFIG}" -x socks5h://127.0.0.1:3305 http://127.0.0.1:27015/getConfig
  REQUIRED_KEYS=("optout_base_url" "core_base_url" "core_api_token" "optout_api_token" "environment" "uid_instance_id_prefix")
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
  DEPLOYMENT_ENVIRONMENT=$(jq -r ".environment" < "${PARAMETERIZED_CONFIG}")
  DEBUG_MODE=$(jq -r ".debug_mode" < "${PARAMETERIZED_CONFIG}")

  IDENTITY_SCOPE_LOWER=$(echo "${IDENTITY_SCOPE}" | tr '[:upper:]' '[:lower:]')
  DEPLOYMENT_ENVIRONMENT_LOWER=$(echo "${DEPLOYMENT_ENVIRONMENT}" | tr '[:upper:]' '[:lower:]')
  DEFAULT_CONFIG="/app/conf/${IDENTITY_SCOPE_LOWER}-${DEPLOYMENT_ENVIRONMENT_LOWER}-config.json"

  jq -s '.[0] * .[1]' "${DEFAULT_CONFIG}" "${PARAMETERIZED_CONFIG}" > "${OPERATOR_CONFIG}"

  if [[ "$DEPLOYMENT_ENVIRONMENT" == "prod" ]]; then
    if [[ "$DEBUG_MODE" == "true" ]]; then
      echo "Cannot run in DEBUG_MODE in production environment. Exiting."
      exit 1
    fi
  fi

  #TODO: Remove below logic after remote config management is implemented

  if [[ "$DEPLOYMENT_ENVIRONMENT" != "prod" ]]; then
    #Allow override of base URL in non-prod environments
    CORE_PATTERN="https://core.*uidapi.com"
    OPTOUT_PATTERN="https://optout.*uidapi.com"
    if [[ "$IDENTITY_SCOPE_LOWER" == "euid" ]]; then
      CORE_PATTERN="https://core.*euid.eu"
      OPTOUT_PATTERN="https://optout.*euid.eu"
    fi
    sed -i "s#${CORE_PATTERN}#${CORE_BASE_URL}#g" "${OPERATOR_CONFIG}"
    sed -i "s#${OPTOUT_PATTERN}#${OPTOUT_BASE_URL}#g" "${OPERATOR_CONFIG}"
  fi
  
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

