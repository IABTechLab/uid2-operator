#!/bin/bash -eufx
LOG_FILE="/home/start.txt"

set -x
exec > $LOG_FILE
exec 2>&1

set -o pipefail
ulimit -n 65536

# -- setup loopback device
echo "Setting up loopback device..."
ifconfig lo 127.0.0.1

# -- start vsock proxy
echo "Starting vsock proxy..."
/app/vsockpx --config /app/proxies.nitro.yaml --daemon --workers $(( $(nproc) * 2 )) --log-level 3

# -- setup syslog-ng
echo "Starting syslog-ng..."
/usr/sbin/syslog-ng --verbose

# -- load config from identity service
echo "Loading config from identity service via proxy..."
set +e
#wait for config service
RETRY_COUNT=0
MAX_RETRY=10
while true; do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -x socks5h://127.0.0.1:3305 http://127.0.0.1:27015/getConfig)
  if [ "$RESPONSE" -eq "200" ]; then
      echo "Config server running"
      break;
  else
      echo "Config server still starting..."
  fi
  RETRY_COUNT=$(( RETRY_COUNT + 1))
  if [ $RETRY_COUNT -gt $MAX_RETRY ]; then
      echo "Config Server did not return a response. Exiting"
      exit 1
  fi
  sleep 5

done

{ set +x; } 2>/dev/null; { IDENTITY_SERVICE_CONFIG=$(curl -s -x socks5h://127.0.0.1:3305 http://127.0.0.1:27015/getConfig); set -x; }
if jq -e . >/dev/null 2>&1 <<<"${IDENTITY_SERVICE_CONFIG}"; then
    echo "Identity service returned valid config"
else
    echo "Failed to get a valid config from identity service"
    exit 1
fi
set -e

export OVERRIDES_CONFIG="/app/conf/config-overrides.json"
{ set +x; } 2>/dev/null; { echo "${IDENTITY_SERVICE_CONFIG}" > "${OVERRIDES_CONFIG}"; set -x; }

export DEPLOYMENT_ENVIRONMENT=$(jq -r ".environment" < "${OVERRIDES_CONFIG}")
export CORE_BASE_URL=$(jq -r ".core_base_url" < "${OVERRIDES_CONFIG}")
export OPTOUT_BASE_URL=$(jq -r ".optout_base_url" < "${OVERRIDES_CONFIG}")
echo "DEPLOYMENT_ENVIRONMENT=${DEPLOYMENT_ENVIRONMENT}"
if [ -z "${DEPLOYMENT_ENVIRONMENT}" ]; then
  echo "DEPLOYMENT_ENVIRONMENT cannot be empty"
  exit 1
fi
if [ "${DEPLOYMENT_ENVIRONMENT}" != "prod" ] && [ "${DEPLOYMENT_ENVIRONMENT}" != "integ" ]; then
  echo "Unrecognized DEPLOYMENT_ENVIRONMENT ${DEPLOYMENT_ENVIRONMENT}"
  exit 1
fi

echo "Loading config final..."
export FINAL_CONFIG="/app/conf/config-final.json"
if [ "${IDENTITY_SCOPE}" = "UID2" ]; then
  python3 /app/make_config.py /app/conf/prod-uid2-config.json /app/conf/integ-uid2-config.json ${OVERRIDES_CONFIG} "$(nproc)" > ${FINAL_CONFIG}
elif [ "${IDENTITY_SCOPE}" = "EUID" ]; then
  python3 /app/make_config.py /app/conf/prod-euid-config.json /app/conf/integ-euid-config.json ${OVERRIDES_CONFIG} "$(nproc)" > ${FINAL_CONFIG}
else
  echo "Unrecognized IDENTITY_SCOPE ${IDENTITY_SCOPE}"
  exit 1
fi

# -- replace base URLs if both CORE_BASE_URL and OPTOUT_BASE_URL are provided
# -- using hardcoded domains is fine because they should not be changed frequently
if [ -n "${CORE_BASE_URL}" ] && [ "${CORE_BASE_URL}" != "null" ] && [ -n "${OPTOUT_BASE_URL}" ] && [ "${OPTOUT_BASE_URL}" != "null" ] && [ "${DEPLOYMENT_ENVIRONMENT}" != "prod" ]; then
    echo "Replacing core and optout URLs by ${CORE_BASE_URL} and ${OPTOUT_BASE_URL}..."

    sed -i "s#https://core-integ.uidapi.com#${CORE_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://core-prod.uidapi.com#${CORE_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://core.integ.euid.eu#${CORE_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://core.prod.euid.eu#${CORE_BASE_URL}#g" "${FINAL_CONFIG}"

    sed -i "s#https://optout-integ.uidapi.com#${OPTOUT_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://optout-prod.uidapi.com#${OPTOUT_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://optout.integ.euid.eu#${OPTOUT_BASE_URL}#g" "${FINAL_CONFIG}"
    sed -i "s#https://optout.prod.euid.eu#${OPTOUT_BASE_URL}#g" "${FINAL_CONFIG}"
fi

# -- set pwd to /app so we can find default configs
cd /app

# -- start operator
echo "Starting Java application..."
java \
  -XX:MaxRAMPercentage=95 -XX:-UseCompressedOops -XX:+PrintFlagsFinal \
  -Djava.security.egd=file:/dev/./urandom \
  -Djava.library.path=/app/lib \
  -Dvertx-config-path="${FINAL_CONFIG}" \
  -Dvertx.logger-delegate-factory-class-name=io.vertx.core.logging.SLF4JLogDelegateFactory \
  -Dlogback.configurationFile=./conf/logback.xml \
  -Dhttp_proxy=socks5://127.0.0.1:3305 \
  -jar /app/"${JAR_NAME}"-"${JAR_VERSION}".jar
