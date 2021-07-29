set -ex

export AZDCAP_DEBUG_LOG_LEVEL=FATAL
/opt/occlum/start_aesm.sh
cd /root/uid2-operator
"$@"
