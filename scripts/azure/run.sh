if [[ "$1" == "" ]]; then
	set -- occlum run /bin/launcher
fi

vars=
for v in aws_access_key_id aws_secret_access_key core_api_token optout_api_token; do
	if [[ -n "${!v}" ]]; then
		vars="$vars -e $v=${!v}"
	fi
done

tty_arg=
if [[ -t 0 ]]; then
	tty_arg="-it"
fi

docker run \
	${tty_arg} \
	--device /dev/sgx/enclave --device /dev/sgx/provision \
	-p 8080:8080 -p 9091:9091 \
	$vars \
	dev.docker.adsrvr.org/uid2/operator/occlum:dev \
	"$@"

