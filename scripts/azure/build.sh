set -ex

config="${1-local}"; shift
enable_docker_push=
jar_version=1.0.0
git_commit="$(git show --format="%h" --no-patch)"
build_container_name=dev.docker.adsrvr.org/uid2/occlum-build:dev
container_name=dev.docker.adsrvr.org/uid2/operator/occlum
container_version=${jar_version}.${git_commit}
occlum_glibc=/opt/occlum/glibc/lib
work_dir="${PWD}"
tty_arg=
if [[ -t 0 ]]; then
	tty_arg="-it"
fi

fast_build=
while [[ -n "$1" ]]; do
	case "$1" in
		--push)
			enable_docker_push=1
			;;
		--build-version)
			container_version=${container_version}.$2
			shift
			;;
		--fast)
			fast_build=1
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 1
			;;
	esac

	shift
done

docker_run()
{
	docker run ${tty_arg} -w "${PWD}" -v "${work_dir}:${work_dir}" -u $(id -u ${USER}):$(id -g ${USER}) $build_container_name "$@"
}

docker_run_root()
{
	docker run ${tty_arg} -w "${PWD}" -v "${work_dir}:${work_dir}" $build_container_name "$@"
}

docker_run_root rm -rf build
mkdir -p build/uid2-operator
pushd build/uid2-operator

docker_run occlum init
mkdir -p image/hostetc
mkdir -p image/usr/lib
mkdir -p image/app
mkdir -p image/app/conf
mkdir -p image/app/static
mkdir -p image/$occlum_glibc
mkdir -p image/etc/ssl

ln -sf /hostetc/resolv.conf image/etc/resolv.conf
ln -sf /hostetc/nsswitch.conf image/etc/nsswitch.conf
cp $work_dir/../../target/uid2-operator-${jar_version}-jar-with-dependencies.jar image/app/uid2-operator.jar
cp $work_dir/conf/${config}-config.json image/app/conf/config.json
docker_run occlum-g++ -std=c++17 -ggdb $work_dir/src/launcher.cc -o image/bin/launcher
cp $work_dir/../../dependencies/uid2-attestation-azure/target/bin/sgx_quote image/bin/sgx_quote
cp $work_dir/../../dependencies/uid2-attestation-azure/target/bin/libazure-attestation.so image/usr/lib

docker_run cp $occlum_glibc/libdl.so.2 image/$occlum_glibc
docker_run cp $occlum_glibc/librt.so.1 image/$occlum_glibc
docker_run cp $occlum_glibc/libm.so.6 image/$occlum_glibc
docker_run bash -c "cp $occlum_glibc/libnss_dns.so* image/$occlum_glibc"
docker_run bash -c "cp $occlum_glibc/libnss_files.so* image/$occlum_glibc"
docker_run bash -c "cp $occlum_glibc/libresolv.so* image/$occlum_glibc"
docker_run cp -r /etc/ssl/certs image/etc/ssl
docker_run cp -r /etc/java-11-openjdk image/etc
docker_run cp -r /usr/lib/jvm/java-11-openjdk-amd64 image/usr/lib/jvm
docker_run cp /lib/x86_64-linux-gnu/libz.so.1 image/lib

cp $work_dir/Occlum.json .
# ephemeral key
openssl genrsa -3 -out enclave-key.pem 3072

docker_run_root occlum build --sign-key enclave-key.pem
docker_run_root occlum package uid2-operator

popd

docker build -t ${container_name}:dev -t ${container_name}:${container_version} .
if [[ ! -n "${fast_build}" ]]; then
	docker save ${container_name}:dev | gzip >build/uid2-operator-azure-sgx.tar.gz
fi
./run.sh occlum run /bin/sgx_quote

if [[ -n "${enable_docker_push}" ]]; then
	docker push ${container_name}:${container_version}
fi
