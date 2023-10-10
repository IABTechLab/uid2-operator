# Overview

This folder provides some scripts to be used by github action to run GCP enclave E2E test.

You could also leverage them to bring up a local docker-compose cluster contains:
 - localstack (local S3)
 - core (depends on localstack)
 - optout (depends on localstack and core)

and expose public Urls via ngrok, which could be used for private operator test.

# How to run locally
Set below config in `./e2e/e2e.sh`
 - NGROK_TOKEN: register a NGROK account and fetch from https://dashboard.ngrok.com/get-started/your-authtoken
 - CORE_VERSION: the core image version
 - OPTOUT_VERSION: the optout image version
 - IMAGE_HASH: the image hash "sha256:..." for your operator image, this is to generate valid GCP OIDC enclave_id
 - AZURE_CC_POLICY_DIGEST: Azure CC policy digest to be used as enclave_id

and run below command under repo root:

```
bash ./e2e/e2e.sh
```

It will copy `e2e` folder to `e2e-target` folder and invoke from there.

Other scripts that may help:
 - `start_gcp_enclave.sh`: start a GCP enclave and run basic health check.
 - `stop_gcp_enclave.sh`: stop a GCP enclave and delete the VM instance.

Notes:
If you are running in mac, you may need to install `GNU sed` and `alias sed=gsed`