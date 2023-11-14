# UID2 Operator - Google Cloud Platform Confidential Space package

UID2 Operator service can be run within a trusted
[Confidential Space](https://cloud.google.com/confidential-computing/confidential-vm/docs/about-cvm#confidential-space).
powered by Google.
Scripts in this folder help to package the service.

We leverage below key components of Confidential Space:
- **A workload**: a containerized image run on top of the 
[Confidential Space image](https://cloud.google.com/confidential-computing/confidential-vm/docs/work-with-confidential-space-images)
, a hardened OS based on Container-Optimized OS. This runs on Confidential Computing,
a cloud-based TEE that offers hardware isolation and remote attestation capabilities.
- **An attestation service**: an [OpenID Connect](https://developers.google.cn/identity/openid-connect/openid-connect) 
(OIDC) token provider that verifies the attestations for the TEE and releases authentication tokens.
The tokens contain identification attributes for the workload.
The attestation service runs in the same region that the workload is running in.

When our workload(UID2 Operator)'s docker container starts up, it will fetch GCP OIDC token from shared mount volume and 

put the token inside Attestation Document. It then sends the Attestation Document plus the UID2 Operator Key to
UID2 Core as Attestation Request.

Once the attestation is successful, UID2 Core will provide seed information such as Salts,
and Keys, to bootstrap UID2 Operator.

## Build

The official Docker image to run UID2 Operator on GCP Confidential Space enclave can be
pulled from the following GitHub Container Registry location:
- docker pull ghcr.io/iabtechlab/uid2-operator

Note that for deployments in integration or production environment, replicated Docker images hosted in Google Cloud Artifact Registry are used to improve reliability.

You can use the following command to build a non-certified UID2 operator container image from source code:

```
# From the root source folder
# Update project version in pom to "1.0.0-SNAPSHOT"

mvn -B package -P gcp 
cp -r target scripts/gcp-oidc/
docker build ./scripts/gcp-oidc/. -t uid2-operator:v1.0.0-SNAPSHOT
```

## Prerequisites

UID2 Operator can be run on any GCP account and project, however to support Attestation, you need to create a 
service account that would be used to run Confidential Space VMs, and grant it proper permissions.

Run below from [Google Cloud Console](https://console.cloud.google.com/):

1. Click "Active Cloud shell".
2. Switch to your project:
    ```
    $ gcloud config set project {PROJECT_ID}
    ```
 
3. Enable the following APIs:

| Name                                 | Description                |
|--------------------------------------|----------------------------|
| compute.googleapis.com               | Compute Engine API         | 
| confidentialcomputing.googleapis.com | Confidential Computing API | 
| logging.googleapis.com               | Cloud Logging API          | 
| secretmanager.googleapis.com         | Secret Manager API         | 
    ```
    $ gcloud services enable compute.googleapis.com \
      confidentialcomputing.googleapis.com \
      logging.googleapis.com \
      secretmanager.googleapis.com
    ```

4. Create a service account to run the workload:
    ```
    $ gcloud iam service-accounts create {SERVICE_ACCOUNT_NAME}
    ```

5. Grant below required permissions to service account:
- `confidentialcomputing.workloadUser`, grants the ability to generate an attestation token and run a workload in a VM.
    ```
    $ gcloud projects add-iam-policy-binding {PROJECT_ID} \
      --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com \
      --role=roles/confidentialcomputing.workloadUser
    ```
- `logging.logWriter`, access to write & view logs in Cloud Logging.
    ```
    $ gcloud projects add-iam-policy-binding {PROJECT_ID} \
      --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com \
      --role=roles/logging.logWriter
    ```
- `roles/secretmanager.secretAccessor`, grants the ability to access operator API token that is managed in Secret Manager.
    ```
    $ gcloud projects add-iam-policy-binding {PROJECT_ID} \
      --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com \
      --role=roles/secretmanager.secretAccessor
    ```
  
6. Add VPC rule to allow public 8080 access (default exposed port of UID2 operator):
    ```
    $ gcloud compute firewall-rules create operator-tcp \
      --direction=INGRESS --priority=1000 --network=default --action=ALLOW \
      --rules=tcp:8080 \
      --source-ranges=0.0.0.0/0 \
      --target-service-accounts={SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com
    ```

## Integration Deployment

We can deploy new UID2 Operator in GCP Confidential Space Enclave into Integration Environment by following below steps.

### (For uid2 admin) Register enclave id in admin portal

1. Generate enclave id:  go to Admin
   portal [GCP Enclave Id page](https://admin-integ.uidapi.com/adm/enclave-gcp-v2.html),

- Input:
    - the full digest for the image, with or without "sha256:"
    - Environment: Production/Integration
    - Debug mode: True/False in Integration. Always False in Production.
- Output: GCP Enclave ID

2. Register the generated GCP Enclave ID: go to Admin
   portal [Enclave Id Management page](https://admin-integ.uidapi.com/adm/enclave-id.html),

- Input:
    - Name: enclave name
    - Protocol: "gcp-oidc"
    - Enclave ID: the generated value in Step 1

### (For partner) Create secret for the Operator Key in Secret Manager

As part of setting up your UID2 account, you'll receive an Operator Key for each environment.

The next step is to store the `{OPERATOR_KEY}` value in GCP Secret Manager and get a full secret name for it,
which you later use to replace the `{OPERATOR_KEY_SECRET_FULL_NAME}` placeholder in the deployment script.

Following these steps:

1. Run the following script, which creates a new secret, first customizing with your own values

```
OPERATOR_KEY="{OPERATOR_KEY}"
echo -n $OPERATOR_KEY | gcloud secrets create {OPERATOR_KEY_SECRET_NAME} \
    --replication-policy="automatic" \
    --data-file=-
```

- Prepare the script, using your own values:
    - For `{OPERATOR_KEY}`, use your own operator key for the environment
    - For `{OPERATOR_KEY_SECRET_NAME}`, specify the name you want to use for your API secret, for this environment. For
      example: `uid2-operator-operator-key-secret-integ`.

2. Run the following command to get the full secret name, including the path, first customizing with your own values:

```
gcloud secrets versions describe latest --secret {OPERATOR_KEY_SECRET_NAME} --format 'value(name)'
```

In this example, the full secret name might
be:`projects/111111111111/secrets/uid2-operator-operator-key-secret-integ/versions/1`. This is the value that you would
use to replace the `{OPERATOR_KEY_SECRET_FULL_NAME}` placeholder in the next section.

### (For partner) Create VM Instance

There are a few placeholders that you need to replace in below command:

- `{INSTANCE_NAME}`: your VM name, can be changed as your need.
- `{ZONE}`: which Google Cloud zone will be deployed on.
- `{SERVICE_ACCOUNT}`: in `{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com` format, the one you created
  in Prerequisites phase.
- `{OPERATOR_IMAGE}`: the Docker image URL for the UID2 Private Operator for GCP. You should have received this from
  UID2 team.
- `{OPERATOR_KEY_SECRET_FULL_NAME}`: the full name of the secret name of your operator key created
  in [the above section](#for-partner-create-secret-for-the-operator-key-in-secret-manager), the format is
  `projects/<project_id>/secrets/<secret_id>/versions/<version>`

```
$ gcloud compute instances create {INSTANCE_NAME} \
  --zone {ZONE} \
  --machine-type n2d-standard-2 \
  --confidential-compute \
  --shielded-secure-boot \
  --maintenance-policy Terminate \
  --scopes cloud-platform \
  --image-project confidential-space-images \
  --image-family confidential-space \
  --service-account {SERVICE_ACCOUNT} \
  --metadata ^~^tee-image-reference={OPERATOR_IMAGE}~tee-restart-policy=Never~tee-env-DEPLOYMENT_ENVIRONMENT=integ~tee-env-API_TOKEN_SECRET_NAME={OPERATOR_KEY_SECRET_FULL_NAME}
```

## Production Deployment

We can deploy new UID2 Operator in GCP Confidential Space Enclave into Production Environment by following the same process as for
Integration.

You will be provided a new operator API token which should be stored in Secret Manager, and `~tee-env-DEPLOYMENT_ENVIRONMENT=integ~` needs to be changed to
`~tee-env-DEPLOYMENT_ENVIRONMENT=prod~`.

It is recommended that you also specify the machine type in the gcloud script. Currently, it is recommended to run the
UID2 operator on a machine type of n2d-standard-16. (default to n2d-standard-2)

An example of the script is given below:

```
$ gcloud compute instances create {INSTANCE_NAME} \
  --zone {ZONE} \
  --machine-type n2d-standard-16 \
  --confidential-compute \
  --shielded-secure-boot \
  --maintenance-policy Terminate \
  --scopes cloud-platform \
  --image-project confidential-space-images \
  --image-family confidential-space \
  --service-account {SERVICE_ACCOUNT} \
  --metadata ^~^tee-image-reference={OPERATOR_IMAGE}~tee-restart-policy=Never~tee-env-DEPLOYMENT_ENVIRONMENT=prod~tee-env-API_TOKEN_SECRET_NAME={OPERATOR_KEY_SECRET_FULL_NAME}
```

Note that compared to the `gcloud` command used in the prior section, parameter `--machine-type n2d-standard-16` is set to ensure production deployment of UID2 Operator runs on the recommended machine type for production.

## Upgrading

For each operator version update, private operators receive an email notification with an upgrade window,
after which the old version is deactivated and no longer supported.
To upgrade to the latest version, change the `{OPERATOR_IMAGE}` to the new value.
