# UID2 Operator


The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review the governance rules [here](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md)

## Building

To run unit tests:

```
mvn clean test
```

To package application:

```
mvn package
```

To run application:

- use `conf/local-config.json` to run standalone operator service 
  for local debugging, which loads salts, keys and optout from mock storage provider, and doesn't communicate with uid2-core and uid2-optout.

```
mvn clean compile exec:java -Dvertx-config-path=conf/local-config.json
```

- use `conf/integ-config.json` to run optout operator that
  integrates with uid2-core (default runs on `localhost:8088`) and uid2-optout  (default runs on `localhost:8081`)

```
mvn clean compile exec:java -Dvertx-config-path=conf/integ-config.json
```
## Local deployment/testing on Docker
1. In [Dockerfile](Dockerfile), change the line
    ```
    COPY ./conf/default-config.json /app/conf/
    ```
    to:
    ```
    COPY ./conf/docker-config.json /app/conf/local-config.json
    ```
2. Run ```mvn package```
3. Go to `pom.xml` and find the version wrapped under `<version>` tag
4. Run ```docker build -t uid2-operator --build-arg JAR_VERSION={version you find in step 3} .```
5. Run ```docker run -it -p 8080:8080 uid2-operator:latest ```
6. Go to postman and test on endpoint `http://localhost:8080/v1/token/generate?email=exampleuser4@test.uidapi.com`

## Running vulnerability scanning locally
The Github actions will run Trivy for vulnerability scanning as part of the build-and-test and publish-docker pipelines. However, they can also be run locally to aid in resolving these.
Trivy only runs on Linux, so you will need to install WSL.

### Installation
Once WSL is installed, follow these instructions:

https://aquasecurity.github.io/trivy/v0.35/getting-started/installation/

Once installed to check the code only (which is what the build-and-test pipeline does), run this command from the root directory:
```
wsl trivy fs .
```

To check the docker image (which is what the publish-docker pipeline does), build the docker image as outlined above and then run this command:
```
wsl trivy image <image reference>
```
where `<image reference>` is the built docker image you want to scan (uid2-latest in the example above). 

## Verifying artifact provenance

Every non-snapshot operator image and release artifact published by this repo
ships with a [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance
attestation, signed by GitHub's [Sigstore](https://www.sigstore.dev/) instance.
The attestation cryptographically binds the artifact digest to the source
repository, signing workflow, and GitHub-hosted runner that produced it.

Install [`gh`](https://cli.github.com/) (≥ 2.49), then use the command for the
artifact type you want to verify. Prefer `--signer-workflow` so verification
rejects attestations produced by a different workflow in the same repository.

### Public operator image

The public image uses the shared publish workflow:

```bash
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-operator:<version> \
  --repo IABTechLab/uid2-operator \
  --signer-repo IABTechLab/uid2-shared-actions
```

### Private operator images

Pin both the signing workflow and the registry-stored attestation bundle:

```bash
# GCP Confidential Space image in GitHub Container Registry
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-operator:<version>-gcp-oidc \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-gcp-oidc-enclave-docker.yaml \
  --bundle-from-oci

# The same GCP image in Google Artifact Registry
gh attestation verify \
  oci://us-docker.pkg.dev/uid2-prod-project/iabtechlab/uid2-operator:<version>-gcp-oidc \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-gcp-oidc-enclave-docker.yaml \
  --bundle-from-oci

# Azure CC/AKS image
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-operator:<version>-azure-cc \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-azure-cc-enclave-docker.yaml \
  --bundle-from-oci

# AWS EKS Nitro images
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-operator-eks-uid2:<version>.<run-number> \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-aws-eks-nitro-enclave-docker.yaml \
  --bundle-from-oci
gh attestation verify \
  oci://ghcr.io/iabtechlab/uid2-operator-eks-euid:<version>.<run-number> \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-aws-eks-nitro-enclave-docker.yaml \
  --bundle-from-oci
```

When `publish-all-operators.yaml` invokes a cloud-specific reusable workflow,
the reusable workflow remains the signer.

To pin an image to immutable bytes, replace its tag with the
`@sha256:<digest>` shown by the registry.

### EIFs, measurements, and release archives

Download the release assets and verify the exact file:

```bash
gh release download v<version> --repo IABTechLab/uid2-operator

# Deployment or combined-manifest archive from Publish All Operators
gh attestation verify <downloaded-archive>.zip \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-all-operators.yaml

# An EIF extracted from the downloaded archives
gh attestation verify <path-to>/uid2operator.eif \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/publish-aws-nitro-eif.yaml

# A measurement file (use the workflow that generated that measurement)
gh attestation verify <path-to>/<measurement-file>.txt \
  --repo IABTechLab/uid2-operator \
  --signer-workflow IABTechLab/uid2-operator/.github/workflows/<producer-workflow>.yaml
```

AWS AMI measurement files contain AMI IDs and the EIF PCR0 used by the build.
Their attestations prove the provenance of those metadata files; they do not
represent a byte-level signature of an AWS AMI. The AMI workflow also verifies
the consumed EIF’s existing provenance before Packer runs.

### Rebuilding AMIs from legacy EIFs

The AMI workflow fails closed when a non-snapshot EIF has no provenance
attestation. EIFs produced before provenance enforcement was introduced cannot
therefore be used to rebuild or repair an AMI with the current workflow. The
cutover is the first non-snapshot operator release published after this
workflow change.

For a legacy EIF, `gh attestation verify` reports `no attestations found`
before Packer starts. This indicates a pre-provenance artifact, not necessarily
artifact corruption. There is currently no bypass; supporting a legacy AMI
rebuild requires a reviewed workflow change.

A successful verification prints `✓ Verification succeeded!` and the SLSA
provenance, including `sourceRepositoryDigest`, `workflow.path`, and runner
identity.

Snapshot versions (`-SNAPSHOT`) deliberately skip attestation.
`gh attestation verify` returning `no attestations found` for a snapshot is
expected.
