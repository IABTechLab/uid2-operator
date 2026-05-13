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

## Verifying image provenance

Every non-snapshot image published by this repo's release workflow ships with a [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation, signed by GitHub's [Sigstore](https://www.sigstore.dev/) instance via the OIDC identity of the [shared publish workflow](https://github.com/IABTechLab/uid2-shared-actions). The attestation cryptographically binds the image digest to the source commit, the signing workflow, and the runner that built it.

To verify an image, install [`gh`](https://cli.github.com/) (≥ 2.49) and run:

```bash
gh attestation verify oci://ghcr.io/iabtechlab/uid2-operator:<tag> --owner IABTechLab --signer-repo IABTechLab/uid2-shared-actions
```

`<tag>` refers to the **Docker image tag** — bare semantic version, no `v` prefix (e.g. `5.70.84`). Note that the corresponding GitHub release and git tag for the same build are named with a `v` (e.g. `v5.70.84`); the registry tag drops it by OCI convention.

**Where to find a tag:**

- **GitHub Packages** for this repo — [`uid2-operator` package](https://github.com/IABTechLab/uid2-operator/pkgs/container/uid2-operator) lists every published image tag and its digest.
- Or take a [release](https://github.com/IABTechLab/uid2-operator/releases) name (e.g. `v5.70.84`) and drop the leading `v`.
- To pin to an exact manifest instead of a mutable tag, use the digest form: `oci://ghcr.io/iabtechlab/uid2-operator@sha256:<digest>` (visible on the Packages page, or via `gh api /orgs/IABTechLab/packages/container/uid2-operator/versions`).

A successful run prints `✓ Verification succeeded!` followed by the SLSA provenance fields — including `sourceRepositoryDigest` (the source commit), `workflow.path` (the signing workflow), and the runner identity.

Snapshot tags (`-SNAPSHOT` suffix) deliberately skip attestation. `gh attestation verify` returns `no attestations found` against a snapshot — that's expected.
