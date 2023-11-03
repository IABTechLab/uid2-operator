# Example to deploy GCP private operator via Terraform

We provide a terraform template to deploy UID2 private operators with LB and auto-scaling feature. All VM instances are
running on Confidential Space VMs, and will be deployed in multiple AZs.

We will set up below in your GCP project
- Activate required GCP APIs.
- Service account to run Confidential Space VMs.
- Secret to hold `operator_key`.
- Network: VPC and subnetwork.
- Instances: Instance template, and Instance groups (with autoscaling)
- Ingress: Load balancer (with healthcheck), forwarding rules, firewall rules.
- Egress: NAT.

## Install Terraform

1. Install Terraform if it is not already installed (visit [terraform.io](https://terraform.io) for other
   distributions):

## Set up the environment

1. Set the project, replace `{PROJECT_ID}` with your project ID:

```
gcloud config set project {PROJECT_ID}
```

2. Configure the environment for Terraform:

```
gcloud auth application-default login
```

## Run Terraform

```
terraform init
terraform apply
```

## Testing

1. Get load balancer public ip:

```
terraform output load-balancer-ip
```

2. Check our health check endpoint

```
http://{PUBLIC_IP}/ops/healthcheck
```

## Cleanup

1. Remove all resources created by Terraform:

```
terraform destroy
```

## Inputs

| Name                         | Type           | Default                 | Required | Description                                                                                                                                                                                                                                                                                                                           |
|------------------------------|----------------|-------------------------|:--------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| project_id                   | `string`       | n/a                     |   yes    | The ID of the GCP project that you want the UID2 Operator to run in; for example, `UID2-Operator-Production`.                                                                                                                                                                                                                         |
| service_account_name         | `string`       | n/a                     |   yes    | The name of the service account that you want to use for your UID2 Operator instance in GCP Confidential Space.                                                                                                                                                                                                                       |
| uid_operator_image           | `string`       | n/a                     |   yes    | The Docker image URL for the UID2 Private Operator for GCP, used in configuration, which you received as part of UID2 Operator Account Setup. For example: `us-docker.pkg.dev/uid2-prod-project/iabtechlab/uid2-operator@sha256:{IMAGE_SHA}`                                                                                          |
| uid_operator_key             | `string`       | n/a                     |   yes    | The UID2 operator key, which you received as part of UID2 Operator Account Setup. <br> Note: only required during first time provision. You could leave it as empty string later if you don't want to update secret value.                                                                                                            |
| uid_deployment_env           | `string`       | n/a                     |   yes    | Valid values: `integ` for integration environment, `prod` for production environment. <br> Machine type is determined by the deployment environment: `integ` uses `n2d-standard-2` and prod uses `n2d-standard-16`.                                                                                                                   |
| uid_operator_key_secret_name | `string`       | `"secret-operator-key"` |    no    | The name that you specify for your operator key secret. The Terraform template creates a secret in the GCP Secret Manager to hold the `uid_operator_key` value. You can define the name; for example, `uid2-operator-operator-key-secret-integ`.                                                                                      |
| region                       | `string`       | `"us-east1"`            |    no    | The region that you want to deploy to. For a list of valid regions, see [Available regions and zones](https://cloud.google.com/compute/docs/regions-zones#available) in the Google Cloud documentation. <br>NOTE: The UID2 Private Operator implementation for GCP Confidential Space is not supported in these areas: Europe, China. |
| network_name                 | `string`       | `"uid-operator"`        |    no    | The VPC resource name (also used for rules/ instance tags).                                                                                                                                                                                                                                                                           |
| max_replicas                 | `number`       | `5`                     |    no    | Indicates the minimum number of replicas you want to deploy.                                                                                                                                                                                                                                                                          |
| min_replicas                 | `number`       | `1`                     |    no    | Indicates the maximum number of replicas you want to deploy.                                                                                                                                                                                                                                                                          |
| debug_mode                   | `bool`         | `false`                 |    no    | Do not set to true unless you are working with the UID2 team to debug an issue. In any other circumstances, if you set this flag to true, attestation will fail.                                                                                                                                                                      |
| ssl                          | `bool`         | `false`                 |    no    | Set to true to enable SSL support, requires variable `ssl_certificate_domains`                                                                                                                                                                                                                                                        |
| ssl_certificate_domains      | `list(string)` | `[]`                    |    no    | A comma-delimited list of the target domains for this certificate, equires `ssl` to be set to `true`. <br> Note: you need to update your DNS record to point to load balancer's IP address                                                                                                                                            |


## Outputs

| Name             | Description |
|------------------|-------------|
| load_balancer_ip | n/a         |
