# Example to deploy GCP private operator via Terraform

We provide a terraform template to deploy UID2 private operators with LB and auto-scaling feature. All VM instances are
running on Confidential Space VMs, and will be deployed in multiple AZs.

We will set up below in your GCP project
- Activate required GCP APIs.
- Service account to run Confidential Space VMs.
- Secret to hold `api_token`.
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

| Name                      | Type     | Default              | Required | Description                                                                                       |
|---------------------------|----------|----------------------|:--------:|---------------------------------------------------------------------------------------------------|
| project_id                | `string` | n/a                  |   yes    | n/a                                                                                               |
| service_account_name      | `string` | n/a                  |   yes    | n/a                                                                                               |
| uid_operator_image        | `string` | n/a                  |   yes    | n/a                                                                                               |
| uid_api_token             | `string` | n/a                  |   yes    | n/a                                                                                               |
| uid_deployment_env        | `string` | n/a                  |   yes    | Allowed values: `"integ"`, `"prod"`                                                               |
| uid_api_token_secret_name | `string` | `"secret-api-token"` |    no    | n/a                                                                                               |
| region                    | `string` | `"us-east1"`         |    no    | n/a                                                                                               |
| network_name              | `string` | `"uid-operator"`     |    no    | n/a                                                                                               |
| max_replicas              | `number` | `5`                  |    no    | n/a                                                                                               |
| min_replicas              | `number` | `1`                  |    no    | n/a                                                                                               |
| debug_mode                | `bool`   | `false`              |    no    | n/a                                                                                               |
| ssl                       | `bool`   | `false`              |    no    | Set to true to enable SSL support, requires variable `private_key` and `certificate`              |
| private_key               | `string` | `null`               |    no    | Content of the private SSL key. Required if `ssl` is true. e.g. `file("path/to/private.key")`     |
| certificate               | `string` | `null`               |    no    | Content of the SSL certificate. Required if `ssl` is true. e.g. `file("path/to/certificate.crt")` |


## Outputs

| Name             | Description |
|------------------|-------------|
| load_balancer_ip | n/a         |
