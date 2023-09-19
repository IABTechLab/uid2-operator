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

| Name                 | Description | Type     | Default             | Required |
|----------------------|-------------|----------|---------------------|:--------:|
| project_id           | n/a         | `string` | n/a                 |   yes    |
| service_account_name | n/a         | `string` | n/a                 |   yes    |
| uid_operator_image   | n/a         | `string` | n/a                 |   yes    |
| uid_api_token        | n/a         | `string` | n/a                 |   yes    |
| region               | n/a         | `string` | `"asia-southeast1"` |    no    |
| network_name         | n/a         | `string` | `"uid-operator"`    |    no    |
| uid_machine_type     | n/a         | `string` | `"n2d-standard-16"` |    no    |
| uid_deployment_env   | n/a         | `string` | `"integ"`           |    no    |
| max_replicas         | n/a         | `number` | `5`                 |    no    |
| min_replicas         | n/a         | `number` | `1`                 |    no    |
| debug_mode           | n/a         | `bool`   | `false`             |    no    |

## Outputs

| Name             | Description |
|------------------|-------------|
| load-balancer-ip | n/a         |

## Notes

You may want to change LB from http to https

- Provide your cert via terraform following this page:
  [google_compute_ssl_certificate](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_certificate.html)

- Then add below configs in `module "gce-lb-http"`

  ```
    ssl                  = true
    ssl_certificates     = [google_compute_ssl_certificate.you_cert.self_link]
    use_ssl_certificates = true
    https_redirect       = true
  ```
