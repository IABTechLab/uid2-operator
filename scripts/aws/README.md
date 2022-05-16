# UID2 Operator - Nitro Enclave

UID2 Operator within Nitro Enclave protects sensitive data, including PII.

This page guides users to setup a UID2 Operator on AWS.

## Prerequisites

- Operator Key
- Amazon Machine Image (AMI) ID
- AWS account

If you do not have the prerequisites, please contact UID2 support team to get them.

## Deployment Steps

Follow through the steps to deploy a UID2 Operator EC2 instance:

- Configuration
- Setup IAM roles
- Create EC2 instance

### Create Configuration

UID2 Operator reads configuration from [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).

- In AWS services panel, find "Secrets Manager" and open Secrets Manager dashboard.
- Click "store a new secret". Create a new secret named **uid2-operator-config-key** (name must be exact, the bootstrap process depends on it)
- For "Secret type", select "Other type of secret"
- You can edit the secret in either key/value format or plain json format. The following is a template you can use.
- Finally, select (or create a new by clicking "Add new key") encryption key you want to use to encrypt the secrets. **Important:** the ARN of this key is needed in the following steps.
- **Important:** the ARN of the config secrets (uid2-operator-config-key) is also needed in the following steps.

```
{
  "api_token": "<your-operator-key>",
  "service_instances": "6",
  "enclave_cpu_count": "6",
  "enclave_memory_mb": "24000",
  "clients_metadata_path": "https://core-integ.uidapi.com/clients/refresh",
  "keys_metadata_path": "https://core-integ.uidapi.com/key/refresh",
  "salts_metadata_path": "https://core-integ.uidapi.com/salt/refresh",
  "keys_acl_metadata_path": "https://core-integ.uidapi.com/key/acl/refresh",
  "optout_metadata_path": "https://optout-integ.uidapi.com/optout/refresh",
  "optout_api_uri": "https://core-integ.uidapi.com/optout/replicate",
  "core_attest_url": "https://core-integ.uidapi.com/attest"
}
```

notes:
- above fields are all required
- service_instances/enclave_cpu_count/enclave_memory_mb are currently not customizable, modification to these fields will be ignored
- `core-integ` is integration test endpoint; use `core-prod` when ready for production usage
- you might need to replicate secret after creation to use it in other regions

### Setup IAM Roles

To fetch the configuration in Secrets Manager from EC2 instances, the instances need to have a IAM role with access to the secrets. This section is a guide for creating the minimal IAM role you need.

- Go to "IAM Management Console" and click "Create role"
- Under "Trusted entity type" select "Custom trust policy"
- Replace <KMS-key-ARN> in the following template to be your encryption key ARN from the previous step
- Replace <Config-key-ARN> to be your config secret ARN (the ARN for 'uid2-operator-config-key')
- Submit the modified content as the trust policy. This is the minimal access an Operator needs to bootstrap.

```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
        "kms:Decrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "<KMS-key-ARN>"
		},
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "<Config-key-ARN>"
    }
	]
}
```


### Create EC2 Instance

To start a UID2 Operator EC2 instance, go to EC2 dashboard and click "Launch Instances". Here we only list the necessary settings for Operator. You can customize fields that are not mentioned in this section.

- Application and OS Images (AMI): please use the AMI ID that is shared with you by UID2 support team.
- Instance type: select from m5.2xlarge, m5n.2xlarge, m5a.2xlarge
- Network settings:
  - (in)  port 80: UID2 API endpoint
  - (in)  port 9080: UID2 prometheus metric endpoint
  - (out) port 443: UID2 Core communication
- Configure storage: 8GB minimum
- Advanced Details
  - IAM instance profile: select the IAM role you have created in the previous step
  - Nitro Enclave: **Enable**
- Customize other fields for your usage
- Click "Launch instance"

The browser will navigate you to EC2 dashboard and you will see a running instance in a moment.

The UID2 Operator takes around 1 minute to bootstrap after the machine starts, please use http://<your-domain-name>/ops/healthcheck to monitor its status.

If your Operator is not started in a few minutes, please double check your configuration, and contact support team.

## Advanced Topic

Here we present useful services for production scenarios.

### Load Balancer

UID2 Operators in production almost always use a load balancer, because
1. A load balancer distributes network traffic to multiple backend operator endpoints, and you almost always have more than one operators in production
2. For public operators you are responsible for serving HTTPS traffic and needs to offload the HTTPS traffic on load balancer

We suggest our users to setup Application Load Balancer (ALB) because it satisfies both needs in one go.

Go to "Load balancer" dashboard and click "Create Load Balancer"
- Under "Load balancer types", select "Application Load Balancer"
- In "Basic configuration", you can choose from Internet-facing and Internal, depending on your usage (public/private operator, for example)
- On "Security groups", you need a security group with at least 80 and/or 443 exposed
- VPC and subnets: select your desired VPC for hosting UID2 Operators, and at least 2 subnets
- Listeners and routing: click "create a target group"
  - "Choose a target type": Instances
  - "Protocol+Port": HTTP+80 (HTTPS+443)
  - "VPC": the same VPC you will use for UID2 Operators
  - "Protocol version": HTTP1
  - "Health check path": /ops/healthcheck
  - Click "Next"
  - In the "Register targets" page, select one of your UID2 Operator EC2 instances
  - Create target group
- Proceed and create the load balancer, you can find the IP address / domain name in "Network & Security - Network Interfaces"

### Auto Scaling Group

Auto scaling group(ASG) helps you adjust the capacity with respect to incoming traffic.

To setup ASG, first you need to define a launch template. Steps for creating a launch template is similar to [creating EC2 instance](#create-ec2-instance). The same requirements apply.

On EC2 Auto Scaling Groups dashboard, click "Create an Auto Scaling group"

- Select the launch template you have just created for UID2 operator
- Choose your VPC and subnets
- If you have setup a load balancer in the previous section, attach to an existing load balancer by adding the ASG to the target group your ALB is targeting. You can also quickly create a basic LB by clicking "Attach to a new load balancer"
- For health checks use 300 seconds

For more configurations, see [AWS User Guide](https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-launch-template.html)

After creating an auto scaling group it should auto spin up some nodes, you can test if they start correctly by visiting /ops/healthcheck on your browser.

### Customize AMI

For partners who wish to add more applications on host machine, one can build one's own AMI containing UID2 Operator.

To setup new tools (metric scraper, for example), you can launch an EC2 instance with UID2 Operator AMI and install them onto the EC2 instance. Then build a new AMI based off of that EC2 instance.

Follow the same steps to create ASG for the new AMI.

### HTTPS

Using HTTPS is crucial for the security of your keys, customers' keys and confidentiality of PIIs. Be sure to establish secure connection when you host an uid2 operator for production.

However, setting up HTTPS on AWS is out of scope of UID2 operator setup. Depending on your solution, you can use Application Load Balancer for HTTPS setup and offloading.

More on [autoscaling load balancer](https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html)

More on [HTTPS offloading](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html)
