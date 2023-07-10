# UID2 Operator - Nitro Enclave

UID2 Operator application running within AWS Nitro Enclave protects sensitive data (encryption keys and salt buckets), including PII.

Follow instructions below to deploy UID2 Operator in your AWS Account. There are some pre-requisites before you proceed with the steps.

## Prerequisites

1. AWS Account
2. Amazon VPC with NAT gateway, private and public subnets
3. UID2 Operator Key
4. UID2 Operator AMI

If you do not have #3 and #4 of pre-requisites, please contact UID2 support team (UID2partners@thetradedesk.com) to get them.


** Note - You can deploy UID2 Operator using either of the below Amazon Machine Image (AMI) configurations **

1. Use UID2 Operator AMI
2. Customize UID2 Operator AMI using UID2 Operator AMI

## Deployment Steps

Follow through the steps to deploy a UID2 Operator EC2 instance:

1. Create secret to store bootstrap configuration
2. Setup IAM role
3. Create EC2 Launch template
4. Create EC2 AutoScaling group
5. Create AWS Application Load Balancer

### Step 1 Create secret

UID2 Operator application reads configuration from [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) secret. You can refer to [AWS User Guide] (https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html) for more information on creating secrets.

1. In AWS Console, find "Secrets Manager" and open Secrets Manager dashboard.
2. Click "Store a new secret" to create a new secret.
3. For "Secret type", select "Other type of secret"
4. Select "Plaintext" under Key/Value pairs section
5. Copy the paste the below template
```
{
  "api_token": "<your-operator-key>",
  "service_instances": "6",
  "enclave_cpu_count": "6",
  "enclave_memory_mb": "24000",
  "clients_metadata_path": "https://core-integ.uidapi.com/clients/refresh",
  "salts_metadata_path": "https://core-integ.uidapi.com/salt/refresh",
  "keysets_metadata_path": "https://core-integ.uidapi.com/key/keyset/refresh",
  "keyset_keys_metadata_path": "https://core-integ.uidapi.com/key/keyset-keys/refresh",
  "optout_metadata_path": "https://optout-integ.uidapi.com/optout/refresh",
  "optout_api_uri": "https://core-integ.uidapi.com/optout/replicate",
  "core_attest_url": "https://core-integ.uidapi.com/attest"s
}
```
Important Notes:
- above fields are all required
- service_instances/enclave_cpu_count/enclave_memory_mb are currently not customizable, modification to these fields will be ignored
- `core-integ` is integration test endpoint; use `core-prod` when ready for production usage
- you might need to replicate secret after creation to use it in other regions

6. Replace `api_token` with the provided UID2 Operator Key
7. Keep selecting default `aws/secretsmanager` as the encryption key. You can create your own encryption key by clicking on `Add new key` link. 
8. Provide secret name as **uid2-operator-config-key** (name must be exact, the bootstrap process depends on it)
9. Click on Next to create the secret. 
10. Click on created secret and capture `Secret ARN` value for later steps
 
 **Important:** Keep note of the ARN value of the created secret. 

### Step 2 Get Arn of Secret Encryption Key

1. Go to Key Management Service in AWS Console
2. Search for `aws/secretsmanager` under **AWS managed keys**
3. Click on `aws/secretsmanager` and capture `ARN` value for later steps.


### Step 3 Setup IAM Roles

You need to create IAM role that has access to secret stored in AWS Secrets Manager. UID2 Operation application on EC2 instance uses the IAM role to access the configuration.

1. Go to "IAM" AWS Console, Click Roles and then click on "Create role" button
2. Under "Trusted entity type", select "AWS Service" and select 'EC2' under Common use cases
3. Click on Next button. On the following screen, click on "Create Policy" button to create the required IAM Policy
4. In Create Policy window, select "JSON"
3. Copy and paste the below IAM policy 
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
** Note - This is the minimal access an Operator needs to bootstrap.** 

3. Replace `<KMS-key-ARN>`  with captured  `ARN`  value in Step 2.3
4. Replace `<Config-key-ARN>` with captured  `Secret ARN`  value in Step 1.10 
5. Click on Next and provide **UID2OperatorConfigKeyPolicy** under Name
6. Click on "Create policy" button to create the required IAM Policy 
7. Go back to IAM role page and search for `UID2OperatorConfigKeyPolicy` under "Permissions policies"
8. Select `UID2OperatorConfigKeyPolicy` from search results to add policy to your IAM role
9. Click on Next and provide **UID2OperatorConfigKeyRole** under RoleName


### Step 4 Create EC2 Launch template

In this step, you create EC2 Auto Scaling groups and Launch template. Auto Scaling groups help to adjust capacity either scale in or scale out to handle incoming traffic. 

You can refer to [AWS User Guide for Launch Template](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-launch-templates.html?icmpid=docs_ec2_console#lt-initiate-launch-template) to understand the details steps. 

1. Go to EC2 AWS Console and find "Launch templates"
2. Click on "Crete launch template" button and provide name **UID2OperatorTemplate**. Provide "Template version description" as neccessary.
3. Under "Application and OS Images (Amazon Machine Image)" and click on "Browse more AMIs"
4. Provide UID2 Operator AMI ID (shared during pre-requisites) in the search bar. If you can't find AMI, uncheck "Owned by me" option on the filters.
5. Click on "Select" button on the AMI in search results. Make sure AMI ID matches what you searched for.
#### Instance Types
6. Under Instance type, select `m5.2xlarge` or `m5n.2xlarge` or `m5a.2xlarge`
7. Click on "Create new key pair" to create key pair for SSH access to EC2 host instance. 
8. Provide a name under "Key pair name", select key pair type as `RSA` and select private key file format as `.pem`. Click on "Create key pair" button. 
#### Network Settings
9.  Select "Create security group", provide `UID2SG` under Security group name
10. Click on "Add security group rule" button to allow below ports.
  - (in)  port 80: UID2 API endpoint
  - (in)  port 9080: UID2 prometheus metric endpoint
  - (in) port 22: SSH access
#### Configure storage
11. Click on "Add new volume" button and provide a minimum of `8` GB with `gp3` EBS volume 
#### Advanced details
12. Expand Advanced details and select `UID2OperatorConfigKeyRole` under IAM instance profile
13. Under Nitro Enclave drop down. select `Enable`
14. Feel free to customize other fields as per your requirement
15. Click on "Create launch template" button


### Step 5 Create EC2 Auto Scaling group
Auto Scaling groups help to adjust capacity either scale in or scale out to handle incoming traffic. 
You can refer to [AWS User Guide for AutoScaling groups](https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-launch-template.html) to understand the details steps. 

1. Go to EC2 AWS Console and find "Auto Scaling groups"
2. Click on "Create an Auto Scaling group" button
3. Provide name **UID2AutoScalingGroup** under AutoScaling group name and select `UID2OperatorTemplate` under Launch temple. Click on Next
4. Select VPC from pre-requisites and select two or more subnets in different availability zones. Note that more than one availability zone provide high availability configuration.
5. Click Next. Select 'No load balancer' and leave rest of the fields to default values
6. Specify `2` in Desired capacity, Minimum capacity and Maximum capacity. You can specify desired values for the three configurations. You can refer to [AWS user guide for scaling group](https://docs.aws.amazon.com/autoscaling/ec2/userguide/scale-your-group.html)
7. You can optionally setup notifications.
8. Click on "Create Auto Scaling group" button


### Step 6 Create Load Balancer (Recommended for Production and Test)

For production environment, it is recommended to use AWS Application Load Balancer.

- A load balancer distributes network traffic to multiple backend operator endpoints, and you almost always have more than one operators in production
- For public operators you are responsible for serving HTTPS traffic and needs to offload the HTTPS traffic on load balancer

1. Go to EC2 in AWS Console and search for "Load Balancer" 
2. Click on "Create Load Balancer" button and Click on "Create" button under "Applicaton Load Balancer"
3. Under Load balancer name, provide **UID2LoadBalancer**
4. Under scheme, choose from `Internet-facing` and `Internal`, depending on your usage (public/private operator, for example)
5. Select VPC  and 2 or more subnets created in pre-requisites section. 
6. Click on "Create new security group" and provide name **UID2SGALB** 
7. Under Inbound rules, select `HTTPS` and Source IP range depending upon your requirements. Click on "create security group" button
8. Go back to Load Balancer page and the created `UID2SGALB` security group
9. Under Listeners and routing section, Click on "Create target group" link.
10. Select `Instances` as target type and provide **UID2ALBTG** as target group name and select "Protocol version" as `HTTP1`
11. Under "Health check path", provide `/ops/healthcheck` and Expand "Advanced health check settings". Select `Override` under Port and update default `80` to `9080`
12. Select UID2 Operator EC2 Instances created by your Auto Scaling group and Click on "Include as pending below" button. Make sure "Ports for the selected instances" contains `80`
13. Click on "create target group" button.
14. Go back to Load Balancer page, select `UID2ALBTG` under "Forward to" and update Port to `443`.
15. Follow instructions on [AWS user guide](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#default-certificate) to setup HTTPS listener.
15. Click on "create load balancer" button

## Sanity Check
Follow these steps to sanity check that UID2 Operator service is running 

Invoke UID2 Operatpor API from EC2 host instance using the below instructions. As a pre-requisite for this test, you need to obtain UID2 Operator Client Key from UID2 Administrator. UID2 Operator Client Key is different from UID2 Operator Key. 
```
SCHEME=http
PUBLIC_DNS=localhost
CLIENT_KEY=<UID2 Operator Client Key>
curl -H "Authorization: Bearer $CLIENT_KEY" $SCHEME://localhost/v1/token/generate?email=example@mail.com
```

### Health Check 

You can add Inbound Rule to your security group `UID2SG` to allow TCP traffic to port 9080. You can check the health of UID2Operator application by typing `http://<EC2-public-domain-name>:9080/ops/healthcheck`

If your Operator is not started in a few minutes, please double check your configuration, and contact UID2 support team at UID2partners@thetradedesk.com

## Advanced Topic

Here we present useful services for production scenarios.

### Customize AMI

For partners who wish to add more applications on host machine, one can build one's own AMI containing UID2 Operator.

To setup new tools (metric scraper, for example), you can 
1. launch an EC2 instance with UID2 Operator AMI (provided by UID2 team) 
2. install new software or setup tools on the EC2 instance
3. Create AMI from your EC2 instance (refer to *Create a Linux AMI from an instance* section of [AWS User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html)).

Follow the same steps to create ASG for the new AMI.

### HTTPS

Using HTTPS is crucial for the security of your keys, customers' keys and confidentiality of PIIs. Be sure to establish secure connection when you host an uid2 operator for production.

Follow instructions on [AWS user guide](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#default-certificate) to setup HTTPS listener.