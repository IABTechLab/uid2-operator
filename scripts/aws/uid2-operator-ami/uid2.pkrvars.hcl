region          = "us-east-1"
identity_scope  = "uid2"
# Pinned to last known-good AL2023 base (May 25 green build); see source.pkr.hcl
source_ami      = "ami-0236922087fa98b6e"
# Default VPC in us-east-1
vpc_id          = "vpc-ec832d91"
subnet_id       = "subnet-99019ec6"
ami_ou_arns    = [
    "arn:aws:organizations::155852253738:ou/o-v1vmbc3c9h/ou-96c8-2vbyb92d"
]
