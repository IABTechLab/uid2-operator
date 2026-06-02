region          = "eu-central-1"
identity_scope  = "euid"
# Pinned to last known-good AL2023 base (May 25 green build); see source.pkr.hcl
source_ami      = "ami-08b013271cfc23534"
subnet_id       = "subnet-0edbf47b073de1c79"
vpc_id          = "vpc-065000fb9082c6a90"
ami_ou_arns    = [
    "arn:aws:organizations::155852253738:ou/o-v1vmbc3c9h/ou-96c8-2vbyb92d"
]
