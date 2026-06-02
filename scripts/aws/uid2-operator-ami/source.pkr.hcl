source "amazon-ebs" "linux" {

  # source parameters
  # TEMPORARY PIN (swi-fix-ami-timeout): the latest AL2023 base image regressed SSM
  # session stability, hanging the Packer build until SSM's 20-min idle timeout fires.
  # Pinned to the last known-good base AMI (May 25 green build) per region, set in the
  # *.pkrvars.hcl files. Revert to the most_recent filter below once the SSM connection
  # issue is resolved.
  source_ami = var.source_ami
  # source_ami_filter {
  #   filters = {
  #     name                = "al2023-ami-2023*-x86_64"
  #     root-device-type    = "ebs"
  #   }
  #   most_recent = true
  #   owners      = ["amazon"]
  # }

  # disable ami creation for testing
  # skip_create_ami = true

  # instance parameters
  ami_name           = local.ami_name
  ami_ou_arns       = var.ami_ou_arns
  instance_type      = var.instance_type
  region             = var.region
  subnet_id          = var.subnet_id
  vpc_id             = var.vpc_id

  # connection parameters
  communicator         = var.communicator
  ssh_username         = var.ssh_username
  ssh_interface        = var.ssh_interface
  iam_instance_profile = var.iam_instance_profile

  tags = {
    Environment = var.env
    Service     = var.service
    Version     = var.version
    Name        = local.ami_name
    Build       = "packer"
    BuildTime   = var.timestamp
  }
}
