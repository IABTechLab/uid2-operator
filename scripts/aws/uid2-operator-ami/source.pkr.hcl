source "amazon-ebs" "linux" {

  # source parameters
  source_ami_filter {
    filters = {
      name                = "amzn2-ami-hvm-*-x86_64-ebs"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }

  # disable ami creation for testing
  # skip_create_ami = true

  # instance parameters
  ami_name           = local.ami_name
  ami_ou_arns        = var.ami_ou_arns
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
