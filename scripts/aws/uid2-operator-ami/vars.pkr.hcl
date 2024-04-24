variable "env" {
  description = "distinct environment/stage name"
  default     = "production"
}

variable "identity_scope" {
    description = "The scope of the operator. uid2 or euid"
    default = "uid2"
}

variable "service" {
  description = "distinct name for the service"
  default     = "operator"
}

variable "region" {
  description = "AWS region name"
  default     = "us-east-1"
}

variable "instance_type" {
  description = "instance type to build on"
  default     = "m5.2xlarge"
}

variable "vpc_id" {
  description = "vpc id for instance creation"
}

variable "subnet_id" {
  description = "subnet id for instance creation"
}

variable "communicator" {
  description = "communication method used for the instance"
  default     = "ssh"
}

variable "ssh_username" {
  description = "ssh username for packer to use for provisioning"
  default     = "ec2-user"
}

variable "ssh_interface" {
  description = "ssh interface for packer to use for provisioning"
  default     = "session_manager"
}

variable "iam_instance_profile" {
  description = "IAM instance profile to attach to AMI instance for SSM"
  default     = "service.packer.target"
}

variable "version" {
  description = "release version"
}

variable "ami_ou_arns" {
  description = "A list of Amazon Resource Names (ARN) of AWS Organizations that have access to launch the resulting AMI(s)."
  type = list(string)
}

variable "timestamp" {
  description = "unique timestamp"
}

locals {
  identifier = "${var.identity_scope}-${var.service}"
  version    = "${var.version}"

  ami_name = "${local.identifier}-${local.version}-${var.timestamp}"
}
