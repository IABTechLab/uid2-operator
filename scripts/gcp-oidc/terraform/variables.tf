variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-east1"
}

variable "network_name" {
  type    = string
  default = "uid-operator"
}

variable "service_account_name" {
  type = string
}

variable "uid_operator_image" {
  type = string
}

variable "uid_deployment_env" {
  type = string

  validation {
    condition     = contains(["integ", "prod"], var.uid_deployment_env)
    error_message = "Allowed values for uid_deployment_env are \"integ\" or \"prod\"."
  }
}

variable "uid_operator_key" {
  type = string
}

variable "uid_operator_key_secret_name" {
  type    = string
  default = "secret-operator-key"
}

variable "max_replicas" {
  type    = number
  default = 5
}

variable "min_replicas" {
  type    = number
  default = 1
}

variable "debug_mode" {
  type    = bool
  default = false
}

variable "ssl" {
  type    = bool
  default = false
}

variable "ssl_certificate_domains" {
  type    = list(string)
  default = []
}
