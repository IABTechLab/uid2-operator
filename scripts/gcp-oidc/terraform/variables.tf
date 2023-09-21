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

variable "uid_machine_type" {
  type    = string
  default = "n2d-standard-16"
}

variable "uid_operator_image" {
  type = string
}

variable "uid_deployment_env" {
  type    = string
  default = "integ"
}

variable "uid_api_token" {
  type = string
}

variable "uid_api_token_secret_name" {
  type    = string
  default = "secret-api-token"
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

variable "certificate" {
  type    = string
  default = null
}

variable "private_key" {
  type    = string
  default = null
}

