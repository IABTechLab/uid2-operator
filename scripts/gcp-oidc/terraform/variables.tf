variable "project_id"{
	type        = string
}

variable "region"{
	type        = string
	default     = "asia-southeast1"
}

variable "network_name" {
  type        = string
  default     = "uid-operator"
}

variable "service_account" {
  type        = string
}

variable "uid_machine_type"{
	type        = string
	default     = "n2d-standard-16"
}

variable "uid_operator_image"{
	type        = string
}

variable "uid_deployment_env"{
	type        = string
	default     = "integ"
}

variable "uid_api_token"{
	type        = string
}

variable "max_replicas" {
	type        = number
    default     = 5
}

variable "min_replicas" {
	type        = number
    default     = 1
}

variable "debug_mode" {
	type        = bool
    default     = false
}

