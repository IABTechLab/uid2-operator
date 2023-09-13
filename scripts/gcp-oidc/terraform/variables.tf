variable "project_id"{
	type        = string
	default     = "uid2-test"
}

variable "region"{
	type        = string
	default     = "asia-southeast1"
}

variable "zone"{
	type        = string
	default     = "asia-southeast1-a"
}

variable "uid_machine_type"{
	type        = string
	default     = "n2d-standard-2"
}

variable "uid_operator_image"{
	type        = string
	default     = "ghcr.io/iabtechlab/uid2-operator@sha256:39274ed4cc3d696bae16183614780617f7bd8b241aa53dac1017ed88b4b6282b"
}

variable "uid_deployment_env"{
	type        = string
	default     = "integ"
}

variable "uid_api_token"{
	type        = string
	default     = "OPINTJ1O8j9x4U0CYIqC8ejsVps2Fxd0Iv+JSpfK/Fpz7xQU="
}
