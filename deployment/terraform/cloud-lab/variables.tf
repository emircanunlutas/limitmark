variable "project_id" {
  type        = string
  description = "Google Cloud project hosting the isolated laboratory."
  default     = "limitmark-field-qual"
}

variable "region" {
  type    = string
  default = "europe-west3"
}

variable "zone" {
  type    = string
  default = "europe-west3-a"
}

variable "vpc_name" {
  type    = string
  default = "limitmark-lab-vpc"
}

variable "subnet_name" {
  type    = string
  default = "limitmark-lab-subnet"
}

variable "cloud_run_service_name" {
  type    = string
  default = "limitmark-public-inquiry-lab"
}

variable "cloud_run_image" {
  type        = string
  description = "Immutable Artifact Registry image reference supplied at deployment time."
}

variable "lab_public_hostname" {
  type = string
}

variable "lab_origin_hostname" {
  type = string
}

variable "lab_admission_hostname" {
  type = string
}

variable "lab_deployment_id" {
  type = string
}

variable "postgres_database_name" {
  type    = string
  default = "limitmark_lab"
}

variable "postgres_database_user" {
  type    = string
  default = "limitmark_lab_app"
}

variable "postgres_disk_size_gb" {
  type    = number
  default = 20
}

variable "postgres_machine_type" {
  type    = string
  default = "e2-small"
}
