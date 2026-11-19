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
  description = "Application image: Artifact Registry reference pinned by digest, supplied at deployment time."

  validation {
    condition     = can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/[a-z][a-z0-9-]+/limitmark/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.cloud_run_image))
    error_message = "Use an Artifact Registry image in the 'limitmark' repository pinned by digest (name@sha256:<64 hex>); tags are mutable."
  }
}

variable "otel_collector_image" {
  type        = string
  description = "OpenTelemetry collector sidecar image mirrored into Artifact Registry and pinned by digest (Cloud Run does not pull the mutable Docker Hub tag)."

  validation {
    condition     = can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/[a-z][a-z0-9-]+/limitmark/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.otel_collector_image))
    error_message = "Mirror the collector into the 'limitmark' Artifact Registry repository and pin it by digest."
  }
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
  type        = string
  description = "Dedicated-core by default: shared-core types (e2-micro/small/medium) throttle CPU after burst credits run out, which would distort capacity measurements."
  default     = "e2-standard-2"

  validation {
    condition     = !contains(["e2-micro", "e2-small", "e2-medium"], var.postgres_machine_type)
    error_message = "Use a dedicated-core machine type so database latency is not dominated by burst-credit throttling."
  }
}

variable "postgres_migration_user" {
  type        = string
  description = "Database owner role used only for reviewed migrations. It is created without a password."
  default     = "limitmark_lab_migrator"

  validation {
    condition     = can(regex("^[a-z_][a-z0-9_]{0,62}$", var.postgres_migration_user)) && var.postgres_migration_user != var.postgres_database_user
    error_message = "The migration role must be a simple lowercase identifier distinct from the application role."
  }
}
