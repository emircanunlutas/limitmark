variable "region" {
  type    = string
  default = "europe-west3"
}
variable "zone" {
  type    = string
  default = "europe-west3-b"
}
variable "folder_id" {
  type        = string
  description = "Dedicated folder that holds only the four M1 projects. Nothing else may live in it."
}
variable "billing_account" {
  type        = string
  description = "Billing account for the four projects."
}
variable "project_prefix" {
  type        = string
  description = "Unique prefix, 4-12 chars, for the four project ids (m1<prefix>-target, -gen, -obs, -evid)."
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{3,11}$", var.project_prefix))
    error_message = "project_prefix must be 4-12 lowercase letters/digits starting with a letter."
  }
}
variable "campaign_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]{1,31}$", var.campaign_id))
    error_message = "campaign_id is limited to 31 characters (existing campaign id limit)."
  }
}
variable "run_id" {
  type        = string
  description = "One apply per run; the run id labels every disposable resource."
}

# ---- owner decisions: no defaults on purpose, so terraform refuses to plan until the owner fixes them
variable "plane_port" {
  type        = number
  description = "Fixed Defense Plane ingress port of the reviewed run configuration (never 22/80/443/3000/5432/55416/55417)."
  validation {
    condition     = !contains([22, 80, 443, 3000, 5432, 55416, 55417], var.plane_port) && var.plane_port > 1023 && var.plane_port < 65536
    error_message = "plane_port must not be one of the forbidden plane/ambient ports."
  }
}
variable "collector_port" {
  type    = number
  default = 8443
}
variable "authorized_target_cidr" {
  type        = string
  description = "The explicitly authorized disposable target address as a /32 inside 10.10.0.0/24 (owner decision O-1). The VM is created with exactly this address."
  validation {
    condition     = can(regex("^10[.]10[.]0[.](?:[2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])/32$", var.authorized_target_cidr))
    error_message = "A single /32 inside 10.10.0.0/24 (host .2 to .253)."
  }
}
variable "authorized_generator_cidr" {
  type = string
  validation {
    condition     = can(regex("^10[.]20[.]0[.](?:[2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])/32$", var.authorized_generator_cidr))
    error_message = "A single /32 inside 10.20.0.0/24 (host .2 to .253)."
  }
}
variable "canary_cidr" {
  type = string
  validation {
    condition     = can(regex("^10[.]30[.]0[.](?:[2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])/32$", var.canary_cidr))
    error_message = "A single /32 inside 10.30.0.0/24 (host .2 to .253)."
  }
}
variable "collector_cidr" {
  type = string
  validation {
    condition     = can(regex("^10[.]30[.]0[.](?:[2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-3])/32$", var.collector_cidr)) && var.collector_cidr != var.canary_cidr
    error_message = "A single /32 inside 10.30.0.0/24, different from the canary."
  }
}
variable "target_image" {
  type        = string
  description = "Pinned image (by id) of the target, built from the recorded clean commit."
}
variable "generator_image" {
  type        = string
  description = "Pinned image (by id) of the external generator."
}
variable "observer_image" {
  type        = string
  description = "Pinned image (by id) of the canary and the origin receipt collector (never the target image)."
}
variable "create_vms" {
  type        = bool
  default     = false
  description = "Teardown switch. true creates the run's four VMs; applying with false deletes ONLY the VMs. Projects, network, IAM and evidence are campaign-level and are protected by prevent_destroy."
}
variable "operators_group" {
  type        = string
  description = "Group that controls the target and generator (principal A)."
}
variable "observers_group" {
  type        = string
  description = "Group that controls the canary and collector (principal B). Must not overlap operators_group."
}
variable "custodian_group" {
  type        = string
  description = "Group that custodies evidence and owns the kill switch (principal C). Must overlap neither of the others."
}
variable "run_max_seconds" {
  type        = number
  default     = 7200
  description = "Provider-enforced maximum lifetime of every disposable VM (DELETE on expiry). The level itself runs 60 seconds; the target policy needs 15 minutes remaining."
  validation {
    condition     = var.run_max_seconds >= 1800 && var.run_max_seconds <= 14400
    error_message = "Between 30 minutes and 4 hours."
  }
}
variable "budget_currency" {
  type        = string
  default     = "TRY"
  description = "Must equal the billing account currency."
}
variable "run_budget" {
  type    = number
  default = 750
}
variable "campaign_budget" {
  type    = number
  default = 3000
}
variable "retention_days" {
  type    = number
  default = 30
}
variable "lock_retention" {
  type        = bool
  default     = false
  description = "Retention LOCK is irreversible. Stays false until the owner decides; activating it is outside this cycle."
}
variable "cpu_quota" {
  type        = number
  default     = 8
  description = "Regional vCPU cap per disposable project (structural cost bound)."
}
