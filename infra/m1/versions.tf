# DEFINITIONS ONLY. Not applied, not planned against any account. No Terraform state exists. Applying requires the owner written GO for the exact campaign
# (M1-QUALIFICATION-GO-NOGO.md) and is outside the authorization of the cycle that wrote this file. `terraform` was not installed when this was written, so it is UNVALIDATED.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 6.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 6.0" }
    archive     = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

# No default project: every resource names its project explicitly so that nothing can be created in a project the owner did not list.
provider "google" {
  region = var.region
  zone   = var.zone
}

# google_service_usage_consumer_quota_override exists only in the beta provider.
provider "google-beta" {
  region = var.region
  zone   = var.zone
}
