terraform {
  # Bucket and prefix are supplied with -backend-config (see backend.gcs.hcl.example and STAGES.md).
  backend "gcs" {}

  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
