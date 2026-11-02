locals {
  required_services = toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iap.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])

  secret_names = toset([
    "limitmark-lab-admission-release-key-id",
    "limitmark-lab-admission-release-rpc-key",
    "limitmark-lab-database-url",
    "limitmark-lab-database-ca-cert",
    "limitmark-lab-ingress-audience",
    "limitmark-lab-ingress-public-keys",
    "limitmark-lab-ingress-request-binding-key",
    "limitmark-lab-otel-collector-config",
    "limitmark-lab-public-origin-secret",
    "limitmark-lab-turnstile-secret-key",
    "limitmark-lab-turnstile-site-key",
  ])
}

data "google_project" "current" {
  project_id = var.project_id
}

data "google_compute_network" "lab" {
  name    = var.vpc_name
  project = var.project_id
}

data "google_compute_subnetwork" "lab" {
  name    = var.subnet_name
  region  = var.region
  project = var.project_id
}

resource "google_project_service" "required" {
  for_each           = local.required_services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "lab" {
  project       = var.project_id
  location      = var.region
  repository_id = "limitmark"
  description   = "Disposable LimitMark Cloud Run laboratory images."
  format        = "DOCKER"

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret" "lab" {
  for_each  = local.secret_names
  project   = var.project_id
  secret_id = each.value

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}
