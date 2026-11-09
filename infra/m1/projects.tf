locals {
  projects = { target = "m1${var.project_prefix}-target", generator = "m1${var.project_prefix}-gen", observer = "m1${var.project_prefix}-obs", evidence = "m1${var.project_prefix}-evid" }
  labels   = { campaign = var.campaign_id, purpose = "m1-qualification", disposable = "true" }
}

resource "google_project" "p" {
  for_each            = local.projects
  name                = each.value
  project_id          = each.value
  folder_id           = var.folder_id
  billing_account     = var.billing_account
  deletion_policy     = "DELETE"
  auto_create_network = false # the default network (permissive firewall) is never created
  labels              = local.labels
}

resource "google_project_service" "compute" {
  for_each = local.projects
  project  = google_project.p[each.key].project_id
  service  = "compute.googleapis.com"
}
resource "google_project_service" "iap" {
  for_each = toset(["target", "generator", "observer"])
  project  = google_project.p[each.key].project_id
  service  = "iap.googleapis.com"
}
resource "google_project_service" "evidence_apis" {
  for_each = toset(["storage.googleapis.com", "cloudfunctions.googleapis.com", "run.googleapis.com", "cloudbuild.googleapis.com", "cloudscheduler.googleapis.com", "pubsub.googleapis.com", "cloudbilling.googleapis.com", "billingbudgets.googleapis.com"])
  project  = google_project.p["evidence"].project_id
  service  = each.value
}

# Safety constraints scoped to the dedicated folder only (never the organization).
resource "google_folder_organization_policy" "no_sa_keys" {
  folder     = var.folder_id
  constraint = "constraints/iam.disableServiceAccountKeyCreation"
  boolean_policy { enforced = true }
}
resource "google_folder_organization_policy" "os_login" {
  folder     = var.folder_id
  constraint = "constraints/compute.requireOsLogin"
  boolean_policy { enforced = true }
}
resource "google_folder_organization_policy" "no_external_ip" {
  folder     = var.folder_id
  constraint = "constraints/compute.vmExternalIpAccess"
  list_policy {
    deny { all = true }
  }
}
resource "google_folder_organization_policy" "shielded" {
  folder     = var.folder_id
  constraint = "constraints/compute.requireShieldedVm"
  boolean_policy { enforced = true }
}

# Structural cost bound: a regional vCPU cap. Even a runaway apply cannot exceed it.
resource "google_service_usage_consumer_quota_override" "cpus" {
  for_each       = toset(["target", "generator", "observer"])
  project        = google_project.p[each.value].project_id
  service        = "compute.googleapis.com"
  metric         = urlencode("compute.googleapis.com/cpus")
  limit          = urlencode("/project/region")
  override_value = tostring(var.cpu_quota)
  dimensions     = { region = var.region }
  force          = true
  depends_on     = [google_project_service.compute]
}
