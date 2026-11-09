# Three principals, no shared credential, no service-account keys (org policy), no human role on locked evidence.
#   A operators_group: controls target + generator. No role on the evidence bucket except a create-only prefix for its own commitment.
#   B observers_group: controls canary + collector. Create-only on its own prefix. No role on target or generator projects.
#   C custodian_group: evidence project owner of the bucket and the kill switch. Cannot start load.
locals {
  bucket_objects = "projects/_/buckets/${google_storage_bucket.evidence.name}/objects"
}

resource "google_service_account" "vm" {
  for_each     = { target = "target", generator = "generator", canary = "observer", collector = "observer" }
  project      = google_project.p[each.value].project_id
  account_id   = "m1-${each.key}"
  display_name = "M1 ${each.key} (disposable, no keys)"
}

# ---- operators (A): IAP tunnel + OS Login administrator on target and generator only
resource "google_project_iam_member" "operators_login" {
  for_each = toset(["target", "generator"])
  project  = google_project.p[each.value].project_id
  role     = "roles/compute.osAdminLogin"
  member   = var.operators_group
}
resource "google_project_iam_member" "operators_iap" {
  for_each = toset(["target", "generator"])
  project  = google_project.p[each.value].project_id
  role     = "roles/iap.tunnelResourceAccessor"
  member   = var.operators_group
}
resource "google_project_iam_member" "operators_vm_admin" {
  for_each = toset(["target", "generator"])
  project  = google_project.p[each.value].project_id
  role     = "roles/compute.instanceAdmin.v1"
  member   = var.operators_group
}
# ---- observers (B): the same on the observer project only
resource "google_project_iam_member" "observers_login" {
  project = google_project.p["observer"].project_id
  role    = "roles/compute.osAdminLogin"
  member  = var.observers_group
}
resource "google_project_iam_member" "observers_iap" {
  project = google_project.p["observer"].project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = var.observers_group
}
resource "google_project_iam_member" "observers_vm_admin" {
  project = google_project.p["observer"].project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = var.observers_group
}

# ---- evidence writes: create-only, one prefix per principal (storage.objectCreator cannot overwrite or delete)
resource "google_storage_bucket_iam_member" "write_a" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.vm["target"].email}"
  condition {
    title      = "prefix-a-only"
    expression = "resource.name.startsWith(\"${local.bucket_objects}/a/\")"
  }
}
resource "google_storage_bucket_iam_member" "write_b" {
  for_each = toset(["canary", "collector"])
  bucket   = google_storage_bucket.evidence.name
  role     = "roles/storage.objectCreator"
  member   = "serviceAccount:${google_service_account.vm[each.value].email}"
  condition {
    title      = "prefix-b-only"
    expression = "resource.name.startsWith(\"${local.bucket_objects}/b/\")"
  }
}
# ---- custodian (C): read, and seal (the seal is the custodian-written c/ prefix plus, later and only by owner decision, the retention lock)
resource "google_storage_bucket_iam_member" "custodian_read" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = var.custodian_group
}
resource "google_storage_bucket_iam_member" "custodian_write" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = var.custodian_group
  condition {
    title      = "prefix-c-only"
    expression = "resource.name.startsWith(\"${local.bucket_objects}/c/\")"
  }
}
resource "google_project_iam_member" "custodian_bucket_admin" {
  project = google_project.p["evidence"].project_id
  role    = "roles/storage.admin"
  member  = var.custodian_group
  condition {
    title      = "this-bucket-only"
    expression = "resource.name == \"projects/_/buckets/${google_storage_bucket.evidence.name}\" || resource.name.startsWith(\"projects/_/buckets/${google_storage_bucket.evidence.name}/\")"
  }
}

# ---- kill switch (C): may list, stop and delete instances in the THREE disposable projects; no role on the evidence bucket
resource "google_service_account" "killswitch" {
  project      = google_project.p["evidence"].project_id
  account_id   = "m1-killswitch"
  display_name = "M1 kill switch (custodian-owned)"
}
resource "google_project_iam_custom_role" "kill" {
  for_each    = toset(["target", "generator", "observer"])
  project     = google_project.p[each.value].project_id
  role_id     = "m1KillSwitch"
  title       = "M1 kill switch"
  permissions = ["compute.instances.list", "compute.instances.get", "compute.instances.delete", "compute.instances.stop", "compute.disks.list", "compute.zoneOperations.get", "compute.globalOperations.get"]
}
resource "google_project_iam_member" "kill" {
  for_each = toset(["target", "generator", "observer"])
  project  = google_project.p[each.value].project_id
  role     = google_project_iam_custom_role.kill[each.value].id
  member   = "serviceAccount:${google_service_account.killswitch.email}"
}
# Detaching billing would need a billing-account-level role that covers every project on the account (broader than this campaign). It is deliberately NOT granted;
# the kill switch deletes instances (disks auto-delete) instead, and removing the projects after the campaign is a custodian action. Owner decision O-9.
