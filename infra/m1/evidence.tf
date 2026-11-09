# Append-only evidence storage, separately controlled (principal C, own project). Prefixes: a/ controller (commitment, finalized package digest), b/ observers
# (canary results, origin receipts, heartbeats, collector declaration, provenance), c/ custodian (seals and exports manifests).
# 30 days is a PROVISIONAL retention. The retention policy below is a policy, not a lock: lock_retention is false, so nothing irreversible happens. Bucket creation here is a
# definition only and has not been applied.
resource "google_storage_bucket" "evidence" {
  project                     = google_project.p["evidence"].project_id
  name                        = "${google_project.p["evidence"].project_id}-evidence"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = local.labels
  lifecycle { prevent_destroy = true }

  versioning { enabled = true }

  retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = var.lock_retention
  }
  soft_delete_policy { retention_duration_seconds = 604800 }
  depends_on = [google_project_service.evidence_apis]
}

# Data-access audit logs for the bucket go to a log bucket in the same project; writes by A and B are therefore attributable.
resource "google_project_iam_audit_config" "storage" {
  project = google_project.p["evidence"].project_id
  service = "storage.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
