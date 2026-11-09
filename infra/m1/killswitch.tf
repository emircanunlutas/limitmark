# Automated hard stops, owned by the custodian (principal C) in the evidence project. Two independent mechanisms, because a budget alert alone is not a hard stop
# (billing data lags by hours and a budget only notifies):
#   1. TTL reaper  : Cloud Scheduler calls the function every 5 minutes; it deletes any labeled disposable instance older than run_max_seconds (also deletes on a stop request).
#   2. Budget stop : a billing budget publishes to Pub/Sub; at >= 80 percent of the campaign budget the same function deletes every labeled instance in the three projects.
# Cost is bounded first by construction (fixed small VM set, vCPU quota override, provider-enforced max_run_duration), so these two are defence in depth.
data "archive_file" "killswitch" {
  type        = "zip"
  source_dir  = "${path.module}/killswitch"
  output_path = "${path.module}/.killswitch.zip"
}

resource "google_storage_bucket" "ops" {
  project                     = google_project.p["evidence"].project_id
  name                        = "${google_project.p["evidence"].project_id}-ops"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  depends_on                  = [google_project_service.evidence_apis]
}
resource "google_storage_bucket_object" "killswitch_src" {
  name   = "killswitch-${data.archive_file.killswitch.output_md5}.zip"
  bucket = google_storage_bucket.ops.name
  source = data.archive_file.killswitch.output_path
}

resource "google_pubsub_topic" "budget" {
  project    = google_project.p["evidence"].project_id
  name       = "m1-budget"
  depends_on = [google_project_service.evidence_apis]
}

resource "google_cloudfunctions2_function" "killswitch" {
  project  = google_project.p["evidence"].project_id
  name     = "m1-killswitch"
  location = var.region
  build_config {
    runtime     = "nodejs22"
    entry_point = "handle"
    source {
      storage_source {
        bucket = google_storage_bucket.ops.name
        object = google_storage_bucket_object.killswitch_src.name
      }
    }
  }
  service_config {
    available_memory      = "256M"
    timeout_seconds       = 120
    max_instance_count    = 1
    service_account_email = google_service_account.killswitch.email
    ingress_settings      = "ALLOW_INTERNAL_ONLY"
    environment_variables = {
      M1_PROJECTS         = join(",", [google_project.p["target"].project_id, google_project.p["generator"].project_id, google_project.p["observer"].project_id])
      M1_ZONE             = var.zone
      M1_RUN_MAX_SECONDS  = tostring(var.run_max_seconds)
      M1_CAMPAIGN_ID      = var.campaign_id
      M1_STOP_FRACTION    = "0.8"
     
    }
  }
  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.budget.id
    retry_policy   = "RETRY_POLICY_RETRY"
  }
  depends_on = [google_project_service.evidence_apis]
}

# The scheduler invokes the same function with a reaper message (see killswitch/decide.js).
resource "google_cloud_scheduler_job" "reaper" {
  project     = google_project.p["evidence"].project_id
  name        = "m1-ttl-reaper"
  region      = var.region
  schedule    = "*/5 * * * *"
  time_zone   = "Etc/UTC"
  pubsub_target {
    topic_name = google_pubsub_topic.budget.id
    data       = base64encode(jsonencode({ kind = "reaper" }))
  }
  depends_on = [google_project_service.evidence_apis]
}

# ---- budgets (notify only). Campaign budget over the three disposable projects; the per-run figure is a hard-stop input of the function, not a billing object.
data "google_project" "billing_projects" {
  for_each   = toset(["target", "generator", "observer", "evidence"])
  project_id = google_project.p[each.key].project_id
}
resource "google_billing_budget" "campaign" {
  billing_account = var.billing_account
  display_name    = "m1-${var.campaign_id}-campaign"
  budget_filter {
    projects = [for key, p in data.google_project.billing_projects : "projects/${p.number}"]
  }
  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.campaign_budget)
    }
  }
  threshold_rules { threshold_percent = 0.5 }
  threshold_rules { threshold_percent = 0.8 }
  threshold_rules { threshold_percent = 1.0 }
  all_updates_rule {
    pubsub_topic = google_pubsub_topic.budget.id
  }
}
