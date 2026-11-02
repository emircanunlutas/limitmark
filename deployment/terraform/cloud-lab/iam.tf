resource "google_service_account" "app" {
  project      = var.project_id
  account_id   = "limitmark-lab-app"
  display_name = "LimitMark laboratory Cloud Run application"

  depends_on = [google_project_service.required]
}

resource "google_service_account" "invoker" {
  project      = var.project_id
  account_id   = "limitmark-lab-invoker"
  display_name = "LimitMark laboratory Cloud Run invoker"

  depends_on = [google_project_service.required]
}

resource "google_service_account" "postgres" {
  project      = var.project_id
  account_id   = "limitmark-lab-postgres"
  display_name = "LimitMark laboratory PostgreSQL VM"

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "app_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.app.email}"

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "app_secret_accessor" {
  for_each  = google_secret_manager_secret.lab
  project   = var.project_id
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.app.email}"
}

resource "google_compute_subnetwork_iam_member" "cloud_run_network_user" {
  project    = var.project_id
  region     = var.region
  subnetwork = data.google_compute_subnetwork.lab.name
  role       = "roles/compute.networkUser"
  member     = "serviceAccount:service-${data.google_project.current.number}@serverless-robot-prod.iam.gserviceaccount.com"

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  name     = var.cloud_run_service_name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.invoker.email}"

  depends_on = [google_cloud_run_v2_service.lab]
}

# generateIdToken on the invoker's own identity requires iam.serviceAccounts.getOpenIdToken.
# roles/iam.serviceAccountOpenIdTokenCreator contains only that permission (it cannot mint
# access tokens, sign blobs, or impersonate), and it is bound to this single service account.
resource "google_service_account_iam_member" "invoker_self_open_id_token" {
  service_account_id = google_service_account.invoker.name
  role               = "roles/iam.serviceAccountOpenIdTokenCreator"
  member             = "serviceAccount:${google_service_account.invoker.email}"
}
