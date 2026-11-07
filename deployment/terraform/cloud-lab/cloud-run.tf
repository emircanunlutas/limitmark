locals {
  cloud_run_secrets = {
    LAB_PUBLIC_ORIGIN_SECRET        = "limitmark-lab-public-origin-secret"
    LAB_DATABASE_URL                = "limitmark-lab-database-url"
    LAB_DATABASE_CA_CERT            = "limitmark-lab-database-ca-cert"
    LAB_INGRESS_AUDIENCE            = "limitmark-lab-ingress-audience"
    LAB_INGRESS_PUBLIC_KEYS         = "limitmark-lab-ingress-public-keys"
    LAB_INGRESS_REQUEST_BINDING_KEY = "limitmark-lab-ingress-request-binding-key"
    LAB_ADMISSION_RELEASE_KEY_ID    = "limitmark-lab-admission-release-key-id"
    LAB_ADMISSION_RELEASE_RPC_KEY   = "limitmark-lab-admission-release-rpc-key"
    LAB_TURNSTILE_SITE_KEY          = "limitmark-lab-turnstile-site-key"
    LAB_TURNSTILE_SECRET_KEY        = "limitmark-lab-turnstile-secret-key"
  }
}

resource "google_cloud_run_v2_service" "lab" {
  project             = var.project_id
  name                = var.cloud_run_service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    service_account                  = google_service_account.app.email
    timeout                          = "30s"
    max_instance_request_concurrency = 2

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"

      network_interfaces {
        network    = data.google_compute_network.lab.id
        subnetwork = data.google_compute_subnetwork.lab.id
      }
    }

    containers {
      name  = "app"
      image = var.cloud_run_image

      depends_on = ["collector"]

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      env {
        name  = "PORT"
        value = "8080"
      }
      env {
        name  = "LIMITMARK_RUNTIME"
        value = "cloud-run-lab"
      }
      env {
        name  = "REQUEST_SUBMISSION_MODE"
        value = "postgres"
      }
      env {
        name  = "ENABLE_PERSISTENT_SUBMISSIONS"
        value = "true"
      }
      env {
        name  = "PUBLIC_ORIGIN_PROTECTION"
        value = "required"
      }
      env {
        name  = "PUBLIC_INQUIRY_OTEL_METRICS"
        value = "true"
      }
      env {
        name  = "PUBLIC_INQUIRY_OTEL_METRICS_ENDPOINT"
        value = "http://127.0.0.1:4318/v1/metrics"
      }
      env {
        name  = "PUBLIC_INQUIRY_OTEL_METRICS_SERVICE"
        value = var.cloud_run_service_name
      }
      env {
        name  = "LAB_PUBLIC_HOSTNAME"
        value = var.lab_public_hostname
      }
      env {
        name  = "LAB_ORIGIN_HOSTNAME"
        value = var.lab_origin_hostname
      }
      env {
        name  = "LAB_ADMISSION_OIDC_AUDIENCE"
        value = "https://${var.lab_admission_hostname}"
      }
      env {
        name  = "LAB_DEPLOYMENT_ID"
        value = var.lab_deployment_id
      }
      env {
        name  = "LAB_ADMISSION_RELEASE_ID"
        value = var.lab_deployment_id
      }
      env {
        name  = "LAB_ADMISSION_SERVICE_URL"
        value = "https://${var.lab_admission_hostname}/"
      }
      env {
        name  = "LAB_DATABASE_POOL_MAX"
        value = "5"
      }
      env {
        name  = "LAB_TURNSTILE_EXPECTED_HOSTNAME"
        value = var.lab_public_hostname
      }

      dynamic "env" {
        for_each = local.cloud_run_secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.lab[env.value].id
              version = "latest"
            }
          }
        }
      }
    }

    containers {
      name  = "collector"
      image = var.otel_collector_image
      args  = ["--config=/etc/otelcol-contrib/config.yaml"]

      resources {
        limits = {
          cpu    = "0.25"
          memory = "128Mi"
        }
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      volume_mounts {
        name       = "collector-config"
        mount_path = "/etc/otelcol-contrib"
      }
    }

    volumes {
      name = "collector-config"

      secret {
        secret = google_secret_manager_secret.lab["limitmark-lab-otel-collector-config"].id
        items {
          version = "latest"
          path    = "config.yaml"
        }
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.app_secret_accessor,
    google_compute_subnetwork_iam_member.cloud_run_network_user,
  ]
}
