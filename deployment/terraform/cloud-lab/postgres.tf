resource "google_compute_disk" "postgres" {
  project = var.project_id
  name    = "limitmark-lab-postgres-disk"
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.postgres_disk_size_gb

  image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64"

  depends_on = [google_project_service.required]
}

resource "google_compute_instance" "postgres" {
  project      = var.project_id
  name         = "limitmark-lab-postgres"
  zone         = var.zone
  machine_type = var.postgres_machine_type
  tags         = ["limitmark-lab-postgres"]

  boot_disk {
    source      = google_compute_disk.postgres.id
    auto_delete = false
  }

  network_interface {
    subnetwork = data.google_compute_subnetwork.lab.id
  }

  service_account {
    email  = google_service_account.postgres.email
    scopes = ["https://www.googleapis.com/auth/logging.write"]
  }

  metadata_startup_script = templatefile("${path.module}/postgres-bootstrap.sh", {
    database_name = var.postgres_database_name
    database_user = var.postgres_database_user
  })

  scheduling {
    automatic_restart   = false
    on_host_maintenance = "MIGRATE"
  }
}

resource "google_compute_firewall" "postgres" {
  project = var.project_id
  name    = "limitmark-lab-cloud-run-to-postgres"
  network = data.google_compute_network.lab.name

  direction     = "INGRESS"
  priority      = 1000
  source_ranges = [data.google_compute_subnetwork.lab.ip_cidr_range]
  target_tags   = ["limitmark-lab-postgres"]

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }

  description = "Only the laboratory subnet may reach the disposable PostgreSQL VM."

  depends_on = [google_project_service.required]
}
