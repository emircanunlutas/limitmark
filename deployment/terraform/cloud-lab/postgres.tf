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

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
  }

  metadata_startup_script = templatefile("${path.module}/postgres-bootstrap.sh", {
    database_name  = var.postgres_database_name
    database_user  = var.postgres_database_user
    migration_user = var.postgres_migration_user
    subnet_cidr    = data.google_compute_subnetwork.lab.ip_cidr_range
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

# Operator access without a public address: only Google IAP TCP forwarding may reach SSH.
# Using it additionally requires roles/iap.tunnelResourceAccessor and OS Login roles for the operator.
resource "google_compute_firewall" "postgres_iap_ssh" {
  project = var.project_id
  name    = "limitmark-lab-iap-ssh-to-postgres"
  network = data.google_compute_network.lab.name

  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["limitmark-lab-postgres"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  description = "IAP TCP forwarding range only; operator SSH to the disposable PostgreSQL VM."

  depends_on = [google_project_service.required]
}
