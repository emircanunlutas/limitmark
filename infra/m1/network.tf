# One VPC per project, custom subnets, default-deny both directions. Peering exists ONLY target<->generator and target<->observer:
# the generator and the observers are never peered (the generator cannot reach an observer or the evidence project, and peering is not transitive).
locals {
  cidr   = { target = "10.10.0.0/24", generator = "10.20.0.0/24", observer = "10.30.0.0/24" }
  iap    = "35.235.240.0/20"
  google = "199.36.153.4/30" # restricted.googleapis.com VIP (Private Google Access for the evidence bucket)
}

resource "google_compute_network" "vpc" {
  for_each                = toset(["target", "generator", "observer"])
  project                 = google_project.p[each.key].project_id
  name                    = "m1-${each.key}"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.compute]
}

resource "google_compute_subnetwork" "subnet" {
  for_each                 = toset(["target", "generator", "observer"])
  project                  = google_project.p[each.key].project_id
  name                     = "m1-${each.key}"
  region                   = var.region
  network                  = google_compute_network.vpc[each.key].id
  ip_cidr_range            = local.cidr[each.key]
  private_ip_google_access = true
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
  }
}

resource "google_compute_network_peering" "target_to_generator" {
  name         = "m1-target-to-generator"
  network      = google_compute_network.vpc["target"].self_link
  peer_network = google_compute_network.vpc["generator"].self_link
}
resource "google_compute_network_peering" "generator_to_target" {
  name         = "m1-generator-to-target"
  network      = google_compute_network.vpc["generator"].self_link
  peer_network = google_compute_network.vpc["target"].self_link
}
resource "google_compute_network_peering" "target_to_observer" {
  name         = "m1-target-to-observer"
  network      = google_compute_network.vpc["target"].self_link
  peer_network = google_compute_network.vpc["observer"].self_link
}
resource "google_compute_network_peering" "observer_to_target" {
  name         = "m1-observer-to-target"
  network      = google_compute_network.vpc["observer"].self_link
  peer_network = google_compute_network.vpc["target"].self_link
}

# ---- default deny (explicit, lowest priority) in every project, both directions
resource "google_compute_firewall" "deny_ingress" {
  for_each      = toset(["target", "generator", "observer"])
  project       = google_project.p[each.key].project_id
  name          = "m1-deny-all-ingress"
  network       = google_compute_network.vpc[each.key].name
  direction     = "INGRESS"
  priority      = 65000
  source_ranges = ["0.0.0.0/0"]
  deny { protocol = "all" }
}
resource "google_compute_firewall" "deny_egress" {
  for_each           = toset(["target", "generator", "observer"])
  project            = google_project.p[each.key].project_id
  name               = "m1-deny-all-egress"
  network            = google_compute_network.vpc[each.key].name
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]
  deny { protocol = "all" }
}

# ---- operators reach the VMs only through IAP on port 22 (the single ambient port the reviewed exposure policy allows)
resource "google_compute_firewall" "iap_ssh" {
  for_each      = toset(["target", "generator", "observer"])
  project       = google_project.p[each.key].project_id
  name          = "m1-allow-iap-ssh"
  network       = google_compute_network.vpc[each.key].name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = [local.iap]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# ---- target: only the generator /32 and the canary /32 reach the plane port; nothing else is allowed in
resource "google_compute_firewall" "target_plane_ingress" {
  project       = google_project.p["target"].project_id
  name          = "m1-allow-plane-from-generator-and-canary"
  network       = google_compute_network.vpc["target"].name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = [var.authorized_generator_cidr, var.canary_cidr]
  target_tags   = ["m1-target"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.plane_port)]
  }
}
# ---- target egress: origin receipts to the collector, and Google APIs through the restricted VIP; nothing else (no internet)
resource "google_compute_firewall" "target_egress_collector" {
  project            = google_project.p["target"].project_id
  name               = "m1-allow-egress-collector"
  network            = google_compute_network.vpc["target"].name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [var.collector_cidr]
  target_tags        = ["m1-target"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.collector_port)]
  }
}
resource "google_compute_firewall" "egress_google_apis" {
  for_each           = toset(["target", "generator", "observer"])
  project            = google_project.p[each.key].project_id
  name               = "m1-allow-egress-google-apis"
  network            = google_compute_network.vpc[each.key].name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [local.google]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# ---- generator: only to the authorized target /32 on the plane port
resource "google_compute_firewall" "generator_egress_target" {
  project            = google_project.p["generator"].project_id
  name               = "m1-allow-egress-target-only"
  network            = google_compute_network.vpc["generator"].name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [var.authorized_target_cidr]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.plane_port)]
  }
}

# ---- observers: the canary to the target plane port; the collector accepts receipts from the target /32 only
resource "google_compute_firewall" "canary_egress_target" {
  project            = google_project.p["observer"].project_id
  name               = "m1-allow-canary-egress-target"
  network            = google_compute_network.vpc["observer"].name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = [var.authorized_target_cidr]
  target_tags        = ["m1-canary"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.plane_port)]
  }
}
resource "google_compute_firewall" "collector_ingress_target" {
  project       = google_project.p["observer"].project_id
  name          = "m1-allow-receipts-from-target"
  network       = google_compute_network.vpc["observer"].name
  direction     = "INGRESS"
  priority      = 900
  source_ranges = [var.authorized_target_cidr]
  target_tags   = ["m1-collector"]
  allow {
    protocol = "tcp"
    ports    = [tostring(var.collector_port)]
  }
}
