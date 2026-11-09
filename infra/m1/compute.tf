# Disposable VMs. Every VM: private address only, shielded, OS Login, no project SSH keys, no service-account keys, and a PROVIDER-enforced maximum lifetime
# (max_run_duration with DELETE) that does not depend on any of our code, billing data or kill switch. Disks are deleted with the instance.
# Fresh-instance rule: a run gets new instances from the pinned image (names carry the run id); an instance is never started twice, and the previous run's
# instances must be gone (destroy) before the next apply. The instance id and creation timestamp go into the pre-run commitment.
locals {
  vms = {
    target    = { project = "target", type = "e2-standard-2", subnet = "target", tags = ["m1-target"], sa = "target", image = var.target_image }
    generator = { project = "generator", type = "e2-standard-2", subnet = "generator", tags = ["m1-generator"], sa = "generator", image = var.target_image }
    canary    = { project = "observer", type = "e2-small", subnet = "observer", tags = ["m1-canary"], sa = "canary", image = var.target_image }
    collector = { project = "observer", type = "e2-small", subnet = "observer", tags = ["m1-collector"], sa = "collector", image = var.target_image }
  }
}

resource "google_compute_instance" "vm" {
  for_each     = local.vms
  project      = google_project.p[each.value.project].project_id
  name         = "m1-${each.key}-${var.run_id}"
  zone         = var.zone
  machine_type = each.value.type
  tags         = each.value.tags
  labels       = merge(local.labels, { run = var.run_id, role = each.key })

  boot_disk {
    auto_delete = true
    initialize_params {
      image = each.value.image
      size  = 20
      type  = "pd-balanced"
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.subnet[each.value.subnet].id
    # no access_config block: no external address
  }
  service_account {
    email  = google_service_account.vm[each.value.sa].email
    scopes = ["https://www.googleapis.com/auth/devstorage.read_write", "https://www.googleapis.com/auth/logging.write"]
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    m1-run-id              = var.run_id
    m1-campaign-id         = var.campaign_id
    m1-role                = each.key
  }
  scheduling {
    provisioning_model          = "STANDARD"
    automatic_restart           = false
    on_host_maintenance         = "MIGRATE"
    instance_termination_action = "DELETE"
    max_run_duration {
      seconds = var.run_max_seconds
    }
  }
  allow_stopping_for_update = false
  deletion_protection       = false
  depends_on                = [google_compute_network_peering.generator_to_target, google_compute_network_peering.observer_to_target, google_service_usage_consumer_quota_override.cpus]
}

# Facts the pre-run commitment binds (read by the commitment builder; outputs only, nothing is fetched from the internet).
output "instance_facts" {
  value = { for key, vm in google_compute_instance.vm : key => { id = vm.instance_id, created = vm.creation_timestamp, project = vm.project, image = local.vms[key].image, self_link = vm.self_link, ip = vm.network_interface[0].network_ip } }
}
