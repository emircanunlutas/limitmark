# Private-only VMs reach Cloud Storage through Private Google Access. Egress is default-deny and only the restricted VIP (199.36.153.4/30) is allowed, so the API names
# MUST resolve to that VIP; without these private zones storage.googleapis.com resolves to public addresses and the (correct) egress deny would silently break evidence upload.
resource "google_dns_managed_zone" "googleapis" {
  for_each   = toset(["target", "generator", "observer"])
  project    = google_project.p[each.key].project_id
  name       = "m1-googleapis"
  dns_name   = "googleapis.com."
  visibility = "private"
  private_visibility_config {
    networks { network_url = google_compute_network.vpc[each.key].id }
  }
  depends_on = [google_project_service.dns]
}

resource "google_dns_record_set" "restricted_a" {
  for_each     = toset(["target", "generator", "observer"])
  project      = google_project.p[each.key].project_id
  managed_zone = google_dns_managed_zone.googleapis[each.key].name
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}

resource "google_dns_record_set" "wildcard_cname" {
  for_each     = toset(["target", "generator", "observer"])
  project      = google_project.p[each.key].project_id
  managed_zone = google_dns_managed_zone.googleapis[each.key].name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}
