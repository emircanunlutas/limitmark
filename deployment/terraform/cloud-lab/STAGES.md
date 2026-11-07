# Reviewable execution stages (after the stage-1 foundation)

Stage 0 (applied, 31 resources) is the foundation: four APIs, three service accounts,
Artifact Registry, eleven empty secrets, their per-secret accessor bindings and the invoker
self-binding. Nothing below changes it. Every stage is a separate, explicitly approved action.

All commands use a short-lived token and never write credentials to disk:

```powershell
$env:GOOGLE_OAUTH_ACCESS_TOKEN = (gcloud auth print-access-token)   # clear it afterwards
```

## Stage 1 - Remote state (bucket creation, then migration) - DONE 2026-11-07

The bucket exists and the 31-resource state was migrated (lineage preserved, serial 29 to 30). From then on the
**remote object is authoritative**: never restore the old local snapshot over it after later applies; recover from the
latest remote version (`gcloud storage ls -a`). `terraform init` now needs
`-backend-config="bucket=limitmark-field-qual-1045646810362-tfstate" -backend-config="prefix=cloud-lab"`.

Design (no suitable bucket exists; the project has none):

| Setting | Value | Reason |
| --- | --- | --- |
| Name | `limitmark-field-qual-1045646810362-tfstate` | Project-number suffix avoids global-name collisions. |
| Location | `europe-west3`, STANDARD | Same region as everything else; state is a few tens of KB. |
| Access | Uniform bucket-level access, public access prevention **enforced** | No ACLs, no public exposure possible. |
| Versioning | On | Every state write is recoverable. |
| Lifecycle | Delete noncurrent versions 90 days after they stop being current (`state-bucket-lifecycle.json`) | Bounded growth with a long recovery window. A version-count condition is deliberately omitted: combined with age it would never delete versions on a low-write bucket. The live object is never deleted. |
| Soft delete | 7 days | Recovers an accidentally deleted live object. |
| Retention policy | **None, deliberately** | A retention policy blocks overwrites and deletes and would break every `terraform apply` and the lock file. |
| IAM | No grants beyond project Owner today. A future CI identity gets `roles/storage.objectUser` on this bucket only. | Least privilege; the bucket never gets `allUsers` or project-wide storage roles. |
| Locking | Native GCS lock object (`default.tflock`) | No extra infrastructure. |
| Credentials | Token or ADC from the environment; the backend file holds only a bucket name and prefix (no secrets) | Nothing secret in Git. |

The bucket is created with `gcloud` rather than from this module, so the state bucket never
lives in the state it protects.

### 1a. Create the bucket (needs approval; not run)

```powershell
$B = "limitmark-field-qual-1045646810362-tfstate"
gcloud storage buckets create "gs://$B" --project limitmark-field-qual --location europe-west3 `
  --default-storage-class STANDARD --uniform-bucket-level-access --public-access-prevention `
  --soft-delete-duration 7d
gcloud storage buckets update "gs://$B" --versioning --lifecycle-file state-bucket-lifecycle.json
gcloud storage buckets describe "gs://$B" --format="yaml(uniform_bucket_level_access,public_access_prevention,versioning_enabled,lifecycle_config,soft_delete_policy,location)"
```

Expected: uniform `true`, prevention `enforced`, versioning `true`, location `EUROPE-WEST3`.

### 1b. Migrate the existing local state (needs approval; not run)

Preconditions: nothing else is running Terraform; the working tree has no uncommitted `.tf` change
that is not intended.

1. **Freeze and record.** Copy `terraform.tfstate` to a fresh timestamped file outside Git
   (`$env:USERPROFILE\.limitmark-state-backup\`), then record the count, `serial` and `lineage`:
   `terraform state list | Measure-Object` must report **31**.
2. Copy `backend.gcs.hcl.example` to `backend.gcs.hcl`; add `backend "gcs" {}` inside the
   `terraform {}` block of `versions.tf` (reviewed in the same change as the migration).
3. `terraform init -migrate-state -backend-config=backend.gcs.hcl`; answer `yes` to copy the
   existing state. Terraform copies the state; the pre-migration backup from step 1 is the authoritative rollback copy, not Terraform's own leftovers.
4. **Verify.** (a) `terraform state list` still reports 31. (b) The remote object's `lineage`
   equals the recorded lineage and its `serial` is >= the recorded one:
   `gcloud storage cat gs://$B/cloud-lab/default.tfstate` parsed locally (never printed). (c) A
   stage-0 targeted plan (the same `-target` list used for the foundation) reports **No changes**.
   (d) `gcloud storage objects list gs://$B/cloud-lab/ --all-versions` shows the version.
5. Keep the local file and the pre-migration backup. Do not delete them until a full release cycle
   has passed on the remote state.

**Rollback** (at any point before step 5): remove the `backend` block, restore the recorded backup
over `terraform.tfstate`, and run `terraform init -reconfigure`. Confirm `state list` is 31 and a
targeted plan shows no changes. The bucket and its versions are left in place and can be deleted
later. Never run `terraform apply` while the backend configuration is in doubt.

Risk: if two people migrate concurrently the second `init` sees the remote state and prompts;
decline and investigate instead of overwriting.

## Stage 2 - PostgreSQL VM, disk and firewalls - DONE 2026-11-07

Exact scope (6 creates, 0 updates, 0 replaces, 0 deletes):

| Resource | Notes |
| --- | --- |
| `google_compute_disk.postgres` | New `pd-balanced` 20 GB from `ubuntu-2404-lts-amd64`; `auto_delete=false` on the VM so data survives instance recreation. |
| `google_compute_instance.postgres` | `e2-standard-2` in `europe-west3-a`, no external address, OS Login on, project SSH keys blocked, runs as `limitmark-lab-postgres` with only the `logging.write` scope. |
| `google_compute_firewall.postgres` | tcp:5432 from `10.80.0.0/24` to tag `limitmark-lab-postgres` only. |
| `google_compute_firewall.postgres_iap_ssh` | tcp:22 from the IAP range `35.235.240.0/20` to the same tag only. |
| `google_project_service.required["compute..."]`, `["iap..."]` | Both APIs are already enabled; this only records them in state. |

Use these explicit targets; because every resource declares `depends_on` on the whole service set,
omitting the two service targets drags in `run.googleapis.com`, `logging` and `monitoring` as well:

```powershell
terraform plan -input=false -var-file=<vars> -out=stage2-vm.tfplan `
  '-target=google_project_service.required["compute.googleapis.com"]' `
  '-target=google_project_service.required["iap.googleapis.com"]' `
  -target=google_compute_disk.postgres -target=google_compute_instance.postgres `
  -target=google_compute_firewall.postgres -target=google_compute_firewall.postgres_iap_ssh
```

Sizing: the workload is tiny (insert-only, at most 4 concurrent requests, small tables), so memory
and disk are not the constraint. The constraint is **CPU consistency**: `e2-micro/small/medium` are
shared-core and throttle after burst credits, which would show up as database latency in capacity
measurements. `e2-standard-2` (2 dedicated vCPU, 8 GB) removes that variable; `variables.tf` now
rejects shared-core types. The disk is online-resizable if it ever needs to grow.

Operator permissions (not granted by Terraform; the operator is currently project Owner, which
already covers all of them): `roles/iap.tunnelResourceAccessor`, `roles/compute.osLogin`,
`roles/iam.serviceAccountUser` on `limitmark-lab-postgres`, and instance/serial-port read access.
A non-Owner operator needs exactly these.

Preconditions verified read-only: Cloud NAT `limitmark-lab-nat` on router `limitmark-lab-router`
(europe-west3, lab VPC) uses `ALL_SUBNETWORKS_ALL_IP_RANGES`, so it covers `limitmark-lab-subnet`;
`apt` egress still needs a live test after the VM boots (the bootstrap fails fast if it cannot reach
mirrors). Quotas are ample (CPUS 0/200, E2_CPUS 0/24, SSD_TOTAL_GB 90/500, IN_USE_ADDRESSES 0/8).

## Stage 3 - Bootstrap, database and application prerequisites - DONE 2026-11-07

Operator procedure and the commands are in `README.md` ("Operator access and CA export",
"Database initialization"). Verification criteria, in order:

1. Serial output (`get-serial-port-output`) shows the bootstrap finished and one `LAB_CA_FINGERPRINT`.
2. `postgresql@16-main` is active; `ss -ltn` shows 5432 only on the private address, not `0.0.0.0`.
3. The server certificate SAN is exactly the VM private IP and chains to the CA
   (`openssl verify -CAfile ... -verify_ip <ip>`).
4. Certificate persistence: after `sudo reboot`, the CA fingerprint is unchanged and the server
   certificate is not reissued.
5. IAP SSH works with OS Login; no external IP; project SSH keys ignored.
6. Public CA exported over IAP SCP; SHA-256 equals the serial-console fingerprint; contains no private key.
7. Passwords set interactively for both roles (never in Terraform, metadata, argv or history).
8. Migrations applied as the migrator, then `postgres-runtime-grants.sql`.
9. Negative checks as the runtime role must fail: `UPDATE`, `DELETE`, `CREATE TABLE`, `SELECT` on
   `inquiry_events`, `notification_outbox`, `admin_notes`; non-TLS connection rejected; wrong-hostname
   `verify-full` rejected. Positive: the three `INSERT`s and the column-limited `SELECT` succeed.
10. Only then create the CA and database-URL secret versions; the Cloud Run connectivity check
    (Direct VPC egress to the private IP, `verify-full`) belongs to the Cloud Run stage.

### Operator notes learned while executing stage 3 (Windows, gcloud with bundled PuTTY)

- `gcloud compute ssh` does not forward stdin to the remote command, so never pipe passwords or SQL into it.
  Ship a short-lived `0600` file with `gcloud compute scp` and shred it on the VM in the same command.
- `gcloud compute scp` mistakes a `C:\` source path for a host and fails on `~`: run it from the file's directory and
  use home-relative remote paths (`host:file`, not `host:~/file`).
- The first connection asks to cache the host key. Compare the ED25519 fingerprint printed by
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` with the `cloud-init` host-key lines in the serial output.
- Applying `drizzle/*.sql` with `psql` does not populate `drizzle.__drizzle_migrations`; rerun only new files.
- The migrator password is not stored anywhere. Reset it with an `ALTER ROLE` file as above when migrations are needed.
