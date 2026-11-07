# LimitMark Cloud laboratory Terraform definition

This directory defines the disposable `europe-west3` laboratory resources.
It references the existing `limitmark-lab-vpc` and `limitmark-lab-subnet`; it
does not recreate either network.

The configuration creates API service declarations, a Docker Artifact Registry
repository, empty Secret Manager containers, dedicated service accounts, an
IAM-authenticated Cloud Run service, a fresh private PostgreSQL VM/disk, and a
TCP/5432 firewall rule limited to the laboratory subnet, plus an IAP-only SSH rule.

## Secret handling

Terraform creates secret **containers only**. Never add secret versions,
database passwords, service-account keys, or certificates to Terraform source,
variables, state files, or logs. Populate secret versions through a separate
reviewed secret-management procedure. Role passwords are set interactively after provisioning (see "Database initialization").

The PostgreSQL bootstrap script contains no credentials. It installs PostgreSQL
16, generates a dedicated laboratory CA and a short-lived server certificate
signed by that CA, includes the VM private IP in the certificate SAN, binds
PostgreSQL to the VM's private address, rejects non-TLS host connections, and
allows the lab application subnet for the named application database/user.
The CA private key remains on the database VM (`/var/lib/limitmark-lab/ca`, mode 0700, owned by `postgres`). Only the public CA certificate is exported (see
"Operator access and CA export"), then stored as the
`limitmark-lab-database-ca-cert` Secret Manager version consumed by Cloud Run.
The application must use the database VM private IP in `LAB_DATABASE_URL` and
the runtime enforces strict certificate and hostname verification.

The database URL must not contain query parameters. The lab runtime supplies
`rejectUnauthorized: true`, the CA certificate, and the URL hostname as the TLS
server name, so `sslmode=disable`, alternate roots, and hostname bypasses are
rejected.

Direct VPC egress uses the existing subnet. The Cloud Run service agent receives
`roles/compute.networkUser` on `limitmark-lab-subnet` only; no project-wide
network-user grant is defined. The PostgreSQL firewall rule allows TCP/5432 only
from `10.80.0.0/24` to the disposable database tag because the existing subnet
is shared with the laboratory VMs.

## Offline validation

```powershell
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

`terraform init` downloads provider metadata and packages but does not contact
the Google Cloud resource APIs or modify resources. Do not run `terraform apply`
without separate infrastructure authorization.

## Cleanup

After confirming no evidence depends on the laboratory:

```powershell
terraform destroy
```

Destroy removes the Terraform-managed Cloud Run service, VM, fresh disk,
firewall, Artifact Registry repository, secret containers, service accounts,
and IAM bindings. Review retained secret versions, images, logs, metrics,
snapshots, NAT usage, and the existing historical VMs/disks separately.

Budget alerts are prerequisites, not hard spending limits. They notify after
thresholds and do not automatically stop or delete resources.

## First deployment sequence

1. Verify billing and configure budget alerts; alerts are not spending caps.
2. Enable the declared Google APIs.
3. Create the dedicated service accounts and scoped IAM bindings.
4. Create the Artifact Registry repository and build an immutable image.
5. Create the Secret Manager containers, excluding secret versions.
6. Create the fresh PostgreSQL VM. Its bootstrap generates the laboratory CA
   and SAN-bound server certificate.
7. Retrieve only the CA certificate through an approved private operator
   channel and create its Secret Manager version. Initialize the database and
   application role over the private TLS connection using a separate migration
   role; never place passwords in Terraform, startup metadata, or shell history.
8. Add the database URL and remaining lab secret versions.
9. Deploy Cloud Run after all referenced secret versions exist.
10. Deploy the isolated Cloudflare Workers and credentials.
11. Run controlled end-to-end verification, then stop or destroy disposable
    resources and review retained images, secrets, logs, metrics, and disks.

The initial Terraform apply cannot complete the full deployment: secret
versions, database initialization, the immutable image, and Cloudflare
resources are external prerequisites. The database CA must be exported between
VM bootstrap and Cloud Run secret population, so those steps are intentionally
separate and non-circular.

## Invoker identity

The Cloudflare signer authenticates as `limitmark-lab-invoker` and calls IAM
Credentials `generateIdToken` for that same account. The API requires
`iam.serviceAccounts.getOpenIdToken`, so `iam.tf` binds
`roles/iam.serviceAccountOpenIdTokenCreator` to the invoker account **on the
invoker service account resource only** (self-binding). That role cannot mint
access tokens, sign blobs, or impersonate. Cloud Run invocation stays a
service-scoped `roles/run.invoker` grant. No project-level token-creator grant
exists; `tests/cloud-lab-infrastructure.test.ts` enforces this.

## Operator access and CA export

The VM has no external address. Prerequisites (not created by Terraform, because
a Cloud NAT on the shared subnet would also give egress to historical VMs):

- A Cloud NAT already covers `limitmark-lab-subnet`. Confirm read-only with
  `gcloud compute routers list` / `gcloud compute routers nats list --router <r> --region europe-west3`.
  Without it the bootstrap fails fast ("package installation failed") before PostgreSQL is configured.
- The operator is granted separately (Terraform grants no operator IAM):
  `roles/iap.tunnelResourceAccessor`, `roles/compute.osLogin`,
  `roles/iam.serviceAccountUser` on `limitmark-lab-postgres` (required to SSH to a VM that
  runs as a service account), and read access to the instance and its serial output.

### Exporting the public CA certificate

Only the **public** CA certificate is exported, from `/var/lib/limitmark-lab/public/lab-ca.crt`
(root-owned, 0644). The CA private key lives in `/var/lib/limitmark-lab/ca` (0700, `postgres`);
never use `sudo` to read that directory, and never copy anything from it. Cloud Run always
verifies the server against the CA stored in Secret Manager (`rejectUnauthorized: true`, strict
hostname); nothing below relaxes that, and no metadata/guest-attribute channel is trusted.

1. **Pin the VM identity.** Record the immutable instance ID and confirm name, zone,
   private IP and service account match the intended laboratory VM:

   ```bash
   gcloud compute instances describe limitmark-lab-postgres --zone europe-west3-a      --format="value(id,networkInterfaces[0].networkIP,serviceAccounts[0].email,status)"
   ```

   Expect service account `limitmark-lab-postgres@<project>.iam.gserviceaccount.com`. `gcloud compute ssh`
   stores the host key under `compute.<instance-id>`, so a different VM reusing the name fails
   host-key verification; do not accept a changed host key.
2. **Read the expected fingerprint from the serial console** (a Google-side channel that does
   not depend on the SSH session):

   ```bash
   gcloud compute instances get-serial-port-output limitmark-lab-postgres --zone europe-west3-a | grep LAB_CA_FINGERPRINT
   ```

3. **Download the certificate over IAP + OS Login.**

   ```bash
   gcloud compute scp --zone europe-west3-a --tunnel-through-iap      limitmark-lab-postgres:/var/lib/limitmark-lab/public/lab-ca.crt ./lab-ca.crt
   ```

4. **Verify locally** that the file is a single CA certificate whose SHA-256 fingerprint
   equals the serial-console value, and that it is not a private key:

   ```bash
   openssl x509 -in lab-ca.crt -noout -subject -fingerprint -sha256 -ext basicConstraints
   grep -c "PRIVATE KEY" lab-ca.crt   # must print 0
   ```

5. **Prove the live server chains to it** through the tunnel from "Database initialization" step 2:

   ```bash
   openssl s_client -starttls postgres -connect 127.0.0.1:55432 -CAfile lab-ca.crt      -verify_ip <VM_PRIVATE_IP> -verify_return_error </dev/null
   ```

6. Only then store it: `gcloud secrets versions add limitmark-lab-database-ca-cert --data-file=lab-ca.crt`,
   delete the local copy per your workspace policy, and deploy a new Cloud Run revision.

## Database initialization

The bootstrap (idempotent, re-run on every boot) already creates, over the
local socket, the database owned by `limitmark_lab_migrator` and the
`limitmark_lab_app` role, both **without passwords** and without superuser,
CREATEDB or CREATEROLE. Neither can log in until a password is set. `pg_hba`
permits both roles, TLS only, from the laboratory subnet; non-TLS is rejected.

1. Open IAP SSH to the VM and set each password interactively (`password`
   is not written to history or argv):

   ```bash
   gcloud compute ssh limitmark-lab-postgres --zone europe-west3-a --tunnel-through-iap
   sudo -u postgres psql
   password limitmark_lab_migrator
   password limitmark_lab_app
   ```

2. Tunnel the database port over the same IAP SSH session. The forwarded
   connection originates from the VM itself, inside the permitted subnet:

   ```bash
   gcloud compute ssh limitmark-lab-postgres --zone europe-west3-a --tunnel-through-iap -- -N -L 127.0.0.1:55432:<VM_PRIVATE_IP>:5432
   ```

3. Connect with strict verification; `hostaddr` keeps the certificate check on
   the VM private IP while traffic uses the tunnel (enter the password at the prompt):

   ```bash
   psql "host=<VM_PRIVATE_IP> hostaddr=127.0.0.1 port=55432 dbname=limitmark_lab user=limitmark_lab_migrator sslmode=verify-full sslrootcert=lab-ca.crt"
   ```

4. Run the reviewed migrations as the migration role, then apply the runtime privileges
   as the same role (repeat after every migration):

   ```bash
   psql "<connection string from step 3>" -v ON_ERROR_STOP=1 -v app_role=limitmark_lab_app -f postgres-runtime-grants.sql
   ```

   `postgres-runtime-grants.sql` is derived from the only code the laboratory runtime executes
   (`PostgresInquiryRepository.create`): `INSERT` on `inquiries`, `inquiry_events` and
   `notification_outbox`, plus column-level `SELECT (id, submission_token, payload_fingerprint)`
   on `inquiries`. No `UPDATE`, `DELETE`, sequence or `CREATE` privilege is granted (all keys are
   `gen_random_uuid()`). No default privileges are granted: a table added by a later migration has
   no runtime access until it is reviewed and added to that file, and a test fails if it is not
   accounted for. The file was verified against a local PostgreSQL 16 container, including
   `ON CONFLICT ... RETURNING`, foreign-key inserts, and denial of everything else.
5. Build `LAB_DATABASE_URL` with the VM private IP as host and no query
   parameters; store it as its secret version through the reviewed procedure.

Note: `drizzle-kit migrate` uses `DATABASE_MIGRATION_URL`, and its handling of a
custom CA / server name through the tunnel has not been verified. Until it is,
apply the SQL in `drizzle/` with the `psql` connection above, or supply TLS
options in a reviewed config change.

## Certificate lifecycle

| Item | Behavior |
| --- | --- |
| CA | RSA-4096, 365 days, `pathlen:0`, created once, persisted on the boot disk. Never rotated automatically. A warning is logged under 30 days; an expired CA aborts the bootstrap. |
| Server certificate | RSA-2048, 30 days, SAN = VM private IP only, signed by the CA. |
| Reboot / VM restart | Existing CA and server certificate are reused (they live on the persistent disk). The bootstrap reissues the server certificate only if it expires within 7 days, the private IP changed, or it no longer verifies against the CA; routine renewal is the daily timer below. |
| Renewal (running VM) | Automatic: a systemd timer (`limitmark-lab-cert-renew.timer`, daily with up to 1 h jitter) runs `postgres-renew-cert.sh`. It does nothing until the certificate has under 10 days left, the private IP changed, or it no longer chains to the CA. It then generates a new key on the VM, signs it with the existing CA, validates it, reloads PostgreSQL (no restart) and confirms with a strict TLS handshake that the new certificate is served; otherwise it restores the previous pair and fails. The CA is unchanged, so no secret or Cloud Run change is needed. Results go to the journal without secrets: `journalctl -t limitmark-lab-cert`. Manual run: `sudo systemctl start limitmark-lab-cert-renew.service`. If the IP changed, update the database URL secret. |
| Reprovisioning | `terraform destroy`/recreate produces a new CA. Export and fingerprint-check it, add a new `limitmark-lab-database-ca-cert` version, and deploy a new Cloud Run revision (secrets resolve at instance start). Re-set role passwords; migrations must be re-applied. |

No external certificate automation is introduced.
