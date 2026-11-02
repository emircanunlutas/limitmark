# LimitMark Cloud laboratory Terraform definition

This directory defines the disposable `europe-west3` laboratory resources.
It references the existing `limitmark-lab-vpc` and `limitmark-lab-subnet`; it
does not recreate either network.

The configuration creates API service declarations, a Docker Artifact Registry
repository, empty Secret Manager containers, dedicated service accounts, an
IAM-authenticated Cloud Run service, a fresh private PostgreSQL VM/disk, and a
TCP/5432 firewall rule limited to the laboratory subnet.

## Secret handling

Terraform creates secret **containers only**. Never add secret versions,
database passwords, service-account keys, or certificates to Terraform source,
variables, state files, or logs. Populate secret versions through a separate
reviewed secret-management procedure. The PostgreSQL role and application
password must be created over the private TLS channel after the VM is
provisioned.

The PostgreSQL bootstrap script contains no credentials. It installs PostgreSQL
16, generates a dedicated laboratory CA and a short-lived server certificate
signed by that CA, includes the VM private IP in the certificate SAN, binds
PostgreSQL to the VM's private address, rejects non-TLS host connections, and
allows the lab application subnet for the named application database/user.
The CA private key remains on the database VM. Export only the CA certificate
over an approved operator channel, then store that certificate as the
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

## Database initialization

After the VM is reachable privately and the CA certificate is stored in the
operator's protected workspace, connect with `psql` using that CA and
`sslmode=verify-full` (the host must be the VM private IP). Create separate
migration and application roles with passwords entered
interactively; the migration role owns the database and the runtime role does
not. Run the reviewed Drizzle migrations with `DATABASE_MIGRATION_URL` over
the same verified TLS connection. Then apply repeatable `REVOKE ALL` and
`GRANT` statements so the runtime role has only `CONNECT`, `USAGE` on the
application schema, and required DML/sequence privileges on migrated tables.
Do not grant the runtime role `CREATE` or ownership. Do not put passwords in
Terraform, startup metadata, command arguments, or shell history.
