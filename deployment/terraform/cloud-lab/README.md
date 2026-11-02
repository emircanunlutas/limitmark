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
16, generates a short-lived self-signed server certificate locally, binds
PostgreSQL to the VM's private address, rejects non-TLS host connections, and
allows the lab application subnet for the named application database/user.

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
