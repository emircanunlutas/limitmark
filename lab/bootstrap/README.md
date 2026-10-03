# Disposable Ubuntu VM bootstrap (system-under-test role)

**Not run against anything yet.** These scripts run *on* the VM after the operator has created it. They
contain no credential, call no cloud/provider API and never read provider metadata.

| File | Role |
| --- | --- |
| `sut-bootstrap.sh` | Writes the recovery marker, installs git/Docker/sysstat/ufw and a digest-pinned, root-owned Node (re-verified on every run), configures the host firewall, **then** builds an exact commit, installs the app as a hardened systemd unit (demo adapter, no secrets) and restarts it, and installs the bounded metrics collector. Convergent: re-running removes lab firewall rules for CIDRs no longer supplied and restarts the application on the new build. `--dry-run` prints every action. |
| `sut-teardown.sh` | Removes everything the bootstrap installed (service, lab-**labelled** containers and volumes, only its own ufw rules, the Node install, lab user and directory). Never suppresses a failure: every step is attempted, failures are listed, the exit status is non-zero and the recovery marker is **kept** so it can be run again. Does **not** delete the VM. |
| `lib-net.sh` | Sourced helpers: strict CIDR validation and `ufw status numbered` parsing (pure bash, unit-tested). |
| `host-metrics.sh` | Bounded (at most 3600 s) `/proc` sampler: CPU, load, memory, network bytes, TCP counts. No addresses. |
| `pins.env` | Node version and tarball digests. Placeholders are refused by a real run. |

```text
sudo env LAB_REPO_URL=https://<repo> LAB_REPO_COMMIT=<40-hex> LAB_APP_ORIGIN=http://<vm-ipv4>:3000 \
  LAB_SSH_ALLOW_CIDRS=<cidr,...> LAB_LOADGEN_CIDRS=<cidr,...> \
  ./sut-bootstrap.sh --i-am-a-disposable-lab-vm [--dry-run]
```

## Firewall expectations

* The cloud VPC firewall is the **primary** perimeter and is created by hand: SSH from the operator CIDR
  only, TCP 3000 from the authorised load-generator CIDRs only, and **nothing** for PostgreSQL
  (5432 / 55416 / 55417).
* `ufw` here is the second layer, configured to the same shape, **before** the application is built or started. CIDR lists are validated strictly: canonical dotted quads only (`999.999.999.999/32` is refused), prefixes `/16`..`/32` only (so two complementary `/1` networks, which together are all of IPv4, are refused as well as `/0`), network addresses only (host bits set is refused), nothing overlapping this-network, loopback, link-local (cloud metadata) or multicast/reserved space, at most 8 entries per list.
* When the CIDRs change, a re-run adds the new rules first and then deletes lab rules (comment `limitmark-lab`) that are no longer wanted; it never touches rules it did not add.
* Docker-published ports bypass `ufw`; the lab PostgreSQL is published on `127.0.0.1` only.
* Plain HTTP on 3000: TLS and edge behaviour are deliberately out of scope for this stand-in.

## Operating the VM

* PostgreSQL lab: from `/opt/limitmark-lab/app`, `sudo -u limitmark-lab npm run lab:db:up -- 16`.
* Host metrics: `/opt/limitmark-lab/bin/host-metrics.sh --duration 900 --interval 5 --out /opt/limitmark-lab/metrics/run.jsonl`.
* Evidence from runs on the VM stays under `/opt/limitmark-lab/app/artifacts/lab/evidence` (gitignored).

## Integrity and recovery

* **Node** lives in `/opt/limitmark-node` (root-owned, outside the service user's tree). It is installed from a tarball whose SHA-256 is pinned in `pins.env`; the digest of every extracted file is recorded in `/etc/limitmark-lab/`. An existing install is accepted only if every file still matches (and no extra file exists); otherwise it is replaced. `node --version` alone is not integrity. Placeholder digests still fail closed before anything is installed.
* **Recovery marker** `/etc/limitmark-lab/DISPOSABLE` is written first (before any package or file), has fixed content that teardown verifies, and is removed last, only when teardown fully succeeded.
* **Ownership**: teardown removes a container or network only if the daemon's `limitmark.lab=disposable` label says the lab created it.
* Residual assumptions: the service user is in the `docker` group (root-equivalent on this VM); the VM's existing firewall policy, metadata access and service-account privileges are operator responsibilities; no Ubuntu package installation, systemd operation or VM provisioning has been exercised by these tests.

## Before first use

1. Replace the Node digest placeholders in `pins.env` with values from the official release notes.
2. Reserve the VM's external address: an ephemeral address that is released may be reassigned to a
   stranger, which is why target definitions expire within 72 h.
3. Review this directory with `--dry-run` on a scratch Ubuntu container or VM.
