# Disposable Ubuntu VM bootstrap (system-under-test role)

**Not run against anything yet.** These scripts run *on* the VM after the operator has created it. They
contain no credential, call no cloud/provider API and never read provider metadata.

| File | Role |
| --- | --- |
| `sut-bootstrap.sh` | Installs git/Docker/sysstat/ufw and a digest-pinned Node, builds an exact commit, installs the app as a hardened systemd unit (demo adapter, no secrets), the bounded metrics collector and the host firewall. Idempotent; `--dry-run` prints every action. |
| `sut-teardown.sh` | Removes everything the bootstrap installed (service, lab containers and volumes, only its own ufw rules, lab user and directory). Does **not** delete the VM. |
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
* `ufw` here is the second layer, configured to the same shape. `/0` CIDRs are refused.
* Docker-published ports bypass `ufw`; the lab PostgreSQL is published on `127.0.0.1` only.
* Plain HTTP on 3000: TLS and edge behaviour are deliberately out of scope for this stand-in.

## Operating the VM

* PostgreSQL lab: from `/opt/limitmark-lab/app`, `sudo -u limitmark-lab npm run lab:db:up -- 16`.
* Host metrics: `/opt/limitmark-lab/bin/host-metrics.sh --duration 900 --interval 5 --out /opt/limitmark-lab/metrics/run.jsonl`.
* Evidence from runs on the VM stays under `/opt/limitmark-lab/app/artifacts/lab/evidence` (gitignored).

## Before first use

1. Replace the Node digest placeholders in `pins.env` with values from the official release notes.
2. Reserve the VM's external address: an ephemeral address that is released may be reassigned to a
   stranger, which is why target definitions expire within 72 h.
3. Review this directory with `--dry-run` on a scratch Ubuntu container or VM.
