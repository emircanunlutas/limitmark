#!/usr/bin/env bash
# LimitMark field-lab: bootstrap of a DISPOSABLE Ubuntu VM that will act as the system under test.
#
# Runs ON the VM, as root, after the operator has created and reached it. It never creates, changes
# or queries any cloud/provider resource, never reads provider metadata, and embeds no credential.
# It is convergent: re-running brings the VM to the state the supplied inputs describe (including removing firewall rules
# an earlier run added for CIDRs that are no longer supplied, and restarting the application on the new build).
# Use --dry-run to print every action.
#
#   sudo ./sut-bootstrap.sh --i-am-a-disposable-lab-vm [--dry-run] [--ba0-field]
#
# --ba0-field prepares the VM for ONE BA0 field level (the Defense Plane qualification) instead of the Field Lab Next service: the old
# application service is stopped, disabled and removed (it must not be a parallel exposed target), NO port-3000 firewall rule is added (and
# any this lab added earlier is removed), the firewall allows exactly ONE port, LAB_BA0_PLANE_PORT, from exactly ONE source, a single /32 in
# LAB_LOADGEN_CIDRS, and the lab user is given exactly one read-only privilege: `ufw status numbered`, so the field preflight can PROVE the firewall
# state. Nothing is started: the operator runs the field runner. Extra environment in this mode:
#   LAB_BA0_PLANE_PORT    the reviewed Defense Plane port (8000..8999, so never the old application port or a database port); LAB_APP_ORIGIN is not used
#
# Required environment (all operator-supplied, none stored here):
#   LAB_REPO_URL          https URL of the repository (no userinfo / credentials)
#   LAB_REPO_COMMIT       full 40-hex commit to build (exact, reproducible)
#   LAB_APP_ORIGIN        http://<VM IPv4>:3000  (used as the demo-mode Origin)
#   LAB_SSH_ALLOW_CIDRS   comma-separated CIDRs allowed to reach SSH (/16../32, network addresses, max 8)
#   LAB_LOADGEN_CIDRS     comma-separated CIDRs of the authorised load generators (same rules)
# Pins: lab/bootstrap/pins.env must contain real Node digests (placeholders are refused).
set -euo pipefail
IFS=$'\n\t'
umask 027

DRY_RUN=0
ACK=0
BA0_FIELD=0
for argument in "$@"; do
  case "$argument" in
    --dry-run) DRY_RUN=1 ;;
    --i-am-a-disposable-lab-vm) ACK=1 ;;
    --ba0-field) BA0_FIELD=1 ;;
    *) echo "unknown argument: $argument" >&2; exit 64 ;;
  esac
done

LAB_ROOT=/opt/limitmark-lab
LAB_USER=limitmark-lab
STATE_DIR=/etc/limitmark-lab
# Node lives OUTSIDE the lab user's tree and is root-owned: the unprivileged service user can never replace its interpreter.
NODE_ROOT=/opt/limitmark-node
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '[bootstrap] %s\n' "$*"; }
die() { printf '[bootstrap] REFUSED: %s\n' "$*" >&2; exit 2; }
# Every state-changing command goes through run(), so --dry-run prints instead of executing.
run() {
  # IFS is a newline in this script; join the words with spaces so a dry-run line is one readable line.
  if [ "$DRY_RUN" = 1 ]; then local IFS=' '; printf '[dry-run] %s\n' "$*"; else "$@"; fi
}

# ---------------------------------------------------------------- validation (no side effects)
[ "$ACK" = 1 ] || die "pass --i-am-a-disposable-lab-vm to confirm this VM is disposable and holds nothing of value"
[ "$(uname -s)" = Linux ] || die "Linux only"
if [ "$DRY_RUN" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (sudo)"
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = ubuntu ] || die "Ubuntu only (found ${ID:-unknown})"
  case "${VERSION_ID:-}" in 22.04|24.04) ;; *) die "Ubuntu 22.04 or 24.04 only (found ${VERSION_ID:-unknown})" ;; esac
fi

# shellcheck disable=SC1091
. "$SCRIPT_DIR/pins.env"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib-net.sh"
case "$(uname -m)" in
  x86_64) NODE_ARCH=x64; NODE_SHA256="${NODE_SHA256_LINUX_X64:-}" ;;
  aarch64) NODE_ARCH=arm64; NODE_SHA256="${NODE_SHA256_LINUX_ARM64:-}" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
[[ "${NODE_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "NODE_VERSION in pins.env is not a plain x.y.z version"
if ! [[ "$NODE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  # A dry run may print the plan with placeholder pins; a real run never proceeds without a real digest.
  [ "$DRY_RUN" = 1 ] || die "Node tarball digest for this architecture is still a placeholder in pins.env"
  log "WARNING: Node digest is a placeholder (dry-run only)"
fi

: "${LAB_REPO_URL:?LAB_REPO_URL is required}"
: "${LAB_REPO_COMMIT:?LAB_REPO_COMMIT is required}"
if [ "$BA0_FIELD" = 0 ]; then
  : "${LAB_APP_ORIGIN:?LAB_APP_ORIGIN is required}"
fi
: "${LAB_SSH_ALLOW_CIDRS:?LAB_SSH_ALLOW_CIDRS is required}"
: "${LAB_LOADGEN_CIDRS:?LAB_LOADGEN_CIDRS is required}"
[[ "$LAB_REPO_URL" =~ ^https://[A-Za-z0-9._/-]+$ ]] || die "LAB_REPO_URL must be a plain https URL without credentials"
[[ "$LAB_REPO_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "LAB_REPO_COMMIT must be a full 40-hex commit"
if [ "$BA0_FIELD" = 0 ]; then
  [[ "$LAB_APP_ORIGIN" =~ ^http://([0-9]{1,3}\.){3}[0-9]{1,3}:3000$ ]] || die "LAB_APP_ORIGIN must look like http://203.0.113.10:3000"
  origin_host="${LAB_APP_ORIGIN:7}"; origin_host="${origin_host%:3000}"
  ipv4_to_int "$origin_host" >/dev/null || die "LAB_APP_ORIGIN host is not a valid IPv4 address"
fi
cidr_list_check "$LAB_SSH_ALLOW_CIDRS" "LAB_SSH_ALLOW_CIDRS" || die "invalid LAB_SSH_ALLOW_CIDRS"
cidr_list_check "$LAB_LOADGEN_CIDRS" "LAB_LOADGEN_CIDRS" || die "invalid LAB_LOADGEN_CIDRS"
if [ "$BA0_FIELD" = 1 ]; then
  # One reviewed Plane port, from exactly one authorised generator host (a single /32): nothing broader can be configured in this mode.
  : "${LAB_BA0_PLANE_PORT:?LAB_BA0_PLANE_PORT is required with --ba0-field}"
  [[ "$LAB_BA0_PLANE_PORT" =~ ^8[0-9]{3}$ ]] || die "LAB_BA0_PLANE_PORT must be a port in 8000..8999 (never the old application port, a database port or a standard service port)"
  [[ "$LAB_LOADGEN_CIDRS" =~ ^[0-9.]+/32$ ]] || die "with --ba0-field LAB_LOADGEN_CIDRS must be exactly one /32 (the one authorised generator host)"
fi

log "validated; dry-run=$DRY_RUN"

# ---------------------------------------------------------------- recovery marker (first state change)
# Written BEFORE anything else is changed, so a run that fails half-way can still be torn down. Teardown removes it last,
# and only when every cleanup step succeeded.
write_marker() {
  log "writing the disposable-VM recovery marker"
  run install -d -m 0755 "$STATE_DIR"
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] write %s/DISPOSABLE\n' "$STATE_DIR"; else
    printf 'limitmark-lab-disposable-v1\n' > "$STATE_DIR/DISPOSABLE"
    run chmod 0644 "$STATE_DIR/DISPOSABLE"
  fi
}

# ---------------------------------------------------------------- packages
install_packages() {
  log "installing OS packages (git, docker, sysstat, ufw, ...)"
  run env DEBIAN_FRONTEND=noninteractive apt-get update -y
  # docker.io + compose v2 come from the Ubuntu archive: no third-party apt key is added.
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl git jq xz-utils sysstat ufw docker.io docker-compose-v2 iproute2 procps sudo
}

# ---------------------------------------------------------------- node (pinned, digest-verified, re-verified on every run)
# An existing install is NOT trusted because `node --version` prints the right string. It must still match the file digests
# recorded (root-owned) when it was installed from the digest-verified tarball: same files, same hashes, nothing extra.
node_install_verified() {
  local target="$1" sums="$2"
  [ -x "$target/bin/node" ] && [ -f "$sums" ] || return 1
  [ "$("$target/bin/node" --version)" = "v${NODE_VERSION}" ] || return 1
  ( cd "$target" && sha256sum --check --quiet --strict "$sums" ) >/dev/null 2>&1 || return 1
  [ "$(cd "$target" && find . -type f | wc -l)" = "$(wc -l < "$sums")" ] || return 1
}

install_node() {
  local target="$NODE_ROOT/node-v${NODE_VERSION}-linux-${NODE_ARCH}"
  local sums="$STATE_DIR/node-v${NODE_VERSION}-linux-${NODE_ARCH}.sha256"
  if [ "$DRY_RUN" = 0 ] && node_install_verified "$target" "$sums"; then
    log "node v${NODE_VERSION} already present and its files match the recorded digests"
  else
    log "installing node v${NODE_VERSION} (any existing copy is replaced)"
    local tarball="/tmp/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
    run install -d -m 0755 -o root -g root "$NODE_ROOT"
    run curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      --output "$tarball" "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
    if [ "$DRY_RUN" = 1 ]; then
      printf '[dry-run] verify sha256 of %s equals the pinned digest, then extract into %s as root and record file digests in %s\n' "$tarball" "$NODE_ROOT" "$sums"
    else
      echo "${NODE_SHA256}  ${tarball}" | sha256sum --check --status || die "Node tarball digest mismatch"
      run rm -rf "$target" "$sums"
      run tar -xJf "$tarball" -C "$NODE_ROOT" --no-same-owner
      run chown -R root:root "$target"
      ( cd "$target" && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$sums"
      run chmod 0644 "$sums"
      run rm -f "$tarball"
      node_install_verified "$target" "$sums" || die "the fresh Node install does not verify against its recorded digests"
    fi
  fi
  run ln -sfn "$target/bin/node" /usr/local/bin/node
  run ln -sfn "$target/bin/npm" /usr/local/bin/npm
  run ln -sfn "$target/bin/npx" /usr/local/bin/npx
}

# ---------------------------------------------------------------- user and directories
prepare_host() {
  log "creating the unprivileged lab user and directories"
  if ! id "$LAB_USER" >/dev/null 2>&1; then
    run useradd --system --create-home --home-dir "$LAB_ROOT/home" --shell /usr/sbin/nologin "$LAB_USER"
  fi
  run install -d -m 0750 -o "$LAB_USER" -g "$LAB_USER" "$LAB_ROOT" "$LAB_ROOT/evidence" "$LAB_ROOT/metrics" "$LAB_ROOT/bin"
  # The lab user drives the lab PostgreSQL container through Docker (root-equivalent on this VM).
  run usermod -aG docker "$LAB_USER"
}

# ---------------------------------------------------------------- firewall
# GCP VPC firewall rules remain the primary perimeter (see README). This is the host-level second layer.
# It is configured BEFORE the application is built or started, so port 3000 is never reachable from anywhere but the
# supplied CIDRs, not even briefly. Allow rules are added first, then rules this lab added earlier for CIDRs that are no
# longer supplied are removed (a changed CIDR list must not leave the old networks allowed).
# Note: Docker-published ports bypass ufw; the lab PostgreSQL is published on 127.0.0.1 ONLY.
configure_firewall() {
  log "configuring ufw: default deny inbound; SSH and the app port only from the supplied CIDRs; stale lab rules removed"
  local -a ssh_cidrs load_cidrs desired
  IFS=',' read -r -a ssh_cidrs <<< "$LAB_SSH_ALLOW_CIDRS"
  IFS=',' read -r -a load_cidrs <<< "$LAB_LOADGEN_CIDRS"
  run ufw --force default deny incoming
  run ufw --force default allow outgoing
  local cidr
  desired=()
  for cidr in "${ssh_cidrs[@]}"; do
    run ufw allow from "$cidr" to any port 22 proto tcp comment 'limitmark-lab ssh'
    desired+=("22|$(ufw_normalize_cidr "$cidr")")
  done
  for cidr in "${load_cidrs[@]}"; do
    if [ "$BA0_FIELD" = 1 ]; then
      # The reviewed Defense Plane port from the single generator /32 only; port 3000 gets no rule (and an earlier one is removed below).
      run ufw allow from "$cidr" to any port "$LAB_BA0_PLANE_PORT" proto tcp comment 'limitmark-lab ba0 plane'
      desired+=("${LAB_BA0_PLANE_PORT}|$(ufw_normalize_cidr "$cidr")")
    else
      run ufw allow from "$cidr" to any port 3000 proto tcp comment 'limitmark-lab app'
      desired+=("3000|$(ufw_normalize_cidr "$cidr")")
    fi
  done
  if [ "$DRY_RUN" = 1 ]; then
    printf '[dry-run] delete every limitmark-lab ufw rule whose port and source are not in: %s\n' "${desired[*]}"
  else
    local status number
    status="$(ufw status numbered)"
    for number in $(printf '%s\n' "$status" | ufw_stale_lab_rule_numbers "${desired[@]}"); do
      log "removing stale lab firewall rule $number"
      run ufw --force delete "$number"
    done
  fi
  run ufw --force enable
}

# ---------------------------------------------------------------- application
build_application() {
  log "fetching and building commit ${LAB_REPO_COMMIT}"
  local app="$LAB_ROOT/app"
  if [ ! -d "$app/.git" ]; then
    run install -d -m 0750 -o "$LAB_USER" -g "$LAB_USER" "$app"
    run runuser -u "$LAB_USER" -- git -C "$app" init --quiet
    run runuser -u "$LAB_USER" -- git -C "$app" remote add origin "$LAB_REPO_URL"
  fi
  run runuser -u "$LAB_USER" -- git -C "$app" fetch --quiet --depth 1 origin "$LAB_REPO_COMMIT"
  run runuser -u "$LAB_USER" -- git -C "$app" checkout --quiet --detach FETCH_HEAD
  if [ "$DRY_RUN" = 0 ]; then
    [ "$(runuser -u "$LAB_USER" -- git -C "$app" rev-parse HEAD)" = "$LAB_REPO_COMMIT" ] || die "checked-out commit differs from LAB_REPO_COMMIT"
  fi
  if [ "$BA0_FIELD" = 1 ]; then
    # The BA0 runner runs from source (tsx): no Next build is needed, and none is made.
    run runuser -u "$LAB_USER" -- bash -c "cd '$app' && npm ci --no-audit --no-fund"
  else
    run runuser -u "$LAB_USER" -- bash -c "cd '$app' && npm ci --no-audit --no-fund && npm run build"
  fi
}

# --ba0-field: the old Field Lab application must not be a parallel exposed target. Stopped, disabled and its unit removed, then proven inactive.
retire_old_app_service() {
  log "ba0-field: stopping, disabling and removing the old Field Lab application service"
  if [ "$DRY_RUN" = 1 ] || systemctl list-unit-files limitmark-lab-app.service 2>/dev/null | grep -q '^limitmark-lab-app.service'; then
    run systemctl disable --now limitmark-lab-app.service
  fi
  run rm -f /etc/systemd/system/limitmark-lab-app.service
  run systemctl daemon-reload
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] prove the old application service is not active\n'; else
    if systemctl is-active --quiet limitmark-lab-app.service; then die "the old application service is still active"; fi
  fi
}

# --ba0-field: the ONE privilege the lab user gets: reading the firewall status (the field preflight proves the rules from it). Validated with
# visudo before it is installed; nothing else, no shell, no write.
install_ba0_sudoers() {
  log "ba0-field: allowing the lab user one read-only command (ufw status numbered)"
  local fragment=/etc/sudoers.d/limitmark-lab-ba0
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] write %s allowing only: /usr/sbin/ufw status numbered\n' "$fragment"; else
    local tmp
    tmp="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: /usr/sbin/ufw status numbered\n' "$LAB_USER" > "$tmp"
    visudo -cf "$tmp" >/dev/null || { run rm -f "$tmp"; die "the sudoers fragment is invalid"; }
    run install -m 0440 -o root -g root "$tmp" "$fragment"
    run rm -f "$tmp"
  fi
}

# After a rebuild or an environment change the RUNNING process still has the old code and the old environment:
# `systemctl enable --now` only starts a stopped service. Every run restarts it and proves the new process is serving.
verify_app_ready() {
  local attempt
  for attempt in $(seq 1 60); do
    if systemctl is-active --quiet limitmark-lab-app.service && curl --fail --silent --max-time 3 --output /dev/null http://localhost:3000/; then return 0; fi
    sleep 1
  done
  return 1
}

install_app_service() {
  if [ "$BA0_FIELD" = 1 ]; then
    # --ba0-field: no application service is installed. The old one is retired and the lab user gets its one read-only privilege.
    retire_old_app_service
    install_ba0_sudoers
    log "ba0-field ready. Next (operator, as the lab user): npm run lab:ba0:field -- --target <id> --level <level> --campaign <id>; start the generator on the other host only after ARMED."
    return 0
  fi
  log "installing the application systemd unit"
  local unit=/etc/systemd/system/limitmark-lab-app.service
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] write %s\n' "$unit"; else
    cat > "$unit" <<UNIT
[Unit]
Description=LimitMark field-lab application (system under test)
After=network-online.target
Wants=network-online.target

[Service]
User=${LAB_USER}
WorkingDirectory=${LAB_ROOT}/app
# Non-persistent demo adapter only; no database URL, no provider key, no secret of any kind.
Environment=NODE_ENV=production
Environment=NEXT_TELEMETRY_DISABLED=1
Environment=REQUEST_SUBMISSION_MODE=demo
Environment=ALLOW_DEMO_SUBMISSIONS=true
Environment=PUBLIC_DEMO_ORIGIN=${LAB_APP_ORIGIN}
Environment=PUBLIC_ORIGIN_PROTECTION=disabled
Environment=ENABLE_PERSISTENT_SUBMISSIONS=false
Environment=ENABLE_REAL_NOTIFICATIONS=false
ExecStart=/usr/local/bin/node node_modules/next/dist/bin/next start --hostname 0.0.0.0 --port 3000
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LAB_ROOT}/app/.next
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  fi
  run systemctl daemon-reload
  run systemctl enable limitmark-lab-app.service
  run systemctl restart limitmark-lab-app.service
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] wait until the restarted service answers on the local port\n'; else
    verify_app_ready || die "the application did not become ready after the restart"
  fi
}

# ---------------------------------------------------------------- host metrics
install_metrics() {
  log "installing the bounded host-metrics collector"
  run install -m 0755 -o root -g root "$SCRIPT_DIR/host-metrics.sh" "$LAB_ROOT/bin/host-metrics.sh"
  run systemctl enable --now sysstat.service
}

# ---------------------------------------------------------------- run
write_marker
install_packages
run install -d -m 0755 "$LAB_ROOT"
install_node
prepare_host
configure_firewall
build_application
install_app_service
install_metrics
log "done. Next (operator): from a trusted lab machine run the lab runner against this VM's target definition."
log "Teardown: sudo lab/bootstrap/sut-teardown.sh --i-am-a-disposable-lab-vm, then delete the VM in the cloud console."
