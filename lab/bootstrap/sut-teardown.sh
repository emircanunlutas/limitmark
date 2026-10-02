#!/usr/bin/env bash
# Removes everything sut-bootstrap.sh installed. It does NOT delete the VM: that is the operator's
# action in the cloud console, and this script performs no provider call of any kind.
#
#   sudo ./sut-teardown.sh --i-am-a-disposable-lab-vm [--dry-run]
set -euo pipefail
IFS=$'\n\t'
DRY_RUN=0; ACK=0
for argument in "$@"; do
  case "$argument" in
    --dry-run) DRY_RUN=1 ;;
    --i-am-a-disposable-lab-vm) ACK=1 ;;
    *) echo "unknown argument: $argument" >&2; exit 64 ;;
  esac
done
LAB_ROOT=/opt/limitmark-lab; LAB_USER=limitmark-lab; STATE_DIR=/etc/limitmark-lab
log() { printf '[teardown] %s\n' "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@" || true; fi; }
[ "$ACK" = 1 ] || { echo "[teardown] REFUSED: pass --i-am-a-disposable-lab-vm" >&2; exit 2; }
if [ "$DRY_RUN" = 0 ]; then
  [ "$(id -u)" = 0 ] || { echo "[teardown] REFUSED: run as root" >&2; exit 2; }
  [ -f "$STATE_DIR/DISPOSABLE" ] || { echo "[teardown] REFUSED: $STATE_DIR/DISPOSABLE is missing; this VM was not bootstrapped as a lab VM" >&2; exit 2; }
fi

log "stopping and removing the application service"
run systemctl disable --now limitmark-lab-app.service
run rm -f /etc/systemd/system/limitmark-lab-app.service
run systemctl daemon-reload

log "removing the lab PostgreSQL containers and volumes (lab-labelled only)"
for name in limitmark-lab-pg16 limitmark-lab-pg17; do
  run docker rm -f -v "$name"
done
run docker network rm limitmark-lab_lab

log "removing only the firewall rules this lab added"
for rule_number in $(ufw status numbered 2>/dev/null | awk '/limitmark-lab/ {gsub(/[\[\]]/,"",$1); print $1}' | sort -rn); do
  run ufw --force delete "$rule_number"
done

log "removing the lab directory and user"
run rm -rf "$LAB_ROOT"
run rm -f /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx
run userdel "$LAB_USER"
run rm -rf "$STATE_DIR"
log "done. Delete the VM itself in the cloud console; nothing here touches the provider."
