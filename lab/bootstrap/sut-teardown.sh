#!/usr/bin/env bash
# Removes everything sut-bootstrap.sh installed. It does NOT delete the VM: that is the operator's
# action in the cloud console, and this script performs no provider call of any kind.
#
# Failures are NEVER swallowed. Every cleanup step is attempted; each failure is recorded and reported, the exit status is
# non-zero, and the recovery marker (/etc/limitmark-lab/DISPOSABLE) is removed only when every step succeeded, so an
# incomplete teardown can simply be run again.
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
LAB_ROOT=/opt/limitmark-lab; LAB_USER=limitmark-lab; STATE_DIR=/etc/limitmark-lab; NODE_ROOT=/opt/limitmark-node
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib-net.sh"
FAILURES=()
log() { printf '[teardown] %s\n' "$*"; }
# run: executes (or, with --dry-run, prints) one cleanup step; a failure is recorded, never ignored.
run() {
  # IFS is a newline in this script; join the words with spaces so a dry-run line is one readable line.
  if [ "$DRY_RUN" = 1 ]; then local IFS=' '; printf '[dry-run] %s\n' "$*"; return 0; fi
  if ! "$@"; then FAILURES+=("$*"); printf '[teardown] FAILED: %s\n' "$*" >&2; fi
}
[ "$ACK" = 1 ] || { echo "[teardown] REFUSED: pass --i-am-a-disposable-lab-vm" >&2; exit 2; }
if [ "$DRY_RUN" = 0 ]; then
  [ "$(id -u)" = 0 ] || { echo "[teardown] REFUSED: run as root" >&2; exit 2; }
  [ -f "$STATE_DIR/DISPOSABLE" ] || { echo "[teardown] REFUSED: $STATE_DIR/DISPOSABLE is missing; this VM was not bootstrapped as a lab VM" >&2; exit 2; }
  [ "$(cat "$STATE_DIR/DISPOSABLE")" = "limitmark-lab-disposable-v1" ] || { echo "[teardown] REFUSED: $STATE_DIR/DISPOSABLE is not a lab marker" >&2; exit 2; }
fi

# A container or network is removed only when the DAEMON's labels say the lab created it (a name alone is not ownership), and a daemon that
# cannot answer is UNKNOWN, which is a failure: it is never read as "nothing to remove" (see teardown_lab_containers in lib-net.sh).

log "stopping and removing the application service"
if [ "$DRY_RUN" = 1 ] || systemctl list-unit-files limitmark-lab-app.service 2>/dev/null | grep -q '^limitmark-lab-app.service'; then
  run systemctl disable --now limitmark-lab-app.service
fi
run rm -f /etc/systemd/system/limitmark-lab-app.service
run systemctl daemon-reload
# The one read-only privilege a --ba0-field bootstrap granted the lab user.
run rm -f /etc/sudoers.d/limitmark-lab-ba0

log "removing the lab PostgreSQL containers and volumes (containers carrying the lab label only)"
if [ "$DRY_RUN" = 1 ]; then
  for name in limitmark-lab-pg16 limitmark-lab-pg17 limitmark-lab-app; do printf '[dry-run] remove %s only if it carries the limitmark.lab=disposable label\n' "$name"; done
  printf '[dry-run] remove the shared lab network if it is lab-labelled and unused\n'
  printf '[dry-run] an unreachable docker daemon is a FAILURE (recovery marker kept), never "no containers"\n'
else
  teardown_lab_containers
fi

log "removing only the firewall rules this lab added"
if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] delete every ufw rule carrying the limitmark-lab comment, highest number first\n'
elif command -v ufw >/dev/null 2>&1; then
  ufw_status="$(ufw status numbered)"
  for rule_number in $(printf '%s\n' "$ufw_status" | ufw_lab_rule_numbers); do
    run ufw --force delete "$rule_number"
  done
fi

log "removing the lab directories, the Node install and the user"
run rm -rf "$LAB_ROOT"
# Only the symlinks this lab created (they point into the lab's Node tree) are removed.
for link in /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx; do
  if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] remove %s if it points into %s\n' "$link" "$NODE_ROOT"
  elif [ -L "$link" ] && [[ "$(readlink "$link")" == "$NODE_ROOT"/* ]]; then run rm -f "$link"; fi
done
run rm -rf "$NODE_ROOT"
if [ "$DRY_RUN" = 1 ] || id "$LAB_USER" >/dev/null 2>&1; then run userdel "$LAB_USER"; fi

if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] remove the state directory and the recovery marker (only if every step above succeeded)\n'; exit 0; fi
if [ "${#FAILURES[@]}" -gt 0 ]; then
  printf '[teardown] INCOMPLETE: %d step(s) failed; the recovery marker %s/DISPOSABLE was KEPT so this can be run again:\n' "${#FAILURES[@]}" "$STATE_DIR" >&2
  printf '[teardown]   - %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
run rm -rf "$STATE_DIR"
if [ "${#FAILURES[@]}" -gt 0 ]; then echo "[teardown] INCOMPLETE: the state directory could not be removed" >&2; exit 1; fi
log "done. Delete the VM itself in the cloud console; nothing here touches the provider."
