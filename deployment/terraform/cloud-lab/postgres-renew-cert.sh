#!/bin/bash
# Periodic renewal of the laboratory PostgreSQL server certificate (run daily by a systemd timer).
#  - Renews only when needed: <RENEW_BEFORE_SECONDS left, wrong private IP, missing, or not chained to the CA.
#  - The CA (and its key) never changes or leaves the host; the new server key is generated on this VM.
#  - Reloads PostgreSQL (SIGHUP, no restart) and proves with a strict TLS handshake that the new certificate is served;
#    otherwise restores the previous pair and fails.
#  - Logs only public facts (serial, expiry, SAN, outcome) to syslog/journal. Contains no credentials.
set -euo pipefail
umask 077

PG_VERSION="${PG_VERSION:-$(ls /etc/postgresql | sort -V | tail -n 1)}"
PG_TLS_DIR="${PG_TLS_DIR:-/etc/postgresql/${PG_VERSION}/main/tls}"
LAB_DIR="${LAB_DIR:-/var/lib/limitmark-lab}"
PG_CA_KEY="${PG_CA_KEY:-${LAB_DIR}/ca/lab-ca.key}"
PG_CA_CERT="${PG_CA_CERT:-${LAB_DIR}/ca/lab-ca.crt}"
PG_SERVER_KEY="${PG_SERVER_KEY:-${PG_TLS_DIR}/server.key}"
PG_SERVER_CERT="${PG_SERVER_CERT:-${PG_TLS_DIR}/server.crt}"
INTERNAL_IP="${INTERNAL_IP:-$(hostname -I | awk '{print $1}')}"
PG_PORT="${PG_PORT:-5432}"
SERVER_DAYS="${SERVER_DAYS:-30}"
RENEW_BEFORE_SECONDS="${RENEW_BEFORE_SECONDS:-864000}" # 10 days: a daily timer gets ~10 attempts before expiry
CA_WARN_BEFORE_SECONDS="${CA_WARN_BEFORE_SECONDS:-2592000}"
RELOAD_CMD="${RELOAD_CMD:-systemctl reload postgresql@${PG_VERSION}-main}"
FILE_OWNER="${FILE_OWNER:-postgres:postgres}"
LOCK_FILE="${LOCK_FILE:-/run/limitmark-lab-cert.lock}"

log() { # $1 syslog priority, rest message
  local priority="$1"; shift
  echo "limitmark-lab-cert [${priority}] $*" >&2
  if command -v logger >/dev/null 2>&1; then logger -t limitmark-lab-cert -p "daemon.${priority}" -- "$*" || true; fi
}

exec 9>"$LOCK_FILE"
if ! flock -n 9; then log notice "another certificate operation is running; skipping"; exit 0; fi

[[ -s "$PG_CA_KEY" && -s "$PG_CA_CERT" ]] || { log err "CA material missing; bootstrap has not completed"; exit 1; }
if ! openssl x509 -checkend 0 -noout -in "$PG_CA_CERT" >/dev/null; then
  log err "the laboratory CA has expired; reprovision the VM and replace the database CA secret version"; exit 1
fi
if ! openssl x509 -checkend "$CA_WARN_BEFORE_SECONDS" -noout -in "$PG_CA_CERT" >/dev/null; then
  log warning "the laboratory CA expires within 30 days; plan reprovisioning (server certificate renewal continues)"
fi

reason=""
if [[ ! -s "$PG_SERVER_KEY" || ! -s "$PG_SERVER_CERT" ]]; then reason="server key or certificate missing"
elif ! openssl x509 -checkend "$RENEW_BEFORE_SECONDS" -noout -in "$PG_SERVER_CERT" >/dev/null; then reason="expires within $((RENEW_BEFORE_SECONDS / 86400)) days"
elif ! openssl x509 -noout -ext subjectAltName -in "$PG_SERVER_CERT" | grep -Fq "IP Address:${INTERNAL_IP}"; then reason="SAN does not contain ${INTERNAL_IP}"
elif ! openssl verify -CAfile "$PG_CA_CERT" "$PG_SERVER_CERT" >/dev/null 2>&1; then reason="not chained to the laboratory CA"
fi
if [[ -z "$reason" ]]; then
  log info "not due: serial $(openssl x509 -noout -serial -in "$PG_SERVER_CERT" | cut -d= -f2), $(openssl x509 -noout -enddate -in "$PG_SERVER_CERT")"
  exit 0
fi
log notice "renewing server certificate: ${reason}"

WORK="$(mktemp -d "${PG_TLS_DIR}/renew.XXXXXX")"
cleanup() { if [[ -n "${WORK:-}" && -d "$WORK" ]]; then find "$WORK" -type f -exec shred -u {} + 2>/dev/null || true; rm -rf "$WORK"; fi; }
trap cleanup EXIT
owner_user="${FILE_OWNER%%:*}"; owner_group="${FILE_OWNER##*:}"

cat > "$WORK/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${INTERNAL_IP}
EXT
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=${INTERNAL_IP}" -keyout "$WORK/new.key" -out "$WORK/new.csr" 2>/dev/null
openssl x509 -req -sha256 -days "$SERVER_DAYS" -CA "$PG_CA_CERT" -CAkey "$PG_CA_KEY" -CAcreateserial -CAserial "$WORK/ca.srl" \
  -in "$WORK/new.csr" -out "$WORK/new.crt" -extfile "$WORK/server.ext" 2>/dev/null

# Validate before touching the live pair.
openssl verify -CAfile "$PG_CA_CERT" "$WORK/new.crt" >/dev/null 2>&1 || { log err "new certificate does not chain to the CA; aborting, nothing changed"; exit 1; }
openssl x509 -noout -ext subjectAltName -in "$WORK/new.crt" | grep -Fq "IP Address:${INTERNAL_IP}" || { log err "new certificate SAN mismatch; aborting"; exit 1; }
openssl x509 -checkend 86400 -noout -in "$WORK/new.crt" >/dev/null || { log err "new certificate is not valid; aborting"; exit 1; }
[[ "$(openssl x509 -noout -pubkey -in "$WORK/new.crt" | openssl sha256)" == "$(openssl pkey -in "$WORK/new.key" -pubout | openssl sha256)" ]] \
  || { log err "new key does not match the new certificate; aborting"; exit 1; }
new_serial="$(openssl x509 -noout -serial -in "$WORK/new.crt" | cut -d= -f2)"

# Keep the previous pair for rollback, then swap atomically (same filesystem).
had_previous=0
if [[ -s "$PG_SERVER_KEY" && -s "$PG_SERVER_CERT" ]]; then
  cp -p "$PG_SERVER_KEY" "$WORK/prev.key"; cp -p "$PG_SERVER_CERT" "$WORK/prev.crt"; had_previous=1
fi
install -o "$owner_user" -g "$owner_group" -m 0600 "$WORK/new.key" "${PG_SERVER_KEY}.new"
install -o "$owner_user" -g "$owner_group" -m 0644 "$WORK/new.crt" "${PG_SERVER_CERT}.new"
mv -f "${PG_SERVER_KEY}.new" "$PG_SERVER_KEY"
mv -f "${PG_SERVER_CERT}.new" "$PG_SERVER_CERT"

served_serial() {
  timeout 10 openssl s_client -starttls postgres -connect "${INTERNAL_IP}:${PG_PORT}" -CAfile "$PG_CA_CERT" \
    -verify_ip "$INTERNAL_IP" -verify_return_error </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}
rollback() {
  if [[ "$had_previous" == 1 ]]; then
    install -o "$owner_user" -g "$owner_group" -m 0600 "$WORK/prev.key" "$PG_SERVER_KEY"
    install -o "$owner_user" -g "$owner_group" -m 0644 "$WORK/prev.crt" "$PG_SERVER_CERT"
    bash -c "$RELOAD_CMD" >/dev/null 2>&1 || true
    log err "rolled back to the previous server certificate"
  else
    log err "no previous certificate to restore"
  fi
}

if ! bash -c "$RELOAD_CMD"; then log err "PostgreSQL reload failed"; rollback; exit 1; fi
verified=0
for _ in $(seq 1 10); do
  if [[ "$(served_serial || true)" == "$new_serial" ]]; then verified=1; break; fi
  sleep 1
done
if [[ "$verified" != 1 ]]; then log err "new certificate (serial ${new_serial}) is not being served with a verified chain"; rollback; exit 1; fi

log notice "renewed: serial ${new_serial}, $(openssl x509 -noout -enddate -in "$PG_SERVER_CERT"), SAN IP ${INTERNAL_IP}; CA fingerprint unchanged $(openssl x509 -noout -fingerprint -sha256 -in "$PG_CA_CERT" | cut -d= -f2)"
