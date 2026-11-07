#!/usr/bin/env bash
# Integration test for postgres-renew-cert.sh against a REAL PostgreSQL, run as root INSIDE a disposable postgres container
# (never on the laboratory VM). Example (from the repo root):
#   docker run -d --name lm-cert-test -e POSTGRES_PASSWORD=localtest postgres:16-alpine
#   docker exec lm-cert-test apk add --no-cache bash openssl coreutils
#   docker cp deployment/terraform/cloud-lab/. lm-cert-test:/w && docker exec lm-cert-test bash /w/test-renew-cert.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RENEW="$HERE/postgres-renew-cert.sh"
T=/tmp/certtest; rm -rf "$T"; mkdir -p "$T/ca" "$T/tls"; chown postgres:postgres "$T/tls"; chmod 700 "$T/tls"
IP=127.0.0.1
export PG_VERSION=16 PG_TLS_DIR="$T/tls" PG_CA_KEY="$T/ca/ca.key" PG_CA_CERT="$T/ca/ca.crt" INTERNAL_IP="$IP" \
       PG_SERVER_KEY="$T/tls/server.key" PG_SERVER_CERT="$T/tls/server.crt" LOCK_FILE="$T/lock" \
       RELOAD_CMD="su postgres -c 'pg_ctl reload -D $PGDATA'"
pass=0; fail=0
check() { if eval "$2"; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; fail=$((fail + 1)); fi; }
serial_of() { openssl x509 -noout -serial -in "$1" | cut -d= -f2; }
served() { openssl s_client -starttls postgres -connect "$IP:5432" -CAfile "$PG_CA_CERT" -verify_ip "$IP" -verify_return_error </dev/null 2>/dev/null | openssl x509 -noout -serial | cut -d= -f2; }
issue() { # $1 days, $2 SAN ip
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$T/i.key" -out "$T/i.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "$2" > "$T/i.ext"
  openssl x509 -req -sha256 -days "$1" -CA "$PG_CA_CERT" -CAkey "$PG_CA_KEY" -CAcreateserial -CAserial "$T/i.srl" -in "$T/i.csr" -out "$T/i.crt" -extfile "$T/i.ext" 2>/dev/null
  install -o postgres -g postgres -m 0600 "$T/i.key" "$PG_SERVER_KEY"; install -o postgres -g postgres -m 0644 "$T/i.crt" "$PG_SERVER_CERT"
  su postgres -c "pg_ctl reload -D $PGDATA" >/dev/null; sleep 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=Test CA" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -keyout "$PG_CA_KEY" -out "$PG_CA_CERT" 2>/dev/null; chmod 600 "$PG_CA_KEY"
CA_FP="$(openssl x509 -noout -fingerprint -sha256 -in "$PG_CA_CERT")"
issue 5 "$IP"
su postgres -c "psql -qAt -c \"ALTER SYSTEM SET ssl='on'\" -c \"ALTER SYSTEM SET ssl_cert_file='$PG_SERVER_CERT'\" -c \"ALTER SYSTEM SET ssl_key_file='$PG_SERVER_KEY'\"" >/dev/null
su postgres -c "pg_ctl reload -D $PGDATA" >/dev/null; sleep 2
OLD="$(serial_of "$PG_SERVER_CERT")"
check "precondition: PostgreSQL serves the 5-day certificate" '[ "$(served)" = "$OLD" ]'

echo "--- due (5 days left, threshold 10)"
bash "$RENEW" >"$T/out1" 2>&1; rc=$?
NEW="$(serial_of "$PG_SERVER_CERT")"
check "renewal exits 0" '[ $rc -eq 0 ]'
check "certificate was replaced" '[ "$NEW" != "$OLD" ]'
check "PostgreSQL now serves the new certificate over a verified chain" '[ "$(served)" = "$NEW" ]'
check "SAN is the private IP only" 'openssl x509 -noout -ext subjectAltName -in "$PG_SERVER_CERT" | grep -Fq "IP Address:$IP" && [ "$(openssl x509 -noout -ext subjectAltName -in "$PG_SERVER_CERT" | grep -c "IP Address")" = 1 ]'
check "new certificate has ~30 days of life" 'openssl x509 -checkend $((25*86400)) -noout -in "$PG_SERVER_CERT" >/dev/null'
check "CA unchanged (continuity)" '[ "$(openssl x509 -noout -fingerprint -sha256 -in "$PG_CA_CERT")" = "$CA_FP" ]'
check "server key permissions 0600 owned by postgres" '[ "$(stat -c "%a %U" "$PG_SERVER_KEY")" = "600 postgres" ]'
check "no temporary key material left behind" '[ "$(ls -A "$PG_TLS_DIR" | sort | tr "\n" " ")" = "server.crt server.key " ]'
check "log reports success without secrets" 'grep -q "renewed: serial $NEW" "$T/out1" && ! grep -Eq "PRIVATE KEY|BEGIN" "$T/out1"'
check "strict verify-full client connection works" 'PGPASSWORD=localtest psql "host=$IP port=5432 dbname=postgres user=postgres sslmode=verify-full sslrootcert=$PG_CA_CERT" -Atc "select ssl from pg_stat_ssl where pid=pg_backend_pid()" | grep -q t'

echo "--- not due (renewal must not touch a healthy certificate)"
bash "$RENEW" >"$T/out2" 2>&1; rc=$?
check "exit 0 and serial unchanged" '[ $rc -eq 0 ] && [ "$(serial_of "$PG_SERVER_CERT")" = "$NEW" ]'
check "logs 'not due'" 'grep -q "not due" "$T/out2"'

echo "--- wrong SAN (IP changed)"
issue 30 10.9.9.9
BAD="$(serial_of "$PG_SERVER_CERT")"
bash "$RENEW" >"$T/out3" 2>&1; rc=$?
check "renews and serves a certificate for the real IP" '[ $rc -eq 0 ] && [ "$(serial_of "$PG_SERVER_CERT")" != "$BAD" ] && [ "$(served)" = "$(serial_of "$PG_SERVER_CERT")" ]'

echo "--- reload failure must roll back"
issue 5 "$IP"
KEEP="$(serial_of "$PG_SERVER_CERT")"
RELOAD_CMD=false bash "$RENEW" >"$T/out4" 2>&1; rc=$?
check "exits non-zero" '[ $rc -ne 0 ]'
check "previous certificate restored" '[ "$(serial_of "$PG_SERVER_CERT")" = "$KEEP" ] && [ "$(served)" = "$KEEP" ]'
check "failure logged as error without secrets" 'grep -q "rolled back" "$T/out4" && ! grep -Eq "PRIVATE KEY|BEGIN" "$T/out4"'

echo "--- expired CA must fail closed"
cp "$PG_CA_CERT" "$T/ca/ca.good"; openssl req -x509 -key "$PG_CA_KEY" -not_before 20200101000000Z -not_after 20200102000000Z -subj "/CN=Test CA" -out "$PG_CA_CERT" 2>/dev/null
BEFORE="$(serial_of "$PG_SERVER_CERT")"
bash "$RENEW" >"$T/out5" 2>&1; rc=$?
check "exit 1, certificate untouched, reason logged" '[ $rc -eq 1 ] && [ "$(serial_of "$PG_SERVER_CERT")" = "$BEFORE" ] && grep -q "CA has expired" "$T/out5"'
cp "$T/ca/ca.good" "$PG_CA_CERT"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
