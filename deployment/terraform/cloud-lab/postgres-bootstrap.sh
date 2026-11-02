#!/bin/bash
# Idempotent: safe to re-run on every boot. Contains no credentials.
set -euo pipefail

CA_DAYS=365
SERVER_DAYS=30
SERVER_RENEW_BEFORE_SECONDS=604800 # reissue the server certificate when <7 days remain
CA_WARN_BEFORE_SECONDS=2592000     # warn loudly when <30 days of CA life remain

export DEBIAN_FRONTEND=noninteractive
if ! dpkg -s postgresql-16 >/dev/null 2>&1; then
  # The VM has no external address. Package installation needs egress through a
  # Cloud NAT that already covers this subnet (Terraform does not create one).
  if ! { apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 update &&
         apt-get install --yes postgresql-16 postgresql-client-16 openssl; }; then
    echo "FATAL: package installation failed. Verify that a Cloud NAT covers the laboratory subnet (see README)." >&2
    exit 1
  fi
fi

INTERNAL_IP="$(hostname -I | awk '{print $1}')"
PG_VERSION="$(ls /etc/postgresql | sort -V | tail -n 1)"
PG_CONF="/etc/postgresql/$${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/$${PG_VERSION}/main/pg_hba.conf"
PG_TLS_DIR="/etc/postgresql/$${PG_VERSION}/main/tls"
LAB_DIR="/var/lib/limitmark-lab"
PG_CA_DIR="$${LAB_DIR}/ca"
PG_CA_PUBLIC_DIR="$${LAB_DIR}/public"
PG_CA_KEY="$${PG_CA_DIR}/lab-ca.key"
PG_CA_CERT="$${PG_CA_DIR}/lab-ca.crt"
PG_CA_PUBLIC_CERT="$${PG_CA_PUBLIC_DIR}/lab-ca.crt"
PG_SERVER_KEY="$${PG_TLS_DIR}/server.key"
PG_SERVER_CERT="$${PG_TLS_DIR}/server.crt"

install -d -o root -g root -m 0755 "$LAB_DIR" "$PG_CA_PUBLIC_DIR"
install -d -o postgres -g postgres -m 0700 "$PG_TLS_DIR" "$PG_CA_DIR"

# --- CA: created once and persisted on the boot disk; never rotated automatically.
if [[ ! -s "$PG_CA_KEY" || ! -s "$PG_CA_CERT" ]]; then
  openssl req -x509 -newkey rsa:4096 -nodes -days "$CA_DAYS" \
    -subj "/CN=LimitMark laboratory PostgreSQL CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$PG_CA_KEY" \
    -out "$PG_CA_CERT"
fi
chown postgres:postgres "$PG_CA_KEY" "$PG_CA_CERT"
chmod 0600 "$PG_CA_KEY"
chmod 0644 "$PG_CA_CERT"
if ! openssl x509 -checkend 0 -noout -in "$PG_CA_CERT" >/dev/null; then
  echo "FATAL: the laboratory CA has expired. Reprovision the VM and replace the database CA secret version (see README)." >&2
  exit 1
fi
if ! openssl x509 -checkend "$CA_WARN_BEFORE_SECONDS" -noout -in "$PG_CA_CERT" >/dev/null; then
  echo "WARNING: the laboratory CA expires within 30 days. Plan reprovisioning." >&2
fi

# --- Server certificate: reissued when missing, near expiry, bound to another IP, or not chained to the CA.
needs_server_cert() {
  [[ -s "$PG_SERVER_KEY" && -s "$PG_SERVER_CERT" ]] || return 0
  openssl x509 -checkend "$SERVER_RENEW_BEFORE_SECONDS" -noout -in "$PG_SERVER_CERT" >/dev/null || return 0
  openssl x509 -noout -ext subjectAltName -in "$PG_SERVER_CERT" | grep -Fq "IP Address:$${INTERNAL_IP}" || return 0
  openssl verify -CAfile "$PG_CA_CERT" "$PG_SERVER_CERT" >/dev/null 2>&1 || return 0
  return 1
}
if needs_server_cert; then
  WORK="$(mktemp -d "$${PG_TLS_DIR}/issue.XXXXXX")"
  cat > "$WORK/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$${INTERNAL_IP}
EXT
  openssl req -new -newkey rsa:2048 -nodes \
    -subj "/CN=$${INTERNAL_IP}" \
    -keyout "$WORK/server.key" -out "$WORK/server.csr"
  openssl x509 -req -sha256 -days "$SERVER_DAYS" \
    -CA "$PG_CA_CERT" -CAkey "$PG_CA_KEY" -CAcreateserial -CAserial "$WORK/ca.srl" \
    -in "$WORK/server.csr" -out "$WORK/server.crt" \
    -extfile "$WORK/server.ext"
  install -o postgres -g postgres -m 0600 "$WORK/server.key" "$PG_SERVER_KEY"
  install -o postgres -g postgres -m 0644 "$WORK/server.crt" "$PG_SERVER_CERT"
  rm -rf "$WORK"
fi

# --- Public (non-secret) CA certificate copy for operator export over IAP SSH. The CA key stays in $PG_CA_DIR (0700).
# The fingerprint is public data; it is logged (serial port 1) as an independent channel for the operator to compare.
install -o root -g root -m 0644 "$PG_CA_CERT" "$PG_CA_PUBLIC_CERT"
echo "LAB_CA_FINGERPRINT: $(openssl x509 -noout -fingerprint -sha256 -in "$PG_CA_PUBLIC_CERT")"

# --- PostgreSQL configuration (private address only, TLS required).
sed -i -E '/^(listen_addresses|ssl|ssl_cert_file|ssl_key_file|password_encryption) =/d' "$${PG_CONF}"
cat >> "$${PG_CONF}" <<CONF
listen_addresses = '$${INTERNAL_IP}'
ssl = on
ssl_cert_file = '$${PG_SERVER_CERT}'
ssl_key_file = '$${PG_SERVER_KEY}'
password_encryption = 'scram-sha-256'
CONF

sed -i '/^# BEGIN limitmark-lab managed$/,/^# END limitmark-lab managed$/d' "$${PG_HBA}"
cat >> "$${PG_HBA}" <<HBA
# BEGIN limitmark-lab managed
hostnossl all all 0.0.0.0/0 reject
hostssl ${database_name} ${database_user} ${subnet_cidr} scram-sha-256
hostssl ${database_name} ${migration_user} ${subnet_cidr} scram-sha-256
# END limitmark-lab managed
HBA

systemctl enable "postgresql@$${PG_VERSION}-main"
systemctl restart "postgresql@$${PG_VERSION}-main"
for _ in $(seq 1 30); do
  runuser -u postgres -- pg_isready --quiet && break
  sleep 2
done
runuser -u postgres -- pg_isready --quiet

# --- Roles and database over the local socket (peer auth). Roles are created WITHOUT passwords,
# so SCRAM login is impossible until an operator sets each password interactively (see README).
runuser -u postgres -- psql --no-psqlrc -v ON_ERROR_STOP=1 <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', '${migration_user}')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${migration_user}')\gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', '${database_user}')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${database_user}')\gexec
SELECT format('CREATE DATABASE %I OWNER %I', '${database_name}', '${migration_user}')
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${database_name}')\gexec
ALTER DATABASE "${database_name}" OWNER TO "${migration_user}";
REVOKE ALL ON DATABASE "${database_name}" FROM PUBLIC;
GRANT CONNECT ON DATABASE "${database_name}" TO "${database_user}";
\connect "${database_name}"
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO "${database_user}";
SQL

echo "PostgreSQL ready on the private laboratory interface; set role passwords and run migrations per README."
