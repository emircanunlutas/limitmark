#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes postgresql-16 postgresql-client-16 openssl

INTERNAL_IP="$(hostname -I | awk '{print $1}')"
PG_VERSION="$(ls /etc/postgresql | sort -V | tail -n 1)"
PG_CONF="/etc/postgresql/$${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/$${PG_VERSION}/main/pg_hba.conf"
PG_TLS_DIR="/etc/postgresql/$${PG_VERSION}/main/tls"

install -d -o postgres -g postgres -m 0700 "$PG_TLS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=$${INTERNAL_IP}" \
  -keyout "$${PG_TLS_DIR}/server.key" \
  -out "$${PG_TLS_DIR}/server.crt"
chown postgres:postgres "$${PG_TLS_DIR}/server.key" "$${PG_TLS_DIR}/server.crt"
chmod 0600 "$${PG_TLS_DIR}/server.key"
chmod 0644 "$${PG_TLS_DIR}/server.crt"

cat >> "$${PG_CONF}" <<EOF
listen_addresses = '$${INTERNAL_IP}'
ssl = on
ssl_cert_file = '$${PG_TLS_DIR}/server.crt'
ssl_key_file = '$${PG_TLS_DIR}/server.key'
password_encryption = 'scram-sha-256'
EOF

cat >> "$${PG_HBA}" <<EOF
hostnossl all all 0.0.0.0/0 reject
hostssl ${database_name} ${database_user} 10.80.0.0/24 scram-sha-256
EOF

systemctl restart "postgresql@$${PG_VERSION}-main"
systemctl enable "postgresql@$${PG_VERSION}-main"
echo "PostgreSQL installed and restricted to the private laboratory interface."
echo "Create the ${database_name} database and ${database_user} role out-of-band before use."
