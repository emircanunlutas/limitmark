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
PG_CA_DIR="/var/lib/limitmark-lab/ca"
PG_CA_KEY="$${PG_CA_DIR}/lab-ca.key"
PG_CA_CERT="$${PG_CA_DIR}/lab-ca.crt"
PG_SERVER_KEY="$${PG_TLS_DIR}/server.key"
PG_SERVER_CSR="$${PG_TLS_DIR}/server.csr"
PG_SERVER_CERT="$${PG_TLS_DIR}/server.crt"

install -d -o postgres -g postgres -m 0700 "$PG_TLS_DIR"
install -d -o postgres -g postgres -m 0700 "$PG_CA_DIR"
if [[ ! -s "$PG_CA_KEY" || ! -s "$PG_CA_CERT" ]]; then
  openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -subj "/CN=LimitMark laboratory PostgreSQL CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$PG_CA_KEY" \
    -out "$PG_CA_CERT"
fi
if [[ ! -s "$PG_SERVER_KEY" || ! -s "$PG_SERVER_CERT" ]]; then
  cat > "$${PG_TLS_DIR}/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$${INTERNAL_IP}
EOF
  openssl req -new -newkey rsa:2048 -nodes \
    -subj "/CN=$${INTERNAL_IP}" \
    -keyout "$PG_SERVER_KEY" \
    -out "$PG_SERVER_CSR"
  openssl x509 -req -sha256 -days 30 \
    -CA "$PG_CA_CERT" -CAkey "$PG_CA_KEY" -CAcreateserial \
    -in "$PG_SERVER_CSR" -out "$PG_SERVER_CERT" \
    -extfile "$${PG_TLS_DIR}/server.ext"
  rm -f "$PG_SERVER_CSR" "$${PG_TLS_DIR}/server.ext" "$${PG_CA_DIR}/lab-ca.srl"
fi
chown postgres:postgres "$PG_SERVER_KEY" "$PG_SERVER_CERT"
chown postgres:postgres "$PG_CA_KEY" "$PG_CA_CERT"
chmod 0600 "$PG_SERVER_KEY" "$PG_CA_KEY"
chmod 0644 "$PG_SERVER_CERT" "$PG_CA_CERT"

sed -i -E '/^(listen_addresses|ssl|ssl_cert_file|ssl_key_file|password_encryption) =/d' "$${PG_CONF}"
cat >> "$${PG_CONF}" <<EOF
listen_addresses = '$${INTERNAL_IP}'
ssl = on
ssl_cert_file = '$${PG_SERVER_CERT}'
ssl_key_file = '$${PG_SERVER_KEY}'
password_encryption = 'scram-sha-256'
EOF

if ! grep -Fq "hostnossl all all 0.0.0.0/0 reject" "$${PG_HBA}"; then
cat >> "$${PG_HBA}" <<EOF
hostnossl all all 0.0.0.0/0 reject
hostssl ${database_name} ${database_user} 10.80.0.0/24 scram-sha-256
EOF
fi

systemctl restart "postgresql@$${PG_VERSION}-main"
systemctl enable "postgresql@$${PG_VERSION}-main"
echo "PostgreSQL installed and restricted to the private laboratory interface."
echo "Create separate migration and application roles plus the ${database_name} database out-of-band before use."
