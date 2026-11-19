#!/usr/bin/env bash
# Records already-applied Drizzle migrations after PROVING the live schema equals the expected migration result.
# Usage: CONN="<libpq conninfo as the migration role>" [PGPASSFILE=...] ./drizzle-reconcile.sh <baseline.sql>
# Files expected beside this script: drizzle-schema-fingerprint.sql, drizzle-expected-schema.txt
# Read-only until the fingerprint matches; the baseline never modifies application tables.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
baseline="${1:?baseline SQL file (from drizzle-baseline.mjs) required}"
: "${CONN:?CONN (libpq conninfo for the migration role) required}"
PSQL=(psql --no-psqlrc -X -q -v ON_ERROR_STOP=1)

actual="$(mktemp)"; trap 'rm -f "$actual"' EXIT
"${PSQL[@]}" "$CONN" -At -f "$here/drizzle-schema-fingerprint.sql" > "$actual"

if [ ! -s "$actual" ]; then echo "ABORT: empty schema fingerprint (wrong database?)" >&2; exit 2; fi
if ! diff -u "$here/drizzle-expected-schema.txt" "$actual"; then
  echo "ABORT: live schema differs from the expected migration result; nothing was recorded." >&2
  exit 3
fi
echo "schema fingerprint matches ($(wc -l < "$actual") lines)"

"${PSQL[@]}" "$CONN" -f "$baseline"
"${PSQL[@]}" "$CONN" -At -c "select id, left(hash, 16), created_at from drizzle.__drizzle_migrations order by created_at"
