#!/usr/bin/env bash
# Database backup — runs pg_dump against $DATABASE_URL and writes a timestamped
# SQL dump into ./backups. If BACKUP_S3_BUCKET is set, the dump is uploaded to
# that private S3/R2 bucket after pg_dump succeeds. The connection URL is
# parsed into PG* environment variables before pg_dump starts so the password is
# not exposed via argv.
#
# Usage:
#   DATABASE_URL=postgresql://... ./scripts/backup.sh
#
# Restore:
#   scripts/backup.sh writes plain SQL. Restore only into an empty target.
#   Test restore procedures before relying on backups.
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "FATAL: DATABASE_URL is not set." >&2
  echo "       Export it before running: DATABASE_URL=postgresql://... $0" >&2
  exit 1
fi

BACKUP_DIR="${BACKUP_DIR:-backups}"
mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTFILE="$BACKUP_DIR/backup-$TIMESTAMP.sql"

echo "Writing backup to $OUTFILE"

# Parse the connection URL into PG* env vars so the password never appears in
# argv. node emits each field NUL-terminated; `read -d ''` assigns the raw bytes
# literally, so passwords containing $, backticks, backslashes, or spaces are
# handled correctly (an `eval` of quoted strings is not safe for those).
{
  IFS= read -r -d '' PGHOST
  IFS= read -r -d '' PGPORT
  IFS= read -r -d '' PGDATABASE
  IFS= read -r -d '' PGUSER
  IFS= read -r -d '' PGPASSWORD
  IFS= read -r -d '' DB_SSLMODE
} < <(
  node -e '
const url = new URL(process.env.DATABASE_URL);
const fields = [
  url.hostname,
  url.port || "5432",
  url.pathname.replace(/^\/+/, ""),
  decodeURIComponent(url.username),
  decodeURIComponent(url.password),
  url.searchParams.get("sslmode") || "",
];
process.stdout.write(fields.map((value) => `${value}\0`).join(""));
'
)
export PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD
[ -n "$DB_SSLMODE" ] && export PGSSLMODE="$DB_SSLMODE"

pg_dump --no-owner --no-privileges > "$OUTFILE"

if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
  node scripts/upload-backup-to-s3.mjs "$OUTFILE"
fi

echo "Done."
