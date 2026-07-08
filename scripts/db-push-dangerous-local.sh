#!/usr/bin/env bash
set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "FATAL: DATABASE_URL is not set." >&2
  exit 1
fi

HOST="$(
  node -e '
const url = new URL(process.env.DATABASE_URL);
process.stdout.write(url.hostname);
'
)"

case "$HOST" in
  localhost|127.*|10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2[0-9].*|172.30.*|172.31.*|postgres|db|database|host.docker.internal)
    ;;
  *)
    if [ "${ALLOW_NONLOCAL_DANGEROUS_DB_PUSH:-}" != "I_UNDERSTAND_THIS_CAN_DESTROY_DATA" ]; then
      cat >&2 <<EOF
FATAL: Refusing db:push:dangerous against non-local database host: $HOST

This command can drop columns/tables and destroy data. Use the expand-contract
schema recipe for shared or production databases. If this is truly a disposable
database, rerun with:

  ALLOW_NONLOCAL_DANGEROUS_DB_PUSH=I_UNDERSTAND_THIS_CAN_DESTROY_DATA pnpm db:push:dangerous
EOF
      exit 1
    fi
    ;;
esac

prisma db push --accept-data-loss
