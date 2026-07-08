#!/bin/sh
# Docker entrypoint — runs before the container CMD.
#
# Responsibilities:
#   1. Validate required environment variables.
#   2. Gate schema sync on APPLY_SCHEMA. When sync is requested, run
#      `prisma db push` under a Postgres advisory lock so concurrent replicas
#      (and any accidental cross-image pushes) serialize.
#   3. exec the container CMD.
#
# Either image (server or worker) can be the schema leader. Set APPLY_SCHEMA
# on exactly one image for a schema-changing deploy; the other keeps it at
# off (or unset). Keep schema sync controlled by APPLY_SCHEMA.
#
# APPLY_SCHEMA values:
#   off       — skip schema sync. Normal app boot. Default when unset.
#   safe      — run `prisma db push`. Prisma refuses destructive operations
#               (drop column, narrow type, etc.) and exits non-zero.
#   dangerous — run `prisma db push --accept-data-loss`. Destructive operations
#               are applied.

set -e

# --- 1. Required env vars ---
missing=""
required_vars="DATABASE_URL REDIS_URL"
case " $* " in
  *" apps/server/dist/index.mjs"*|*" apps/server/"*)
    required_vars="$required_vars BETTER_AUTH_SECRET"
    ;;
esac

for var in $required_vars; do
  eval val=\$$var
  if [ -z "$val" ]; then
    missing="$missing $var"
  fi
done

if [ -n "$missing" ]; then
  echo "FATAL: Missing required environment variable(s):$missing" >&2
  echo "       Set them in your orchestrator (Dokploy, Azure Container Apps, etc.)." >&2
  exit 1
fi

if [ "$NODE_ENV" = "production" ] && [ -z "$ADMIN_EMAILS" ]; then
  echo "WARNING: ADMIN_EMAILS is empty. No users will be granted admin privileges." >&2
  echo "         Set ADMIN_EMAILS to a comma-separated list of email addresses." >&2
fi

# --- 2. Schema sync ---
APPLY_SCHEMA="${APPLY_SCHEMA:-off}"
case "$APPLY_SCHEMA" in
  off)
    echo "APPLY_SCHEMA=off — skipping schema sync."
    ;;
  safe)
    echo "APPLY_SCHEMA=safe — applying non-destructive schema changes."
    # Prisma 7's `db push` does not run `generate` and rejects `--skip-generate`
    # ("unknown or unexpected option"). The client is already generated at
    # image-build time, so no flag is needed here.
    push_flags=""
    ;;
  dangerous)
    echo "APPLY_SCHEMA=dangerous — applying schema changes with --accept-data-loss."
    push_flags="--accept-data-loss"
    ;;
  *)
    echo "FATAL: APPLY_SCHEMA=$APPLY_SCHEMA is invalid. Use off, safe, or dangerous." >&2
    exit 1
    ;;
esac

if [ "$APPLY_SCHEMA" != "off" ]; then
  # 0x44414450 = "DADP" — template-specific magic number for the advisory
  # lock. `prisma db push` does NOT take an advisory lock on its own (unlike
  # `prisma migrate deploy`), so we wrap it ourselves to serialize replicas.
  LOCK_ID=1145389648
  STATUS_FILE=$(mktemp)
  echo 1 > "$STATUS_FILE"

  echo "Acquiring schema advisory lock ($LOCK_ID)..."
  # psql holds a session-level advisory lock across the `\!` shell call that
  # invokes `prisma db push`. When the heredoc closes, the session exits and
  # the lock is released.
  #
  # We call the prisma CLI by its copied path (node_modules/.bin/prisma)
  # rather than `npx prisma`: the binary is COPY'd into the image explicitly
  # by both Dockerfiles, and the global npm/npx is stripped from the runtime
  # image (it is never used at runtime and its vendored deps drag in CVEs).
  #
  # Connect psql via discrete libpq PG* env vars rather than passing
  # DATABASE_URL as a CLI argument. A CLI argument is visible in
  # /proc/<pid>/cmdline, so the password would leak to anything that can read
  # process listings inside the container during the push; PGPASSWORD does not.
  # We parse with node (already in the image — the HEALTHCHECK uses it too)
  # because POSIX sh has no URL parser. Forwarding only the libpq-understood
  # fields also avoids psql choking on Prisma-only query params (e.g. ?schema=).
  # prisma db push is unaffected: it reads the full DATABASE_URL from the
  # environment itself.
  pg_env="$(node -e '
    const u = new URL(process.env.DATABASE_URL);
    const SQ = String.fromCharCode(39);
    const q = (v) => SQ + String(v).split(SQ).join(SQ + "\\" + SQ + SQ) + SQ;
    const dec = (v) => { try { return decodeURIComponent(v); } catch { return v; } };
    const out = [];
    out.push("export PGHOST=" + q(dec(u.hostname)));
    if (u.port) out.push("export PGPORT=" + q(u.port));
    if (u.username) out.push("export PGUSER=" + q(dec(u.username)));
    if (u.password) out.push("export PGPASSWORD=" + q(dec(u.password)));
    const db = dec(u.pathname.replace(/^\//, ""));
    if (db) out.push("export PGDATABASE=" + q(db));
    const sslmode = u.searchParams.get("sslmode");
    if (sslmode) out.push("export PGSSLMODE=" + q(sslmode));
    process.stdout.write(out.join("\n") + "\n");
  ')" || { echo "FATAL: could not parse DATABASE_URL for psql." >&2; exit 1; }
  eval "$pg_env"

  psql -v ON_ERROR_STOP=1 <<EOF
SET lock_timeout = '300s';
SELECT pg_advisory_lock($LOCK_ID);
\! cd /app/packages/db && node_modules/.bin/prisma db push $push_flags; echo \$? > $STATUS_FILE
SELECT pg_advisory_unlock($LOCK_ID);
EOF

  status=$(cat "$STATUS_FILE")
  rm -f "$STATUS_FILE"
  if [ "$status" != "0" ]; then
    echo "FATAL: prisma db push failed (exit $status)." >&2
    if [ "$APPLY_SCHEMA" = "safe" ]; then
      echo "       This usually means the schema change includes a destructive" >&2
      echo "       operation (drop column, narrow type, etc.). Review the diff." >&2
      echo "       If the data loss is intentional, review the schema diff" >&2
      echo "       and backup posture before using APPLY_SCHEMA=dangerous." >&2
    fi
    exit 1
  fi
  echo "Schema sync complete."
fi

# --- 3. Hand off to the container CMD ---
exec "$@"
