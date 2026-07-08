FROM node:24-slim AS base

# Runtime base:
#   - openssl: required by Prisma query engine
#   - postgresql-client: provides psql, used by docker-entrypoint.sh to hold a
#     Postgres advisory lock around `prisma db push` (multi-replica safety).
# `apt-get upgrade` pulls the latest Debian 12 security patches for packages
# already in node:24-slim (glibc, libcap2, systemd libs, etc.) — the base image
# lags the Debian point release, so Trivy fails on fixable HIGH CVEs without it.
RUN apt-get update -y && apt-get upgrade -y && apt-get install -y \
  openssl \
  postgresql-client \
  && rm -rf /var/lib/apt/lists/*

# --- Build-time base ---
# Adds git + pnpm. Not inherited by the final runtime image.
FROM base AS build-base

RUN apt-get update -y && apt-get install -y \
  git \
  && rm -rf /var/lib/apt/lists/*

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@11.1.2 --activate

# --- Builder stage ---
# pnpm install runs here with source files present so workspace symlinks resolve correctly
FROM build-base AS builder

WORKDIR /app

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml turbo.json ./
COPY apps/web/package.json apps/web/
COPY apps/server/package.json apps/server/
COPY apps/worker/package.json apps/worker/
COPY apps/relay/package.json apps/relay/
COPY packages/api/package.json packages/api/
COPY packages/auth/package.json packages/auth/
COPY packages/config/package.json packages/config/
COPY packages/db/package.json packages/db/
COPY packages/env/package.json packages/env/
COPY packages/i18n-translate/package.json packages/i18n-translate/
COPY packages/mailer/package.json packages/mailer/
COPY packages/queue/package.json packages/queue/
COPY packages/relay-protocol/package.json packages/relay-protocol/
COPY packages/test-utils/package.json packages/test-utils/
COPY packages/ui/package.json packages/ui/

# Prisma schema + config must be present before install (postinstall runs prisma generate)
COPY packages/db/prisma.config.ts packages/db/
COPY packages/db/prisma packages/db/prisma

# Strip the root `postinstall` (which only runs `lefthook install`, a dev-only
# git hook installer that errors without a real repo). The real package.json is
# restored by the subsequent `COPY . .`, so this only affects the install step.
RUN node -e "const f='package.json';const p=JSON.parse(require('fs').readFileSync(f));delete p.scripts.postinstall;require('fs').writeFileSync(f,JSON.stringify(p,null,2))"

RUN pnpm install --frozen-lockfile

COPY . .

# Keep the restored root package.json from reintroducing the dev-only lefthook
# installer in later Docker build steps after the full source tree is copied.
RUN node -e "const f='package.json';const p=JSON.parse(require('fs').readFileSync(f));delete p.scripts.postinstall;require('fs').writeFileSync(f,JSON.stringify(p,null,2))"

# Remove any stale .js files next to .tsx route files (breaks TanStack Router)
RUN find apps/web/src/routes -name '*.js' -delete 2>/dev/null || true

# Build-time client env. Vite inlines VITE_* into the SPA bundle during the
# build below — they are NOT read at runtime, so they must be present here.
# Render (and any platform that forwards env vars into the Docker build)
# injects a service's env vars as build args with matching keys, so setting
# these on the `server` service in render.yaml flows them in. All three are
# optional; an empty value falls back to the app default (VITE_APP_NAME -> "App",
# VITE_SERVER_URL -> window.location.origin, client-side push registration
# disabled). Changing any of them requires a REBUILD, not just a restart.
# Worker note: Dockerfile.worker does NOT build the web SPA, so it needs no
# matching ARG block — this is the one build-arg surface that legitimately
# differs between the two Dockerfiles.
ARG VITE_APP_NAME=""
ARG VITE_SERVER_URL=""
ARG VITE_VAPID_PUBLIC_KEY=""
ENV VITE_APP_NAME=$VITE_APP_NAME \
    VITE_SERVER_URL=$VITE_SERVER_URL \
    VITE_VAPID_PUBLIC_KEY=$VITE_VAPID_PUBLIC_KEY

# Deterministic build version. The web build (vite.config.ts → getBuildVersion())
# prefers process.env.BUILD_VERSION over `git rev-parse` — and `.git` is excluded
# from the Docker context, so without this the build falls back to a random UUID
# per build (a fresh "version" on every rebuild of the SAME commit). Pass a
# stable value (the git SHA) so identical content keeps the same version across
# rebuilds. Empty = falls back to the random UUID. Render forwards a service's
# env vars into the build as build args, so set BUILD_VERSION on the `server`
# service in render.yaml (wired to the commit SHA) to make it stable.
# Worker note: Dockerfile.worker does NOT build the web SPA, so it needs no
# matching ARG — same as the VITE_* block above.
ARG BUILD_VERSION=""
ENV BUILD_VERSION=$BUILD_VERSION

# --- Turborepo Remote Cache ---
# Shipped present-but-inert: with both empty (the default on a fresh clone),
# turbo reports NotLinked and the build runs normally with local cache only —
# no error, no behavior change ("just skips"). Set TURBO_TOKEN + TURBO_TEAM
# (BOTH required; a token alone is ignored) to make `turbo build` replay cached
# app outputs from Vercel's free remote cache ("just works"). Platforms that
# forward a service's env vars into the Docker build as build args (Render)
# populate these automatically; everywhere else pass them explicitly, e.g.
# `docker build --build-arg TURBO_TOKEN=… --build-arg TURBO_TEAM=…`. Self-host
# instead? add a matching `ARG TURBO_API=""` here and point it at your cache
# (see the pattern doc). Builder stage ONLY — the final runner stage is
# FROM base and never inherits these ENVs, so the token never ships in the
# image. Keep this block in BOTH Dockerfiles (AGENTS.md § keep in sync).
ARG TURBO_TOKEN=""
ARG TURBO_TEAM=""
ENV TURBO_TOKEN=$TURBO_TOKEN \
    TURBO_TEAM=$TURBO_TEAM

RUN pnpm turbo build --filter=server --filter=web

# Verify build outputs exist
RUN test -f apps/server/dist/index.mjs && test -d apps/web/dist/client && test -d apps/web/dist/server

# --- Production deps stage ---
FROM build-base AS prod-deps

WORKDIR /app

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
COPY apps/relay/package.json apps/relay/
COPY packages/api/package.json packages/api/
COPY packages/auth/package.json packages/auth/
COPY packages/config/package.json packages/config/
COPY packages/db/package.json packages/db/
COPY packages/env/package.json packages/env/
COPY packages/i18n-translate/package.json packages/i18n-translate/
COPY packages/mailer/package.json packages/mailer/
COPY packages/queue/package.json packages/queue/
COPY packages/relay-protocol/package.json packages/relay-protocol/
COPY packages/test-utils/package.json packages/test-utils/
COPY packages/ui/package.json packages/ui/

# Prisma schema + config needed for postinstall
COPY packages/db/prisma.config.ts packages/db/
COPY packages/db/prisma packages/db/prisma

# Install prod deps for BOTH the server and the web app. The server bundle
# imports the built web SSR handler (apps/web/dist/server), which leaves `react`
# external — so web's runtime deps must be present in the image for SSR to load.
RUN pnpm install --frozen-lockfile --prod --ignore-scripts --filter=server... --filter=web...

# --- Runner stage ---
# Server image: Hono API + SSR bundle + static web SPA. Ships the Prisma CLI
# and postgresql-client so `prisma db push` can run on boot when
# APPLY_SCHEMA=safe|dangerous. The worker image ships the same tooling — either
# image can be the schema leader on a given deploy.
# If you want a smaller app image and always lead schema sync from the worker
# (or an ACA Job), see the "slim app image variant" section in that doc.
# No .env files are COPYed into the image — production env values are injected
# at runtime by the orchestrator (e.g. Dokploy, Azure Container Apps).
FROM base AS runner

ENV NODE_ENV=production
WORKDIR /app

# Copy workspace config (needed for pnpm --filter at runtime)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/server/package.json apps/server/
COPY packages/db/package.json packages/db/

# Copy production node_modules. The two Prisma-bearing trees are
# --chown=node:node: `prisma db push` runs at runtime as USER node and
# materializes its schema engine into node_modules, so uid 1000 must own
# them. Done at COPY time (not a RUN chown) to avoid duplicating the layer.
COPY --chown=node:node --from=prod-deps /app/node_modules ./node_modules
COPY --from=prod-deps /app/apps/server/node_modules ./apps/server/node_modules
COPY --chown=node:node --from=prod-deps /app/packages/db/node_modules ./packages/db/node_modules
# web's node_modules: the server bundle dynamically imports apps/web/dist/server,
# whose SSR chunks resolve `react` (left external by the web build) from here.
COPY --from=prod-deps /app/apps/web/node_modules ./apps/web/node_modules

# Copy Prisma schema + config for runtime `prisma db push` (gated on APPLY_SCHEMA)
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/packages/db/prisma.config.ts ./packages/db/prisma.config.ts
# Copy generated Prisma client (built during deps stage)
COPY --from=builder /app/packages/db/prisma/generated ./packages/db/prisma/generated
# Copy prisma CLI (devDependency, not in prod node_modules) so the entrypoint can run `prisma db push`
COPY --chown=node:node --from=builder /app/packages/db/node_modules/.bin/prisma ./packages/db/node_modules/.bin/prisma
COPY --chown=node:node --from=builder /app/packages/db/node_modules/prisma ./packages/db/node_modules/prisma

# Copy built server and web SPA
COPY --from=builder /app/apps/server/dist ./apps/server/dist
COPY --from=builder /app/apps/web/dist ./apps/web/dist

# Copy runtime scripts (entrypoint validates required env vars; backup.sh is
# used by optional Render/Railway cron jobs).
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY scripts/backup.sh scripts/upload-backup-to-s3.mjs ./scripts/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh ./scripts/backup.sh ./scripts/upload-backup-to-s3.mjs

# Strip the global npm CLI from the runtime image. The server runs `node`
# directly (CMD) and the entrypoint invokes the COPY'd prisma binary by path
# (not `npx`), so npm is never used at runtime. node:slim's bundled npm
# vendors its own dependency tree (e.g. picomatch) that Trivy flags as
# fixable HIGH CVEs we cannot patch via pnpm overrides — removing npm
# eliminates that whole class, shrinks the image, and cuts attack surface.
# Build stages keep npm; this only affects the final runner image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Drop privileges. The `node` user (uid 1000) ships in node:24-slim. The
# server only reads /app at runtime; the entrypoint's writes go to /tmp
# (mktemp) and to Postgres over the network, so no chown of /app is needed.
USER node

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 3000

# Dokploy uses the Docker healthcheck for rolling updates.
# Use Node's built-in fetch; node:slim does not ship curl or wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD node -e "const port=process.env.SERVER_PORT||process.env.PORT||3000;fetch('http://localhost:'+port+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Start the server. Schema sync (gated on APPLY_SCHEMA) runs inside the
# ENTRYPOINT before this CMD executes. See scripts/docker-entrypoint.sh.
CMD ["node", "apps/server/dist/index.mjs"]
