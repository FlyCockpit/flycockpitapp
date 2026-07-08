/**
 * First-run onboarding script. Idempotent — safe to re-run.
 *
 * One command takes a fresh clone to a runnable state:
 *   1. Copy .env.example -> .env if .env does not exist.
 *   2. Copy apps/web/.env.example -> apps/web/.env if it does not exist.
 *   3. Copy apps/native/.env.example -> apps/native/.env if it does not exist.
 *   4. Generate BETTER_AUTH_SECRET if it is empty in .env.
 *   5. Start the local Docker services — Postgres + Redis (`pnpm dev:services`,
 *      the canonical root docker-compose.dev.yml).
 *   6. Wait for Postgres and Redis to accept connections.
 *   7. Apply the schema (`pnpm db:push`).
 *   8. Check whether the global portless CLI is available for `pnpm dev`.
 *
 * After this, `pnpm dev` is the only remaining step.
 *
 * Run: `pnpm setup`
 */

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname!, "..");
const ENV_PATH = resolve(ROOT, ".env");
const ENV_EXAMPLE_PATH = resolve(ROOT, ".env.example");
const WEB_ENV_PATH = resolve(ROOT, "apps/web/.env");
const WEB_ENV_EXAMPLE_PATH = resolve(ROOT, "apps/web/.env.example");
const NATIVE_ENV_PATH = resolve(ROOT, "apps/native/.env");
const NATIVE_ENV_EXAMPLE_PATH = resolve(ROOT, "apps/native/.env.example");

function log(msg: string) {
  console.log(`[setup] ${msg}`);
}

function fail(msg: string): never {
  console.error(`[setup] ERROR: ${msg}`);
  process.exit(1);
}

function run(command: string, args: string[]) {
  log(`running: ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: ROOT,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (result.status !== 0) {
    fail(`command failed: ${command} ${args.join(" ")}`);
  }
}

function commandExists(command: string): boolean {
  const result = spawnSync(command, ["--version"], {
    cwd: ROOT,
    stdio: "ignore",
    shell: process.platform === "win32",
  });
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// 1. Copy .env.example -> .env
// ---------------------------------------------------------------------------
function ensureEnvFile() {
  if (existsSync(ENV_PATH)) {
    log(".env already exists — leaving it alone");
    return;
  }
  if (!existsSync(ENV_EXAMPLE_PATH)) {
    fail(".env.example not found at repo root");
  }
  const template = readFileSync(ENV_EXAMPLE_PATH, "utf-8");
  writeFileSync(ENV_PATH, template, "utf-8");
  log("created .env from .env.example");
}

// ---------------------------------------------------------------------------
// 2. Copy apps/web/.env.example -> apps/web/.env
//
// apps/web/.env.example is all-optional (every VITE_ var is commented out),
// so copying it verbatim is a safe, runnable default. Without this file the
// web app still boots, but onboarding docs previously made this a manual step
// the user had to remember — fold it into `pnpm setup` instead.
// ---------------------------------------------------------------------------
function ensureWebEnvFile() {
  if (existsSync(WEB_ENV_PATH)) {
    log("apps/web/.env already exists — leaving it alone");
    return;
  }
  if (!existsSync(WEB_ENV_EXAMPLE_PATH)) {
    fail("apps/web/.env.example not found");
  }
  const template = readFileSync(WEB_ENV_EXAMPLE_PATH, "utf-8");
  writeFileSync(WEB_ENV_PATH, template, "utf-8");
  log("created apps/web/.env from apps/web/.env.example");
}

// ---------------------------------------------------------------------------
// 3. Copy apps/native/.env.example -> apps/native/.env
// ---------------------------------------------------------------------------
function ensureNativeEnvFile() {
  if (existsSync(NATIVE_ENV_PATH)) {
    log("apps/native/.env already exists — leaving it alone");
    return;
  }
  if (!existsSync(NATIVE_ENV_EXAMPLE_PATH)) {
    fail("apps/native/.env.example not found");
  }
  const template = readFileSync(NATIVE_ENV_EXAMPLE_PATH, "utf-8");
  writeFileSync(NATIVE_ENV_PATH, template, "utf-8");
  log("created apps/native/.env from apps/native/.env.example");
}

// ---------------------------------------------------------------------------
// 4. Generate BETTER_AUTH_SECRET if missing/empty
// ---------------------------------------------------------------------------
function ensureBetterAuthSecret() {
  const contents = readFileSync(ENV_PATH, "utf-8");
  const lines = contents.split("\n");
  let touched = false;
  let foundLine = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    // Skip pure comment lines.
    if (line.trim().startsWith("#")) continue;
    const match = line.match(/^(\s*)BETTER_AUTH_SECRET\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    foundLine = true;
    const value = (match[2] ?? "").replace(/^["']|["']$/g, "");
    if (value.length > 0) {
      log("BETTER_AUTH_SECRET already set — leaving it alone");
      return;
    }
    const secret = randomBytes(32).toString("base64");
    lines[i] = `${match[1]}BETTER_AUTH_SECRET=${secret}`;
    touched = true;
    log("generated and wrote a new BETTER_AUTH_SECRET");
    break;
  }

  if (!foundLine) {
    // Append it if the line was missing entirely.
    const secret = randomBytes(32).toString("base64");
    lines.push(`BETTER_AUTH_SECRET=${secret}`);
    touched = true;
    log("BETTER_AUTH_SECRET line was missing — appended a generated value");
  }

  if (touched) {
    writeFileSync(ENV_PATH, lines.join("\n"), "utf-8");
  }
}

// ---------------------------------------------------------------------------
// 5. Start Docker services — Postgres + Redis
//
// Uses `pnpm dev:services` (root docker-compose.dev.yml), the canonical
// local-services command referenced everywhere else in the docs and
// AGENTS.md. Starting Redis here too means queue-backed features (BullMQ
// workers, rate limiting) work out of the box without a remembered extra
// step, and it avoids the dual-compose footgun of `pnpm db:start` (the
// separate packages/db compose, which also binds :5432).
// ---------------------------------------------------------------------------
function startDocker() {
  run("pnpm", ["dev:services"]);
}

// ---------------------------------------------------------------------------
// 6. Wait for Postgres + Redis
// ---------------------------------------------------------------------------
function parseEnvUrl(varName: string, defaultPort: number): { host: string; port: number } | null {
  const contents = readFileSync(ENV_PATH, "utf-8");
  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(new RegExp(`^${varName}\\s*=\\s*(.*)$`));
    if (!match) continue;
    const value = (match[1] ?? "").trim().replace(/^["']|["']$/g, "");
    if (!value) return null;
    try {
      const url = new URL(value);
      const host = url.hostname || "localhost";
      const port = url.port ? Number(url.port) : defaultPort;
      return { host, port };
    } catch {
      return null;
    }
  }
  return null;
}

function tcpProbe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolveProbe) => {
    const socket = connect({ host, port });
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolveProbe(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

async function waitForService(
  label: string,
  envVar: string,
  defaultPort: number,
  containerHint: string,
) {
  const target = parseEnvUrl(envVar, defaultPort);
  if (!target) {
    log(`could not parse ${envVar} — skipping ${label} readiness wait`);
    return;
  }
  log(`waiting for ${label} at ${target.host}:${target.port} (up to 30s)`);
  const deadline = Date.now() + 30_000;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt++;
    const ok = await tcpProbe(target.host, target.port, 1500);
    if (ok) {
      log(`${label} is accepting connections (after ${attempt} attempt(s))`);
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  fail(
    `${label} did not become ready within 30s at ${target.host}:${target.port}. ` +
      `Check Docker is running and \`docker ps\` shows the ${containerHint} container.`,
  );
}

// ---------------------------------------------------------------------------
// 7. Apply schema
// ---------------------------------------------------------------------------
function runMigrations() {
  run("pnpm", ["db:push"]);
}

// ---------------------------------------------------------------------------
// 8. Check global portless CLI
// ---------------------------------------------------------------------------
function checkPortless() {
  if (commandExists("portless")) {
    log("portless is available — `pnpm dev` will use https://flycockpit.localhost");
    return;
  }
  log(
    "portless is not installed. Install it globally with `npm install -g portless` " +
      "before running `pnpm dev`, or use `pnpm dev:raw` as the manual-port fallback.",
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  log("starting first-run setup");
  ensureEnvFile();
  ensureWebEnvFile();
  ensureNativeEnvFile();
  ensureBetterAuthSecret();
  startDocker();
  await waitForService("Postgres", "DATABASE_URL", 5432, "postgres");
  await waitForService("Redis", "REDIS_URL", 6379, "redis");
  runMigrations();
  checkPortless();
  log("Ready. Run `pnpm dev` to start.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
