/**
 * Environment health-check. Validates env vars and tests connectivity to
 * Postgres, Redis, and (optionally) SMTP. Does NOT mutate any state.
 *
 * Exit code: 0 if all required checks pass, 1 otherwise.
 *
 * Run: `pnpm doctor`
 */

import { spawnSync } from "node:child_process";
import { connect } from "node:net";
import { resolve } from "node:path";
import { config as loadEnv } from "dotenv";

const ROOT = resolve(import.meta.dirname!, "..");
loadEnv({ path: resolve(ROOT, ".env") });

/**
 * Runs a tiny inline Node script inside a workspace package so we can use
 * dependencies (`@flycockpit/db`, `ioredis`) that live in that package without
 * adding them to the root package.json.
 */
function runInPackage(filter: string, script: string): { ok: boolean; output: string } {
  const result = spawnSync(
    "pnpm",
    ["--silent", "-F", filter, "exec", "node", "--input-type=module", "-e", script],
    {
      cwd: ROOT,
      encoding: "utf-8",
      shell: process.platform === "win32",
    },
  );
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  return { ok: result.status === 0, output };
}

type CheckStatus = "ok" | "fail" | "warn" | "skip";

interface CheckResult {
  name: string;
  status: CheckStatus;
  detail?: string;
  hint?: string;
  required: boolean;
}

const results: CheckResult[] = [];

function record(result: CheckResult) {
  results.push(result);
}

function parseBooleanEnv(name: string): boolean | null {
  const value = process.env[name];
  if (value === undefined) return null;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be exactly "true" or "false" when set.`);
}

function isLocalDatabaseHost(host: string): boolean {
  return (
    host === "localhost" ||
    host === "postgres" ||
    host === "db" ||
    host === "database" ||
    host === "host.docker.internal" ||
    host.startsWith("127.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  );
}

// ---------------------------------------------------------------------------
// 1. Portless CLI (global dev prerequisite)
// ---------------------------------------------------------------------------
function checkPortless() {
  const result = spawnSync("portless", ["--version"], {
    cwd: ROOT,
    encoding: "utf-8",
    shell: process.platform === "win32",
  });
  if (result.status === 0) {
    const version = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    record({
      name: "portless CLI",
      status: "ok",
      detail: version || "installed",
      required: true,
    });
    return;
  }
  record({
    name: "portless CLI",
    status: "warn",
    detail: "portless is not available on PATH",
    hint: "Install it globally with `npm install -g portless`, then run `portless trust` if the CLI asks you to trust its local CA. Use `pnpm dev:raw` only as a fallback.",
    required: false,
  });
}

// ---------------------------------------------------------------------------
// 2. Env validation via @flycockpit/env (zod)
// ---------------------------------------------------------------------------
async function checkEnv() {
  try {
    await import("@flycockpit/env/server");
    record({ name: "env (zod schema)", status: "ok", required: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    record({
      name: "env (zod schema)",
      status: "fail",
      detail: message,
      hint: "Open .env at the repo root and fix the variables called out above.",
      required: true,
    });
  }
}

// ---------------------------------------------------------------------------
// 3. Database connection (uses `pg` from @flycockpit/db's deps via workspace exec)
// ---------------------------------------------------------------------------
function checkDatabase() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    record({
      name: "database",
      status: "fail",
      detail: "DATABASE_URL is not set",
      hint: "Set DATABASE_URL in .env or run `pnpm setup`.",
      required: true,
    });
    return;
  }
  try {
    const host = new URL(url).hostname;
    if (!isLocalDatabaseHost(host)) {
      record({
        name: "database target",
        status: "warn",
        detail: `DATABASE_URL points at non-local host ${host}`,
        hint: "Use read-only tools for production inspection. Destructive schema commands are intended for local Postgres only.",
        required: false,
      });
    }
  } catch {
    // Env validation will report the malformed URL; avoid duplicate noise here.
  }
  // Inline script runs inside @flycockpit/db so it can resolve `pg`.
  const script = `
    import pg from "pg";
    const client = new pg.Client({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 3000 });
    try {
      await client.connect();
      await client.query("SELECT 1");
      console.log("ok");
      await client.end();
      process.exit(0);
    } catch (err) {
      console.error(err && err.message ? err.message : String(err));
      process.exit(1);
    }
  `;
  const { ok, output } = runInPackage("@flycockpit/db", script);
  if (ok) {
    record({ name: "database", status: "ok", detail: "connected", required: true });
  } else {
    record({
      name: "database",
      status: "fail",
      detail: output || "connection failed",
      hint:
        "Is the Postgres container running? Try `pnpm db:start`, then `pnpm db:push`. " +
        "Verify DATABASE_URL host/port/credentials.",
      required: true,
    });
  }
}

// ---------------------------------------------------------------------------
// 4. Redis connection (uses `ioredis` from @flycockpit/queue via workspace exec)
// ---------------------------------------------------------------------------
function checkRedis() {
  const url = process.env.REDIS_URL;
  if (!url) {
    record({
      name: "redis",
      status: "fail",
      detail: "REDIS_URL is not set",
      hint: "Set REDIS_URL in .env (e.g. redis://localhost:6379).",
      required: true,
    });
    return;
  }
  const script = `
    import IORedis from "ioredis";
    const client = new IORedis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      lazyConnect: true,
      connectTimeout: 3000,
    });
    try {
      await client.connect();
      const pong = await client.ping();
      client.disconnect();
      if (pong === "PONG") {
        console.log("ok");
        process.exit(0);
      }
      console.error("unexpected PING reply: " + pong);
      process.exit(1);
    } catch (err) {
      console.error(err && err.message ? err.message : String(err));
      process.exit(1);
    }
  `;
  const { ok, output } = runInPackage("@flycockpit/queue", script);
  if (ok) {
    record({ name: "redis", status: "ok", detail: "PONG", required: true });
  } else {
    record({
      name: "redis",
      status: "fail",
      detail: output || "connection failed",
      hint: "Is Redis running? Try `pnpm dev:services`. Verify REDIS_URL host/port.",
      required: true,
    });
  }
}

// ---------------------------------------------------------------------------
// 5. SMTP connectivity (optional — warn-only)
// ---------------------------------------------------------------------------
function checkSmtp(): Promise<void> {
  return new Promise((done) => {
    const host = process.env.SMTP_HOST;
    const portStr = process.env.SMTP_PORT;
    let signupEnabled = false;
    try {
      signupEnabled = parseBooleanEnv("SIGNUP_ENABLED") ?? false;
    } catch (err) {
      record({
        name: "smtp",
        status: "fail",
        detail: err instanceof Error ? err.message : String(err),
        hint: "Set boolean env flags to exactly true or false in the root .env.",
        required: true,
      });
      done();
      return;
    }
    if (!host || !portStr) {
      if (signupEnabled) {
        record({
          name: "smtp",
          status: "fail",
          detail: "SMTP_HOST/SMTP_PORT not set but SIGNUP_ENABLED=true",
          hint:
            "Email verification is enforced on signup. Set SMTP_HOST/SMTP_PORT/SMTP_FROM " +
            "(and SMTP_USER/SMTP_PASS if your provider requires auth), or set " +
            "SIGNUP_ENABLED=false until SMTP is wired up.",
          required: true,
        });
      } else {
        record({
          name: "smtp",
          status: "skip",
          detail: "SMTP_HOST/SMTP_PORT not set — email is optional",
          required: false,
        });
      }
      done();
      return;
    }
    const port = Number(portStr);
    if (!Number.isFinite(port) || port <= 0) {
      record({
        name: "smtp",
        status: "warn",
        detail: `SMTP_PORT is not a valid number: ${portStr}`,
        required: false,
      });
      done();
      return;
    }
    const socket = connect({ host, port });
    let settled = false;
    const finish = (status: CheckStatus, detail: string, hint?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      record({ name: "smtp", status, detail, hint, required: false });
      done();
    };
    socket.setTimeout(3000);
    socket.once("connect", () => finish("ok", `connected to ${host}:${port}`));
    socket.once("timeout", () =>
      finish(
        "warn",
        `timed out connecting to ${host}:${port}`,
        "Email sends will fail until SMTP is reachable.",
      ),
    );
    socket.once("error", (err) =>
      finish(
        "warn",
        `could not connect to ${host}:${port}: ${err.message}`,
        "Email sends will fail until SMTP is reachable.",
      ),
    );
  });
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
function statusLabel(status: CheckStatus): string {
  switch (status) {
    case "ok":
      return "OK  ";
    case "fail":
      return "FAIL";
    case "warn":
      return "WARN";
    case "skip":
      return "SKIP";
  }
}

function printSummary() {
  console.log("");
  console.log("=== doctor: summary ===");
  for (const r of results) {
    const tag = statusLabel(r.status);
    const detail = r.detail ? ` — ${r.detail}` : "";
    console.log(`[${tag}] ${r.name}${detail}`);
    if (r.hint && (r.status === "fail" || r.status === "warn")) {
      console.log(`        hint: ${r.hint}`);
    }
  }
  console.log("");
}

async function main() {
  checkPortless();
  await checkEnv();
  // Stop further checks if env failed — they would all fail with confusing
  // messages and the user needs to fix env first.
  const envOk = results.find((r) => r.name === "env (zod schema)")?.status === "ok";
  if (envOk) {
    checkDatabase();
    checkRedis();
    await checkSmtp();
  } else {
    record({
      name: "database",
      status: "skip",
      detail: "skipped because env validation failed",
      required: true,
    });
    record({
      name: "redis",
      status: "skip",
      detail: "skipped because env validation failed",
      required: true,
    });
    record({
      name: "smtp",
      status: "skip",
      detail: "skipped because env validation failed",
      required: false,
    });
  }

  printSummary();

  const requiredFailed = results.some(
    (r) => r.required && (r.status === "fail" || r.status === "skip"),
  );
  if (requiredFailed) {
    console.log("doctor: one or more required checks failed.");
    process.exit(1);
  }
  console.log("doctor: all required checks passed.");
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
