#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import type { ImportAcknowledgement } from "@flycockpit/cockpit-protocol";
import { importPolicyJws } from "../packages/api/src/lib/remote-public-policy";
import type { PolicyStore, SqlClient } from "../packages/api/src/lib/remote-public-policy-storage";

/**
 * Operator import command for the signed public service policy. Strict
 * `--flag value` parsing, absolute paths only, machine-JSON output. There is no
 * fallback ring and no unsigned mode: the ring comes exclusively from
 * `REMOTE_PUBLIC_SERVICE_POLICY_JWKS` and the JWS is verified before any write.
 *
 * The core `runImport` is exported and testable with a fake store; the thin
 * `main` wires the env ring, the operator clock, and the Postgres store.
 */
export interface RunImportArgs {
  jwksJson: string;
  compactJws: string;
  now: bigint;
  store: PolicyStore;
}

export async function runImport(args: RunImportArgs): Promise<ImportAcknowledgement> {
  return importPolicyJws(args);
}

async function main(): Promise<void> {
  const [command, ...argv] = process.argv.slice(2);
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("every option requires an explicit value");
    }
    flags.set(key.slice(2), value);
  }
  if (command !== "import") throw new Error("command must be import");

  const jwsPath = flags.get("jws");
  if (!jwsPath) throw new Error("--jws is required");
  if (!isAbsolute(jwsPath)) throw new Error("--jws path must be absolute");

  const jwksJson = process.env.REMOTE_PUBLIC_SERVICE_POLICY_JWKS;
  if (!jwksJson) throw new Error("REMOTE_PUBLIC_SERVICE_POLICY_JWKS is required");

  const compactJws = (await readFile(jwsPath, "utf8")).trim();

  // The outermost operator entry legitimately reads the wall clock once; every
  // downstream check (store logic) is DB-time. `now` is injected from here.
  const now = BigInt(Math.floor(Date.now() / 1000));

  const { default: prisma } = await import("../packages/db/src/index");
  const { PostgresPolicyStore } = await import(
    "../packages/api/src/lib/remote-public-policy-storage"
  );
  const store = new PostgresPolicyStore(prisma as unknown as SqlClient);

  const acknowledgement = await runImport({ jwksJson, compactJws, now, store });
  process.stdout.write(`${JSON.stringify(acknowledgement)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
