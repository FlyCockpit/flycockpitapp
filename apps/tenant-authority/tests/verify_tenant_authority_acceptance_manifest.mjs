#!/usr/bin/env node
// verify_tenant_authority_acceptance_manifest.mjs
//
// Consumes a package-scoped Nextest list stream and compares the complete
// lexicographically sorted `tenant_authority_*` manifest to exactly the nine
// names below. CI-bound executor (remote feature enabled):
//
//   bash scripts/check-tenant-authority-acceptance-manifest.sh
//
// Manual pipe (same check):
//
//   cargo nextest list -p tenant-authority --features remote \
//     --message-format json \
//     | node apps/tenant-authority/tests/verify_tenant_authority_acceptance_manifest.mjs
//
// Within that stream, every `tenant_authority_*` name must come from binary
// `tenant_authority_service_acceptance`. Rejects an empty stream,
// malformed/unknown schema, wrong binary, missing/renamed/extra/duplicate name,
// or any entry with `ignored=true`; it must not filter to the allowlist before
// comparison.

const EXACT_NINE = [
  "tenant_authority_fixed_preparation_and_identity_rotation",
  "tenant_authority_offline_bootstrap_contract",
  "tenant_authority_pkcs11_conformance",
  "tenant_authority_service_idempotency_and_replica_state",
  "tenant_authority_service_identity_status_contract",
  "tenant_authority_service_only_closed_handlers",
  "tenant_authority_service_submit_credential_insufficient",
  "tenant_authority_service_webauthn_registry",
  "tenant_authority_workspace_and_config_contract",
];

const EXPECTED_BINARY = "tenant_authority_service_acceptance";
const PREFIX = "tenant_authority_";

function fail(msg) {
  process.stderr.write(`verify_tenant_authority_acceptance_manifest: ${msg}\n`);
  process.exit(1);
}

function readStream(stream) {
  return new Promise((resolve, reject) => {
    let data = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      data += chunk;
    });
    stream.on("end", () => resolve(data));
    stream.on("error", reject);
  });
}

async function main() {
  const input = await readStream(process.stdin);
  if (input.length === 0) {
    fail("empty stream");
  }
  const lines = input.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    fail("no lines in stream");
  }

  // First non-empty line must be the Nextest schema/version object.
  let first;
  try {
    first = JSON.parse(lines[0]);
  } catch (e) {
    fail(`malformed JSON on first line: ${e}`);
  }
  if (
    first.type !== "version" &&
    first["schema-version"] === undefined &&
    first.version === undefined
  ) {
    if (!Array.isArray(first.tests) && first.type !== "test") {
      fail("unknown schema: first line is not a Nextest version event");
    }
  }

  // Collect all test entries with the prefix from the exact binary.
  const seen = new Map(); // name -> {ignored, binary}
  let schemaOk = false;
  for (const line of lines) {
    let ev;
    try {
      ev = JSON.parse(line);
    } catch (e) {
      fail(`malformed JSON line: ${e}`);
    }
    if (ev.type === "version" || ev["schema-version"] !== undefined) {
      schemaOk = true;
      continue;
    }
    if (ev.type !== "test") {
      continue;
    }
    schemaOk = true;
    const name = ev.name;
    if (typeof name !== "string") {
      fail("test entry missing string name");
    }
    if (!name.startsWith(PREFIX)) {
      continue;
    }
    const binary = ev.binary || ev["binary-id"] || ev.binary_id;
    if (binary !== EXPECTED_BINARY) {
      fail(`wrong binary: expected ${EXPECTED_BINARY} got ${binary} for ${name}`);
    }
    if (seen.has(name)) {
      fail(`duplicate name: ${name}`);
    }
    seen.set(name, { ignored: ev.ignored === true, binary });
  }

  if (!schemaOk) {
    fail("no recognized Nextest schema event found");
  }

  if (seen.size === 0) {
    fail("no tenant_authority_* tests found");
  }

  // Reject any entry with ignored=true.
  for (const [name, meta] of seen) {
    if (meta.ignored) {
      fail(`entry ${name} has ignored=true`);
    }
  }

  // Complete sorted manifest.
  const sorted = [...seen.keys()].sort();
  const expected = [...EXACT_NINE].sort();

  if (sorted.length !== expected.length) {
    const missing = expected.filter((n) => !sorted.includes(n));
    const extra = sorted.filter((n) => !expected.includes(n));
    const parts = [];
    if (missing.length) parts.push(`missing: ${missing.join(", ")}`);
    if (extra.length) parts.push(`extra: ${extra.join(", ")}`);
    fail(`manifest mismatch (${parts.join("; ")})`);
  }
  for (let i = 0; i < expected.length; i++) {
    if (sorted[i] !== expected[i]) {
      fail(`manifest mismatch at position ${i}: expected ${expected[i]} got ${sorted[i]}`);
    }
  }

  process.stdout.write(
    `verify_tenant_authority_acceptance_manifest: OK (${sorted.length} tests)\n`,
  );
}

main().catch((e) => fail(String(e)));
