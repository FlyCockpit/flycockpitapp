#!/usr/bin/env node
// verify_tenant_authority_acceptance_manifest.mjs
//
// Consumes a package-scoped Nextest TestListSummary (`--message-format json`)
// and compares the complete lexicographically sorted `tenant_authority_*`
// manifest to exactly the nine names below. CI-bound executor (remote feature
// enabled):
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
// `tenant_authority_service_acceptance`. Rejects empty input, malformed JSON,
// unknown schema, wrong binary, missing/renamed/extra/duplicate name, or any
// entry with `ignored=true`; it must not filter to the allowlist before
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

function collectPrefixedTests(summary) {
  const suites = summary["rust-suites"];
  if (!suites || typeof suites !== "object" || Array.isArray(suites)) {
    fail("unknown schema: missing rust-suites (expected Nextest TestListSummary)");
  }

  const seen = new Map();
  for (const [suiteKey, suite] of Object.entries(suites)) {
    if (!suite || typeof suite !== "object") {
      fail(`malformed suite entry: ${suiteKey}`);
    }
    const binaryId = suite["binary-id"] ?? suiteKey;
    const testcases = suite.testcases;
    if (!testcases || typeof testcases !== "object" || Array.isArray(testcases)) {
      continue;
    }
    for (const [name, meta] of Object.entries(testcases)) {
      if (typeof name !== "string" || !name.startsWith(PREFIX)) {
        continue;
      }
      if (binaryId !== EXPECTED_BINARY) {
        fail(`wrong binary: expected ${EXPECTED_BINARY} got ${binaryId} for ${name}`);
      }
      if (seen.has(name)) {
        fail(`duplicate name: ${name}`);
      }
      const ignored = meta && typeof meta === "object" && meta.ignored === true;
      seen.set(name, { ignored, binary: binaryId });
    }
  }
  return seen;
}

async function main() {
  const input = await readStream(process.stdin);
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    fail("empty input");
  }

  let summary;
  try {
    summary = JSON.parse(trimmed);
  } catch (e) {
    fail(`malformed JSON: ${e}`);
  }
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) {
    fail("unknown schema: root is not a JSON object");
  }

  const seen = collectPrefixedTests(summary);

  if (seen.size === 0) {
    fail("no tenant_authority_* tests found");
  }

  for (const [name, meta] of seen) {
    if (meta.ignored) {
      fail(`entry ${name} has ignored=true`);
    }
  }

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
