#!/usr/bin/env node
/**
 * Verify that the named Vitest JSON reports cover a test-runnable manifest.
 *
 * @see prompts/flycockpitapp/ready/remote-tenant-authority-governance.md
 *
 * The parser recognizes only the pinned Vitest result schema, requires each
 * report to name exactly its manifest file and contain at least one passed
 * assertion, requires every manifest name exactly once across the union, and
 * rejects a missing/extra report, duplicate required name, zero assertion,
 * failure, or any `pending|skipped|todo|disabled` assertion/suite.
 *
 * Usage:
 *   node scripts/verify-vitest-runnable-manifest.mjs <manifest.json> <report1.json> [report2.json ...]
 */

import { readFileSync } from "node:fs";

const NON_TERMINAL_STATUSES = new Set(["pending", "skipped", "todo", "disabled"]);

function loadJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`failed to read ${path}: ${error.message}`);
  }
}

function collectAssertionStatuses(node, into) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const child of node) collectAssertionStatuses(child, into);
    return;
  }
  const status = node.status;
  if (typeof status === "string") {
    into.total += 1;
    if (status === "passed") into.passed += 1;
    else if (status === "failed") into.failed += 1;
    if (NON_TERMINAL_STATUSES.has(status)) {
      into.nonTerminal.push(status);
      into.nonTerminalNodes.push(node);
    }
  }
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) collectAssertionStatuses(child, into);
    } else if (value && typeof value === "object") {
      collectAssertionStatuses(value, into);
    }
  }
}

function collectTestNames(node, names) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const child of node) collectTestNames(child, names);
    return;
  }
  // Vitest JSON `assertionResults` entries carry a `fullName` that combines
  // the suite (describe) path with the test (it) name, space-separated. The
  // required manifest names are describe block names, so we collect both
  // `fullName` (for test-level coverage) and `name` (for suite-level coverage).
  if (typeof node.fullName === "string") names.push(node.fullName);
  if (typeof node.name === "string" && typeof node.status === "string") {
    names.push(node.name);
  }
  for (const key of Object.keys(node)) {
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) collectTestNames(child, names);
    } else if (value && typeof value === "object") {
      collectTestNames(value, names);
    }
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error("usage: verify-vitest-runnable-manifest.mjs <manifest.json> <report...>");
    process.exit(2);
  }
  const [manifestPath, ...reportPaths] = args;
  const manifest = loadJson(manifestPath);
  if (manifest.schemaVersion !== 1) {
    console.error(`manifest ${manifestPath} schemaVersion must be 1`);
    process.exit(1);
  }
  if (!Array.isArray(manifest.files) || !Array.isArray(manifest.requiredTestNames)) {
    console.error(`manifest ${manifestPath} missing files or requiredTestNames`);
    process.exit(1);
  }

  // Reject a missing/extra report: the report count must equal the manifest
  // file count.
  if (reportPaths.length !== manifest.files.length) {
    console.error(
      `report count ${reportPaths.length} does not match manifest file count ${manifest.files.length}`,
    );
    process.exit(1);
  }

  // Each report must name exactly its manifest file. The Vitest JSON schema
  // does not include the source file path directly; we infer it from the
  // `name` field at the top of each test file result. We map report → manifest
  // file by checking that the report's test file path matches one of the
  // manifest files. Vitest JSON reports include a `testResults` array whose
  // entries have a `name` field that is the absolute file path.
  const usedManifestFiles = new Set();
  const allTestNames = [];
  let totalPassed = 0;
  let totalFailed = 0;
  const nonTerminal = [];

  for (const reportPath of reportPaths) {
    const report = loadJson(reportPath);
    // Recognize only the pinned Vitest result schema: top-level
    // `testResults` array (Vitest JSON reporter).
    if (!report || !Array.isArray(report.testResults)) {
      console.error(
        `report ${reportPath} does not match the pinned Vitest JSON schema (missing testResults)`,
      );
      process.exit(1);
    }

    // Each report must name exactly its manifest file. Vitest testResults
    // entries have a `name` field that is the test file path. We accept
    // reports whose testResults paths end with one of the manifest files.
    const reportFilePaths = report.testResults.map((entry) => entry.name).filter(Boolean);
    const matchedManifestFile = manifest.files.find((file) =>
      reportFilePaths.some((p) => p.endsWith(file) || p.endsWith(file.replace(/^\.\//, ""))),
    );
    if (!matchedManifestFile) {
      console.error(
        `report ${reportPath} does not name any manifest file; report paths: ${reportFilePaths.join(", ")}`,
      );
      process.exit(1);
    }
    if (usedManifestFiles.has(matchedManifestFile)) {
      console.error(`duplicate report for manifest file ${matchedManifestFile}`);
      process.exit(1);
    }
    usedManifestFiles.add(matchedManifestFile);

    // Each report must contain at least one passed assertion.
    const statuses = { total: 0, passed: 0, failed: 0, nonTerminal: [], nonTerminalNodes: [] };
    collectAssertionStatuses(report, statuses);
    if (statuses.total === 0) {
      console.error(`report ${reportPath} contains zero assertions`);
      process.exit(1);
    }
    if (statuses.passed === 0) {
      console.error(`report ${reportPath} contains no passed assertion`);
      process.exit(1);
    }
    if (statuses.failed > 0) {
      console.error(`report ${reportPath} contains ${statuses.failed} failed assertion(s)`);
      process.exit(1);
    }
    if (statuses.nonTerminal.length > 0) {
      console.error(
        `report ${reportPath} contains non-terminal assertion/suite status: ${statuses.nonTerminal.join(", ")}`,
      );
      process.exit(1);
    }
    totalPassed += statuses.passed;
    totalFailed += statuses.failed;
    nonTerminal.push(...statuses.nonTerminal);

    collectTestNames(report, allTestNames);
  }

  // Every manifest file must be covered by exactly one report.
  for (const file of manifest.files) {
    if (!usedManifestFiles.has(file)) {
      console.error(`missing report for manifest file ${file}`);
      process.exit(1);
    }
  }

  // Require every manifest name exactly once across the union. The manifest
  // names are describe block names. Vitest JSON `fullName` is
  // `"<describe> <it>"` (space-separated), so a required name matches when a
  // collected fullName starts with `<required> ` or a collected name equals
  // `<required>`. We count the number of distinct tests under each required
  // describe; exactly one test per required name is expected.
  const requiredCounts = new Map();
  for (const required of manifest.requiredTestNames) {
    let count = 0;
    for (const name of allTestNames) {
      if (name === required || name.startsWith(`${required} `) || name.endsWith(` > ${required}`))
        count += 1;
    }
    requiredCounts.set(required, count);
  }
  const missing = [];
  const duplicates = [];
  for (const [required, count] of requiredCounts) {
    if (count === 0) missing.push(required);
    if (count > 1) duplicates.push(`${required} (${count})`);
  }
  if (missing.length > 0) {
    console.error(`missing required test names: ${missing.join(", ")}`);
    process.exit(1);
  }
  if (duplicates.length > 0) {
    console.error(`duplicate required test names: ${duplicates.join(", ")}`);
    process.exit(1);
  }

  console.error(
    `ok: ${manifest.requiredTestNames.length} required names across ${reportPaths.length} reports (${totalPassed} passed, ${totalFailed} failed, ${nonTerminal.length} non-terminal)`,
  );
}

main();
