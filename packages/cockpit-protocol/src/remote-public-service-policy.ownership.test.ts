import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
// packages/cockpit-protocol/src -> repo root
const repoRoot = join(here, "..", "..", "..");

// Files whose content legitimately references these names (the foundation
// module itself and its colocated tests) are excluded from the duplicate scan.
const EXCLUDED_BASENAMES = new Set([
  "remote-public-service-policy.ts",
  "remote-public-service-policy.test.ts",
  "remote-public-service-policy.ownership.test.ts",
]);

/**
 * Structural detector: returns a reason when `source` *defines* a
 * foundation-owned capability enum, transport-bit constant, or the
 * permission-ceiling binary layout. Usages (calls, imports, type references)
 * are deliberately not matched.
 */
function scanForGuardedDefinition(source: string): string | null {
  if (
    /(?:const|enum|type)\s+RemoteProjectCapabilityV1\b/.test(source) ||
    /(?:const|enum|type)\s+RemoteAttachmentCapabilityV1\b/.test(source)
  ) {
    return "capability enum definition";
  }
  if (/\bTRANSPORT_BIT_WEBRTC\s*=/.test(source)) return "transport-bit assignment";
  if (/function\s+encodePermissionCeiling\b/.test(source)) return "ceiling binary layout";
  return null;
}

function collectSourceFiles(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist" || entry === "generated") continue;
    const full = join(dir, entry);
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      continue;
    }
    if (isDir) {
      collectSourceFiles(full, out);
    } else if ((entry.endsWith(".ts") || entry.endsWith(".tsx")) && full.includes("/src/")) {
      out.push(full);
    }
  }
}

describe("remote public service policy ownership guard", () => {
  it("detects planted duplicate definitions (non-vacuity proof)", () => {
    expect(
      scanForGuardedDefinition(
        "export const RemoteProjectCapabilityV1 = { ProjectRead: 1 } as const;",
      ),
    ).not.toBeNull();
    expect(
      scanForGuardedDefinition("const RemoteAttachmentCapabilityV1 = { AttachmentRead: 1 };"),
    ).not.toBeNull();
    expect(scanForGuardedDefinition("export const TRANSPORT_BIT_WEBRTC = 0x01;")).not.toBeNull();
    expect(
      scanForGuardedDefinition("export function encodePermissionCeiling(c: unknown) { return c; }"),
    ).not.toBeNull();
    // Usages must NOT be flagged.
    expect(scanForGuardedDefinition("const x = encodePermissionCeiling(ceiling);")).toBeNull();
    expect(
      scanForGuardedDefinition(
        "import { RemoteProjectCapabilityV1 } from '@flycockpit/cockpit-protocol';",
      ),
    ).toBeNull();
  });

  it("finds no duplicate definitions across packages/*/src and apps/*/src", () => {
    const files: string[] = [];
    collectSourceFiles(join(repoRoot, "packages"), files);
    collectSourceFiles(join(repoRoot, "apps"), files);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const base = file.slice(file.lastIndexOf("/") + 1);
      if (EXCLUDED_BASENAMES.has(base)) continue;
      const content = readFileSync(file, "utf8");
      const reason = scanForGuardedDefinition(content);
      expect(reason, `duplicate ${reason} in ${file}`).toBeNull();
    }
  });

  it("wires the foundation definitions into the package barrel", () => {
    const index = readFileSync(join(here, "index.ts"), "utf8");
    expect(index).toContain('export * from "./remote-public-service-policy"');
  });
});
