import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

async function sourceFiles(root: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...(await sourceFiles(path)));
    else if (/\.(?:ts|tsx)$/.test(entry.name) && !entry.name.endsWith(".test.ts"))
      result.push(path);
  }
  return result;
}

describe("remote_authority_static_ownership", () => {
  it("keeps authority code independent of legacy secrets and enterprise providers", async () => {
    const apiRoot = new URL("..", import.meta.url).pathname,
      serverRoot = new URL("../../../../apps/server/src", import.meta.url).pathname,
      keyScript = new URL("../../../../scripts/remote-authority-keys.ts", import.meta.url).pathname,
      files = [
        ...(await sourceFiles(apiRoot)),
        ...(await sourceFiles(serverRoot)),
        keyScript,
      ].filter((path) => path.includes("remote-authority"));
    expect(files.length).toBeGreaterThan(0);
    for (const path of files) {
      const source = await readFile(path, "utf8");
      expect(source, path).not.toMatch(/BETTER_AUTH_SECRET/);
      expect(source, path).not.toMatch(/createRelayKeySet/);
      expect(source, path).not.toMatch(/from\s+["'][^"']*enterprise[^"']*["']/);
      expect(source, path).not.toMatch(/console\.(?:log|info|warn|error)\s*\(/);
    }
  });
});
