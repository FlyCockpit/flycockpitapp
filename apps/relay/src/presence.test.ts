import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { MemoryPresenceStore } from "./presence";

// Split tokens so retirement greps do not treat this suite as a live reference.
const retiredRustRelayMember = ["apps", "relay-rs"].join("/");
const retiredRustRelayPackage = ["flycockpit", "relay"].join("-");
const retiredExternalBinaryEnv = ["RELAY_UNDER", "TEST_BIN"].join("_");

describe("MemoryPresenceStore", () => {
  it("expires stale daemon leases", async () => {
    const store = new MemoryPresenceStore();
    await store.setDaemonLease(
      {
        instanceId: "instance-1",
        relayId: "relay-1",
        connectionId: "conn-1",
        expiresAt: Date.now() - 1,
      },
      30_000,
    );

    await expect(store.getDaemonLease("instance-1")).resolves.toBeNull();
  });

  it("does not let an old connection delete the newest lease", async () => {
    const store = new MemoryPresenceStore();
    await store.setDaemonLease(
      {
        instanceId: "instance-1",
        relayId: "relay-1",
        connectionId: "conn-new",
        expiresAt: Date.now() + 30_000,
      },
      30_000,
    );

    await store.deleteDaemonLease("instance-1", "conn-old");

    await expect(store.getDaemonLease("instance-1")).resolves.toMatchObject({
      connectionId: "conn-new",
    });
  });
});

describe("retire rust websocket relay presence", () => {
  it("rejects Rust relay package path and external-binary harness markers", () => {
    const workspaceRoot = join(import.meta.dirname, "../../..");
    const relaySrc = join(workspaceRoot, "apps/relay/src");

    const member = join(workspaceRoot, retiredRustRelayMember);
    if (existsSync(member)) {
      // Empty tombstone only: package source must already be wiped. Prefer full rm -rf.
      const cargoPath = join(member, "Cargo.toml");
      const mainPath = join(member, "src", "main.rs");
      const cargoText = existsSync(cargoPath) ? readFileSync(cargoPath, "utf8").trim() : "";
      const mainText = existsSync(mainPath) ? readFileSync(mainPath, "utf8").trim() : "";
      expect(cargoText).toBe("");
      expect(mainText).toBe("");
    }

    const fixture = readFileSync(join(relaySrc, "conformance-fixture.ts"), "utf8");
    const serverTest = readFileSync(join(relaySrc, "server.test.ts"), "utf8");
    const presenceSource = readFileSync(join(relaySrc, "presence.ts"), "utf8");

    for (const source of [fixture, serverTest, presenceSource]) {
      expect(source).not.toContain(retiredExternalBinaryEnv);
      expect(source).not.toContain(retiredRustRelayMember);
      expect(source).not.toContain(retiredRustRelayPackage);
    }

    // Presence stays an in-process TypeScript concern; no subprocess launch surface.
    expect(fixture).toContain("createRelayServer");
    expect(fixture).not.toMatch(/ChildProcess|startSubprocessRelay/);
  });

  it("keeps TypeScript bridge production sources free of Rust server binary selection", () => {
    const relaySrc = join(import.meta.dirname);
    const productionFiles = listTsFiles(relaySrc).filter(
      (file) => !file.endsWith(".test.ts") && !file.endsWith("conformance-fixture.ts"),
    );
    // Re-check the harness explicitly; production modules must stay clean.
    const fixture = readFileSync(join(relaySrc, "conformance-fixture.ts"), "utf8");
    expect(fixture).not.toContain(retiredExternalBinaryEnv);
    expect(fixture).not.toContain(retiredRustRelayMember);

    expect(productionFiles.length).toBeGreaterThan(0);
    for (const file of productionFiles) {
      const text = readFileSync(file, "utf8");
      expect(text).not.toContain(retiredExternalBinaryEnv);
      expect(text).not.toContain(retiredRustRelayMember);
    }
  });
});

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      out.push(...listTsFiles(path));
      continue;
    }
    if (name.endsWith(".ts")) out.push(path);
  }
  return out;
}
