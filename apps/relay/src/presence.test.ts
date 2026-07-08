import { describe, expect, it } from "vitest";
import { MemoryPresenceStore } from "./presence";

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
