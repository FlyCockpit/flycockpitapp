import { CustodyClass, PresenceMode } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  probeRemoteBrowserIdentityCapability,
  REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
  REMOTE_BROWSER_IDENTITY_DB_NAME,
  REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
  REMOTE_BROWSER_IDENTITY_RECORD_KEY,
  REMOTE_BROWSER_IDENTITY_STORE,
  RemoteBrowserIdentityCustodyError,
  RemoteBrowserIdentityCustodyProvider,
  type RemoteBrowserIdentityPersistedRecord,
  type RemoteBrowserIdentityStore,
  remoteBrowserIdentityCustodyClassGuard,
  remoteBrowserIdentityX25519AbsenceGuard,
} from "./remote-browser-identity-custody";

function makeFakeStore(): RemoteBrowserIdentityStore & {
  records: Map<string, RemoteBrowserIdentityPersistedRecord>;
  putShouldFail: boolean;
  openShouldFail: boolean;
} {
  const records = new Map<string, RemoteBrowserIdentityPersistedRecord>();
  return {
    records,
    putShouldFail: false,
    openShouldFail: false,
    async open() {
      if (this.openShouldFail) {
        throw new RemoteBrowserIdentityCustodyError("storage_unavailable", "injected open failure");
      }
      return { fake: true };
    },
    async get(_db, key) {
      return records.get(key);
    },
    async put(_db, key, value) {
      if (this.putShouldFail) {
        throw new RemoteBrowserIdentityCustodyError("storage_unavailable", "injected put failure");
      }
      records.set(key, value);
    },
    async delete(_db, key) {
      records.delete(key);
    },
  };
}

const ORIGIN = "https://app.flycockpit.example";

const SUPPORTED_CAPABILITY = {
  nonExtractableP256: true,
  indexedDb: true,
  supported: true,
} as const;

describe("remote_browser_identity_capability_matrix", () => {
  it("feature-detects non-extractable ECDSA P-256 and IndexedDB", async () => {
    const capability = await probeRemoteBrowserIdentityCapability();
    expect(capability.nonExtractableP256).toBe(true);
    expect(typeof capability.indexedDb).toBe("boolean");
    expect(capability.supported).toBe(capability.nonExtractableP256 && capability.indexedDb);
  });

  it("reports origin_protected custody and unattended presence", () => {
    expect(REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS).toBe(CustodyClass.origin_protected);
    expect(REMOTE_BROWSER_IDENTITY_PRESENCE_MODE).toBe(PresenceMode.unattended);
    expect(REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS).not.toBe(CustodyClass.hardware_or_external);
    expect(REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS).not.toBe(CustodyClass.os_protected);
  });

  it("proves no WebCrypto X25519 ownership/API", () => {
    const guard = remoteBrowserIdentityX25519AbsenceGuard();
    expect(guard.hasX25519Api).toBe(false);
    expect(guard.ownsX25519).toBe(false);
  });

  it("proves custody class is always origin_protected", () => {
    const guard = remoteBrowserIdentityCustodyClassGuard();
    expect(guard.custodyClass).toBe(CustodyClass.origin_protected);
    expect(guard.neverHardware).toBe(true);
    expect(guard.neverOsProtected).toBe(true);
  });

  it("uses the exact IndexedDB database/store/key names", () => {
    expect(REMOTE_BROWSER_IDENTITY_DB_NAME).toBe("flycockpit-remote-identity");
    expect(REMOTE_BROWSER_IDENTITY_STORE).toBe("p256-custody");
    expect(REMOTE_BROWSER_IDENTITY_RECORD_KEY).toBe("current-generation");
  });

  it("reopen fails when no durable record exists (storage/P-256 loss requires re-enrollment)", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
    });
    await expect(provider.reopen()).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("reopen rejects a corrupted extractable handle", async () => {
    const store = makeFakeStore();
    const fakeKey = { extractable: true } as unknown as CryptoKey;
    store.records.set(REMOTE_BROWSER_IDENTITY_RECORD_KEY, {
      keyHandle: fakeKey,
      metadata: {
        custodyClass: CustodyClass.origin_protected,
        presenceMode: PresenceMode.unattended,
        subjectKind: 1 as const,
        generation: 1,
        origin: ORIGIN,
        evidenceDigest: "00",
      },
    });
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
    });
    await expect(provider.reopen()).rejects.toMatchObject({
      code: "corrupted",
    });
  });

  it("reopen rejects an origin-changed handle", async () => {
    const store = makeFakeStore();
    const fakeKey = { extractable: false } as unknown as CryptoKey;
    store.records.set(REMOTE_BROWSER_IDENTITY_RECORD_KEY, {
      keyHandle: fakeKey,
      metadata: {
        custodyClass: CustodyClass.origin_protected,
        presenceMode: PresenceMode.unattended,
        subjectKind: 1 as const,
        generation: 1,
        origin: "https://other-origin.example",
        evidenceDigest: "00",
      },
    });
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
    });
    await expect(provider.reopen()).rejects.toMatchObject({
      code: "origin_changed",
    });
  });

  it("generate fails before server allocation when engine is unsupported", async () => {
    const store = makeFakeStore();
    const original = globalThis.crypto.subtle.generateKey;
    globalThis.crypto.subtle.generateKey = (async () => {
      throw new Error("unsupported");
    }) as typeof crypto.subtle.generateKey;
    try {
      const provider = new RemoteBrowserIdentityCustodyProvider({
        origin: ORIGIN,
        store,
      });
      await expect(provider.generate(1 as const, new Uint8Array([1, 2, 3]))).rejects.toThrow();
      expect(store.records.size).toBe(0);
    } finally {
      globalThis.crypto.subtle.generateKey = original;
    }
  });
});

describe("remote_browser_identity_private_material_guard", () => {
  it("generate persists only the non-extractable handle and public metadata, no private bytes", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const record = await provider.generate(1 as const, new Uint8Array([1, 2, 3]));
    expect(record.keyHandle.extractable).toBe(false);
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    expect(persisted).toBeDefined();
    expect(persisted!.keyHandle.extractable).toBe(false);
    expect(persisted!.metadata.custodyClass).toBe(CustodyClass.origin_protected);
    expect(persisted!.metadata.presenceMode).toBe(PresenceMode.unattended);
    expect(persisted!.metadata).not.toHaveProperty("privateKey");
    expect(persisted!.metadata).not.toHaveProperty("d");
    expect(persisted!.metadata).not.toHaveProperty("pkcs8");
  });

  it("export of the persisted handle fails (non-extractable)", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const record = await provider.generate(1 as const, new Uint8Array([1, 2, 3]));
    await expect(crypto.subtle.exportKey("pkcs8", record.keyHandle)).rejects.toThrow();
  });

  it("sign returns a signature, never private bytes", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await provider.generate(1 as const, new Uint8Array([1, 2, 3]));
    const signature = await provider.signPossessionProof(new Uint8Array(32).fill(0xab));
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBeGreaterThan(0);
    expect(signature.length).toBeLessThanOrEqual(72);
  });

  it("error messages never contain private material", async () => {
    const store = makeFakeStore();
    store.openShouldFail = true;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    try {
      await provider.generate(1 as const, new Uint8Array([1, 2, 3]));
      expect.unreachable("should have thrown");
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toMatch(
        /private\s*key|secret\s*key|pkcs8|\bjwk\b|extractable\s*private/i,
      );
    }
  });
});

describe("remote_browser_identity_atomic_rotation", () => {
  it("rotation publishes only a complete new generation", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const original = await provider.generate(1 as const, new Uint8Array([1]));
    const rotated = await provider.rotate(new Uint8Array([2]));
    expect(rotated.metadata.generation).toBe(original.metadata.generation + 1);
    expect(rotated.keyHandle.extractable).toBe(false);
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    expect(persisted!.metadata.generation).toBe(rotated.metadata.generation);
  });

  it("rotation injects failure at the persistence boundary and exposes only the old generation", async () => {
    const store = makeFakeStore();
    let persistFailed = false;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      onBeforePersist: async () => {
        if (persistFailed) {
          store.putShouldFail = true;
        }
      },
    });
    const original = await provider.generate(1 as const, new Uint8Array([1]));
    persistFailed = true;
    await expect(provider.rotate(new Uint8Array([2]))).rejects.toMatchObject({
      code: "storage_unavailable",
    });
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    expect(persisted!.metadata.generation).toBe(original.metadata.generation);
  });

  it("destroy removes the durable handle", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await provider.generate(1 as const, new Uint8Array([1]));
    expect(store.records.size).toBe(1);
    await provider.destroy();
    expect(store.records.size).toBe(0);
    await expect(provider.reopen()).rejects.toMatchObject({ code: "not_found" });
  });

  it("generate injects failure at the persistence boundary and leaves no record", async () => {
    const store = makeFakeStore();
    store.putShouldFail = true;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await expect(provider.generate(1 as const, new Uint8Array([1]))).rejects.toMatchObject({
      code: "storage_unavailable",
    });
    expect(store.records.size).toBe(0);
  });
});
