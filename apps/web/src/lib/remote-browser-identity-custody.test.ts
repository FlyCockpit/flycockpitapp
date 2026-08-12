import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  CustodyClass,
  decodeCustodyEvidence,
  decodePossessionProof,
  encodeCustodyEvidence,
  PresenceMode,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  defaultRemoteBrowserIdentityStore,
  normalizeLowSP1363,
  probeRemoteBrowserIdentityCapability,
  REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
  REMOTE_BROWSER_IDENTITY_DB_NAME,
  REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
  REMOTE_BROWSER_IDENTITY_RECORD_KEY,
  REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY,
  REMOTE_BROWSER_IDENTITY_STORE,
  RemoteBrowserIdentityCustodyError,
  RemoteBrowserIdentityCustodyProvider,
  type RemoteBrowserIdentityPersistedRecord,
  type RemoteBrowserIdentityStore,
  type RemoteBrowserIdentityStoredRecord,
} from "./remote-browser-identity-custody";

const ORIGIN = "https://app.flycockpit.example";

const SUPPORTED_CAPABILITY = {
  nonExtractableP256: true,
  indexedDb: true,
  supported: true,
} as const;

const POLICY = { minCustodyClass: CustodyClass.origin_protected, allowUserPresenceRequired: false };

const FIXED_NOW = 1_723_400_000_000n;

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

interface SigningFixture {
  purpose: number;
  unsignedProof: string;
  message: string;
  digest: string;
  publicKey: { x: string; y: string };
  signatureLowS: string;
  signatureHighS: string;
}

const FIXTURE = JSON.parse(
  readFileSync(
    resolve(
      import.meta.dirname,
      "../../../../packages/cockpit-protocol/fixtures/remote-identity-custody-signing-v1.json",
    ),
    "utf8",
  ),
) as SigningFixture;

function makeFakeStore(): RemoteBrowserIdentityStore & {
  records: Map<string, RemoteBrowserIdentityStoredRecord>;
  putShouldFail: boolean;
  recordPutShouldFail: boolean;
  openShouldFail: boolean;
} {
  const records = new Map<string, RemoteBrowserIdentityStoredRecord>();
  return {
    records,
    putShouldFail: false,
    // Fail ONLY the durable-record put, letting the generation reservation
    // succeed first. Models a real quota exhaustion that strikes after the
    // sequence transaction committed but before the record write.
    recordPutShouldFail: false,
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
      if (this.recordPutShouldFail && key === REMOTE_BROWSER_IDENTITY_RECORD_KEY) {
        throw new RemoteBrowserIdentityCustodyError(
          "storage_unavailable",
          "injected record put failure (quota)",
        );
      }
      records.set(key, value);
    },
    async delete(_db, key) {
      records.delete(key);
    },
    async reserveGeneration(_db) {
      if (this.putShouldFail) {
        throw new RemoteBrowserIdentityCustodyError("storage_unavailable", "injected put failure");
      }
      // Atomic increment: no `await` between the read and the write, so
      // concurrent invocations run to completion one at a time (modeling the
      // single-transaction IndexedDB reservation). The high-water mark is a
      // bigint so it stays exact above Number.MAX_SAFE_INTEGER.
      const seq = records.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
      const current = seq && "highWater" in seq ? seq.highWater : 0n;
      const next = current + 1n;
      records.set(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY, { highWater: next });
      return next;
    },
  };
}

function fakePersistedRecord(
  handleId: Uint8Array,
  options: { extractable: boolean; origin: string },
): RemoteBrowserIdentityPersistedRecord {
  return {
    handleId,
    keyHandle: { extractable: options.extractable } as unknown as CryptoKey,
    publicKeyX: new Uint8Array(32).fill(2),
    publicKeyY: new Uint8Array(32).fill(3),
    metadata: {
      custodyClass: CustodyClass.origin_protected,
      presenceMode: PresenceMode.unattended,
      subjectKind: 1 as const,
      generation: 1n,
      origin: options.origin,
      evidenceDigest: "00",
    },
  };
}

function assembleProof(unsignedProof: Uint8Array, signature: Uint8Array): Uint8Array {
  const proof = new Uint8Array(239);
  proof.set(unsignedProof, 0);
  proof.set(signature, 175);
  return proof;
}

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

  it("uses the exact IndexedDB database/store/key names", () => {
    expect(REMOTE_BROWSER_IDENTITY_DB_NAME).toBe("flycockpit-remote-identity");
    expect(REMOTE_BROWSER_IDENTITY_STORE).toBe("p256-custody");
    expect(REMOTE_BROWSER_IDENTITY_RECORD_KEY).toBe("current-generation");
    expect(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY).toBe("generation-sequence");
    expect(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY).not.toBe(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
  });

  it("reopen rejects a corrupted extractable handle", async () => {
    const store = makeFakeStore();
    const handleId = new Uint8Array(16).fill(7);
    store.records.set(
      REMOTE_BROWSER_IDENTITY_RECORD_KEY,
      fakePersistedRecord(handleId, { extractable: true, origin: ORIGIN }),
    );
    const provider = new RemoteBrowserIdentityCustodyProvider({ origin: ORIGIN, store });
    await expect(provider.reopen(handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reopen rejects an origin-changed handle", async () => {
    const store = makeFakeStore();
    const handleId = new Uint8Array(16).fill(7);
    store.records.set(
      REMOTE_BROWSER_IDENTITY_RECORD_KEY,
      fakePersistedRecord(handleId, {
        extractable: false,
        origin: "https://other-origin.example",
      }),
    );
    const provider = new RemoteBrowserIdentityCustodyProvider({ origin: ORIGIN, store });
    await expect(provider.reopen(handleId)).rejects.toMatchObject({ code: "origin_changed" });
  });

  it("reopen rejects a mismatched handle id with not_found", async () => {
    const store = makeFakeStore();
    const persistedHandle = new Uint8Array(16).fill(7);
    store.records.set(
      REMOTE_BROWSER_IDENTITY_RECORD_KEY,
      fakePersistedRecord(persistedHandle, { extractable: false, origin: ORIGIN }),
    );
    const provider = new RemoteBrowserIdentityCustodyProvider({ origin: ORIGIN, store });
    await expect(provider.reopen(new Uint8Array(16).fill(9))).rejects.toMatchObject({
      code: "not_found",
    });
  });

  it("generate denies a custody class above origin_protected before any storage write", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await expect(
      provider.generate(1, {
        minCustodyClass: CustodyClass.os_protected,
        allowUserPresenceRequired: false,
      }),
    ).rejects.toMatchObject({ code: "policy_denied" });
    expect(store.records.size).toBe(0);
  });
});

describe("remote_browser_identity_private_material_guard", () => {
  it("generate persists only the non-extractable handle, public key, and metadata", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    });
    const generation = await provider.generate(1, POLICY);
    expect(generation.custodyClass).toBe(CustodyClass.origin_protected);
    expect(generation.presenceMode).toBe(PresenceMode.unattended);
    expect(generation.publicKey.x).toHaveLength(32);
    expect(generation.publicKey.y).toHaveLength(32);
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    expect(persisted && "keyHandle" in persisted).toBe(true);
    if (!persisted || !("keyHandle" in persisted)) throw new Error("missing generation record");
    expect(persisted.keyHandle.extractable).toBe(false);
    expect(persisted.metadata.custodyClass).toBe(CustodyClass.origin_protected);
    expect(persisted.metadata).not.toHaveProperty("privateKey");
    expect(persisted.metadata).not.toHaveProperty("d");
    expect(persisted.metadata).not.toHaveProperty("pkcs8");
  });

  it("export of the persisted handle fails (non-extractable)", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await provider.generate(1, POLICY);
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!persisted || !("keyHandle" in persisted)) throw new Error("missing generation record");
    await expect(crypto.subtle.exportKey("pkcs8", persisted.keyHandle)).rejects.toThrow();
  });

  it("sign returns a 64-byte low-S signature, never private bytes", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const generation = await provider.generate(1, POLICY);
    const signature = await provider.signPossessionProof(
      generation.handleId,
      new Uint8Array(237).fill(0xab),
    );
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature).toHaveLength(64);
  });
});

describe("remote_browser_identity_signature_normalization", () => {
  it("accepts every normalized WebCrypto signature over the fixture message as a possession proof", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const generation = await provider.generate(1, POLICY);
    const message = fromHex(FIXTURE.message);
    const unsignedProof = fromHex(FIXTURE.unsignedProof);
    expect(unsignedProof).toHaveLength(175);
    for (let i = 0; i < 96; i++) {
      const signature = await provider.signPossessionProof(generation.handleId, message);
      expect(signature).toHaveLength(64);
      const proof = decodePossessionProof(assembleProof(unsignedProof, signature));
      expect(proof.purpose).toBe(FIXTURE.purpose);
    }
  });

  it("normalizes the pinned high-S fixture signature to a codec- and verify-accepted low-S form", async () => {
    const highS = fromHex(FIXTURE.signatureHighS);
    const lowS = fromHex(FIXTURE.signatureLowS);
    const normalized = normalizeLowSP1363(highS);
    expect(Array.from(normalized)).toEqual(Array.from(lowS));

    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(fromHex(FIXTURE.publicKey.x), 1);
    raw.set(fromHex(FIXTURE.publicKey.y), 33);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      new Uint8Array(normalized),
      fromHex(FIXTURE.message),
    );
    expect(verified).toBe(true);

    const proof = decodePossessionProof(assembleProof(fromHex(FIXTURE.unsignedProof), normalized));
    expect(proof.purpose).toBe(FIXTURE.purpose);
  });

  it("rejects a zero-r signature as corrupted rather than mangling it", () => {
    const zeroR = new Uint8Array(64);
    zeroR[63] = 1;
    expect(() => normalizeLowSP1363(zeroR)).toThrowError(RemoteBrowserIdentityCustodyError);
  });

  it("rejects s >= n as corrupted rather than 'normalizing' it into malformed output", () => {
    // n (the P-256 group order) and n+1, each as a 32-byte big-endian s with a
    // valid r = 1. Since `n - s` for `s >= n` is <= 0, normalizing would emit a
    // malformed/negative scalar; the function MUST reject instead.
    const N_HEX = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const rOne = new Uint8Array(32);
    rOne[31] = 1;

    const sEqualsN = fromHex(N_HEX);
    const atN = new Uint8Array(64);
    atN.set(rOne, 0);
    atN.set(sEqualsN, 32);
    expect(() => normalizeLowSP1363(atN)).toThrowError(RemoteBrowserIdentityCustodyError);
    try {
      normalizeLowSP1363(atN);
      throw new Error("expected throw");
    } catch (error) {
      expect((error as RemoteBrowserIdentityCustodyError).code).toBe("corrupted");
    }

    // s = n + 1
    const sAboveN = fromHex(N_HEX);
    sAboveN[31] = (sAboveN[31]! + 1) & 0xff; // ...2551 -> ...2552, still > n
    const aboveN = new Uint8Array(64);
    aboveN.set(rOne, 0);
    aboveN.set(sAboveN, 32);
    expect(() => normalizeLowSP1363(aboveN)).toThrowError(RemoteBrowserIdentityCustodyError);
  });
});

describe("remote_browser_identity_custody_evidence_clock", () => {
  it("stamps evidence observedAt from the injected clock and round-trips through the codec", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    });
    const generation = await provider.generate(2, POLICY);
    expect(generation.evidence.observedAt).toBe(FIXED_NOW);
    expect(generation.evidence.generation).toBe(1n);
    expect(generation.evidence.custodyClass).toBe(CustodyClass.origin_protected);
    expect(Array.from(generation.evidence.subjectId)).toEqual(Array.from(generation.handleId));
    const roundTrip = decodeCustodyEvidence(encodeCustodyEvidence(generation.evidence));
    expect(roundTrip.observedAt).toBe(FIXED_NOW);
    expect(Array.from(roundTrip.evidenceDigest)).toEqual(
      Array.from(generation.evidence.evidenceDigest),
    );
  });

  it("stamps the injected clock as observedAt on BOTH generate and rotate", async () => {
    let tick = 1_000n;
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => tick,
    });
    const created = await provider.generate(1, POLICY);
    expect(created.evidence.observedAt).toBe(1_000n);
    tick = 2_000n;
    const rotated = await provider.rotate(created.handleId);
    expect(rotated.evidence.observedAt).toBe(2_000n);
  });
});

describe("remote_browser_identity_monotonic_sequence", () => {
  it("advances generation across destroy on a fresh provider and is consumed by rotate", async () => {
    const store = makeFakeStore();
    const providerA = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    });
    const first = await providerA.generate(1, POLICY);
    expect(first.evidence.generation).toBe(1n);
    await providerA.destroy(first.handleId);
    expect(store.records.has(REMOTE_BROWSER_IDENTITY_RECORD_KEY)).toBe(false);
    expect(store.records.has(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY)).toBe(true);

    const providerB = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    });
    const second = await providerB.generate(1, POLICY);
    expect(second.evidence.generation).toBe(2n);
    expect(second.evidence.generation > first.evidence.generation).toBe(true);

    const rotated = await providerB.rotate(second.handleId);
    expect(rotated.evidence.generation).toBe(3n);
    expect(Array.from(rotated.handleId)).toEqual(Array.from(second.handleId));
    const sequence = store.records.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
    expect(sequence && "highWater" in sequence ? sequence.highWater : 0n).toBe(3n);
  });
});

describe("remote_browser_identity_generation_reservation_is_atomic", () => {
  it("hands out distinct generations under concurrent reservation", async () => {
    const store = makeFakeStore();
    const db = await store.open();
    const reserved = await Promise.all([
      store.reserveGeneration(db),
      store.reserveGeneration(db),
      store.reserveGeneration(db),
      store.reserveGeneration(db),
    ]);
    // No duplicates — the read/modify/write is atomic per reservation.
    expect(new Set(reserved).size).toBe(reserved.length);
    expect([...reserved].sort((a, b) => Number(a - b))).toEqual([1n, 2n, 3n, 4n]);
  });

  it("two providers generating concurrently never share a generation", async () => {
    const store = makeFakeStore();
    const options = {
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    };
    const providerA = new RemoteBrowserIdentityCustodyProvider(options);
    const providerB = new RemoteBrowserIdentityCustodyProvider(options);
    const [a, b] = await Promise.all([
      providerA.generate(1, POLICY),
      providerB.generate(1, POLICY),
    ]);
    expect(a.evidence.generation).not.toBe(b.evidence.generation);
    expect(new Set([a.evidence.generation, b.evidence.generation]).size).toBe(2);
  });

  it("leaves exactly ONE usable persisted identity; a superseded provider fails closed", async () => {
    const store = makeFakeStore();
    const options = {
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    };
    const providerA = new RemoteBrowserIdentityCustodyProvider(options);
    const providerB = new RemoteBrowserIdentityCustodyProvider(options);
    const a = await providerA.generate(1, POLICY); // persists record A
    const b = await providerB.generate(1, POLICY); // persists record B, OVERWRITES A
    expect(a.evidence.generation).not.toBe(b.evidence.generation);

    const message = new Uint8Array(237).fill(0xab);
    // B owns the single persisted record and can sign.
    const sigB = await providerB.signPossessionProof(b.handleId, message);
    expect(sigB).toHaveLength(64);
    // A's record was overwritten: A must NOT keep signing a live untracked
    // identity from its cached key — it fails closed. (With a trusted cache, A
    // would sign successfully and this assertion would fail.)
    await expect(providerA.signPossessionProof(a.handleId, message)).rejects.toMatchObject({
      code: "not_found",
    });
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
    const original = await provider.generate(1, POLICY);
    const rotated = await provider.rotate(original.handleId);
    expect(rotated.evidence.generation).toBe(original.evidence.generation + 1n);
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!persisted || !("keyHandle" in persisted)) throw new Error("missing generation record");
    expect(persisted.metadata.generation).toBe(rotated.evidence.generation);
    expect(persisted.keyHandle.extractable).toBe(false);
  });

  it("rotation failure at the persistence boundary exposes only the old generation", async () => {
    const store = makeFakeStore();
    let persistFailed = false;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      onBeforePersist: async () => {
        if (persistFailed) store.putShouldFail = true;
      },
    });
    const original = await provider.generate(1, POLICY);
    persistFailed = true;
    await expect(provider.rotate(original.handleId)).rejects.toMatchObject({
      code: "storage_unavailable",
    });
    const persisted = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!persisted || !("keyHandle" in persisted)) throw new Error("missing generation record");
    expect(persisted.metadata.generation).toBe(original.evidence.generation);
  });

  it("destroy removes the durable handle and reopen then fails not_found", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    const generation = await provider.generate(1, POLICY);
    await provider.destroy(generation.handleId);
    expect(store.records.has(REMOTE_BROWSER_IDENTITY_RECORD_KEY)).toBe(false);
    await expect(provider.reopen(generation.handleId)).rejects.toMatchObject({ code: "not_found" });
  });
});

describe("remote_browser_identity_failure_matrix", () => {
  it("private_mode_open_rejection reports storage_unavailable and writes no record", async () => {
    const store = makeFakeStore();
    store.openShouldFail = true;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await expect(provider.generate(1, POLICY)).rejects.toMatchObject({
      code: "storage_unavailable",
    });
    expect(store.records.size).toBe(0);
  });

  it("quota_exceeded_put_rejection: reservation succeeds, the record put fails, no durable identity is cached", async () => {
    const store = makeFakeStore();
    // De-vacuous: the generation reservation SUCCEEDS (its transaction commits);
    // only the subsequent durable-record put fails, as a real quota exhaustion
    // would. A vacuous variant that also failed the reservation would never
    // exercise the "reserved-but-not-persisted" window.
    store.recordPutShouldFail = true;
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await expect(provider.generate(1, POLICY)).rejects.toMatchObject({
      code: "storage_unavailable",
    });
    // The reservation persisted (the sequence advanced to 1) — proving the put
    // failure struck AFTER a successful reservation, not before it.
    const sequence = store.records.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
    expect(sequence && "highWater" in sequence ? sequence.highWater : 0n).toBe(1n);
    // No partial durable record was written...
    expect(store.records.has(REMOTE_BROWSER_IDENTITY_RECORD_KEY)).toBe(false);
    // ...and no durable identity is cached: a follow-up sign/reopen fails closed
    // rather than serving an identity that was never persisted. (Once the quota
    // clears, a fresh generate advances PAST the reserved-but-unused number.)
    store.recordPutShouldFail = false;
    await expect(
      provider.signPossessionProof(new Uint8Array(16).fill(1), new Uint8Array(237).fill(0xab)),
    ).rejects.toMatchObject({ code: "not_found" });
    const next = await provider.generate(1, POLICY);
    expect(next.evidence.generation).toBe(2n);
  });

  it("storage_cleared_reopen reports not_found", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    await expect(provider.reopen(new Uint8Array(16).fill(1))).rejects.toMatchObject({
      code: "not_found",
    });
    expect(store.records.size).toBe(0);
  });

  it("extractable_only_engine_rejection reports non_extractable_unavailable and writes no record", async () => {
    const store = makeFakeStore();
    const original = globalThis.crypto.subtle.generateKey;
    globalThis.crypto.subtle.generateKey = (async () => ({
      privateKey: { extractable: true } as CryptoKey,
      publicKey: { extractable: true } as CryptoKey,
    })) as unknown as typeof crypto.subtle.generateKey;
    try {
      const provider = new RemoteBrowserIdentityCustodyProvider({
        origin: ORIGIN,
        store,
        capability: SUPPORTED_CAPABILITY,
      });
      await expect(provider.generate(1, POLICY)).rejects.toMatchObject({
        code: "non_extractable_unavailable",
      });
      expect(store.records.size).toBe(0);
    } finally {
      globalThis.crypto.subtle.generateKey = original;
    }
  });

  it("unsupported_engine_rejection fails before server allocation", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: { nonExtractableP256: false, indexedDb: true, supported: false },
    });
    await expect(provider.generate(1, POLICY)).rejects.toMatchObject({
      code: "unsupported_engine",
    });
    expect(store.records.size).toBe(0);
  });
});

describe("remote_browser_identity_raw_input_fail_closed", () => {
  it("denies a structurally invalid policy BEFORE any key allocation or storage write", async () => {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
    });
    // A non-finite / out-of-enum custody class would make `minCustodyClass >
    // class` short-circuit to `false`; a non-boolean presence flag would corrupt
    // the presence gate. Both must fail closed with a typed denial.
    const badPolicies: unknown[] = [
      { minCustodyClass: undefined, allowUserPresenceRequired: false },
      { minCustodyClass: null, allowUserPresenceRequired: false },
      { minCustodyClass: Number.NaN, allowUserPresenceRequired: false },
      { minCustodyClass: 1.5, allowUserPresenceRequired: false },
      { minCustodyClass: 99, allowUserPresenceRequired: false },
      { minCustodyClass: CustodyClass.origin_protected, allowUserPresenceRequired: "no" },
      { minCustodyClass: CustodyClass.origin_protected, allowUserPresenceRequired: undefined },
    ];
    for (const bad of badPolicies) {
      await expect(
        provider.generate(
          1,
          bad as { minCustodyClass: number; allowUserPresenceRequired: boolean },
        ),
      ).rejects.toMatchObject({ code: "policy_denied" });
    }
    // The guard runs before key allocation and any storage write.
    expect(store.records.size).toBe(0);
  });
});

describe("remote_browser_identity_reopen_validates_persisted_metadata", () => {
  async function generatedStore() {
    const store = makeFakeStore();
    const provider = new RemoteBrowserIdentityCustodyProvider({
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    });
    const generation = await provider.generate(1, POLICY);
    return { store, provider, generation };
  }

  function tamper(
    store: ReturnType<typeof makeFakeStore>,
    mutate: (record: RemoteBrowserIdentityPersistedRecord) => RemoteBrowserIdentityPersistedRecord,
  ): void {
    const record = store.records.get(REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!record || !("keyHandle" in record)) throw new Error("missing generation record");
    store.records.set(REMOTE_BROWSER_IDENTITY_RECORD_KEY, mutate(record));
  }

  it("reports a tampered custody-class upgrade as corrupted, not as hardware custody", async () => {
    const { store, provider, generation } = await generatedStore();
    tamper(store, (record) => ({
      ...record,
      metadata: { ...record.metadata, custodyClass: CustodyClass.hardware_or_external },
    }));
    await expect(provider.reopen(generation.handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reports a tampered presence-mode upgrade as corrupted", async () => {
    const { store, provider, generation } = await generatedStore();
    tamper(store, (record) => ({
      ...record,
      metadata: { ...record.metadata, presenceMode: PresenceMode.user_presence_required },
    }));
    await expect(provider.reopen(generation.handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reports a tampered generation counter as corrupted", async () => {
    const { store, provider, generation } = await generatedStore();
    tamper(store, (record) => ({
      ...record,
      // A non-bigint generation (as a legacy JS-number record would carry).
      metadata: { ...record.metadata, generation: 5 as unknown as bigint },
    }));
    await expect(provider.reopen(generation.handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reports a substituted public key (not matching the private handle) as corrupted", async () => {
    const { store, provider, generation } = await generatedStore();
    tamper(store, (record) => ({
      ...record,
      // Swap in a well-formed-but-wrong public key that does not correspond to
      // the stored non-extractable private handle.
      publicKeyX: fromHex(FIXTURE.publicKey.x),
      publicKeyY: fromHex(FIXTURE.publicKey.y),
    }));
    await expect(provider.reopen(generation.handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("accepts an untampered persisted record", async () => {
    const { provider, generation } = await generatedStore();
    const reopened = await provider.reopen(generation.handleId);
    expect(reopened.custodyClass).toBe(CustodyClass.origin_protected);
    expect(reopened.presenceMode).toBe(PresenceMode.unattended);
  });
});

describe("remote_browser_identity_generation_bigint_precision", () => {
  it("advances the counter exactly past Number.MAX_SAFE_INTEGER (no float collision)", async () => {
    const store = makeFakeStore();
    // Seed the high-water mark at MAX_SAFE_INTEGER so the next two reservations
    // land on 2^53 and 2^53+1 — two values a JS number cannot both represent
    // (both round to 2^53), which would collide into a duplicate generation.
    const seed = BigInt(Number.MAX_SAFE_INTEGER);
    store.records.set(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY, { highWater: seed });
    const options = {
      origin: ORIGIN,
      store,
      capability: SUPPORTED_CAPABILITY,
      now: () => FIXED_NOW,
    };
    const first = await new RemoteBrowserIdentityCustodyProvider(options).generate(1, POLICY);
    const second = await new RemoteBrowserIdentityCustodyProvider(options).generate(1, POLICY);
    expect(first.evidence.generation).toBe(seed + 1n);
    expect(second.evidence.generation).toBe(seed + 2n);
    expect(first.evidence.generation).not.toBe(second.evidence.generation);
    // The high-water mark persisted as an exact bigint.
    const sequence = store.records.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
    expect(sequence && "highWater" in sequence ? sequence.highWater : 0n).toBe(seed + 2n);
  });
});

describe("remote_browser_identity_indexeddb_transaction_durability", () => {
  // A fake IDBDatabase whose object-store request SUCCEEDS and whose transaction
  // then ABORTS (e.g. quota) — the exact "request success then rollback" window.
  function abortAfterRequestSuccessDb(): IDBDatabase {
    const tx = {
      oncomplete: null as null | (() => void),
      onabort: null as null | (() => void),
      onerror: null as null | (() => void),
      error: { message: "quota exceeded" } as DOMException,
      objectStore() {
        const scheduleAbort = () => {
          const request: { onsuccess: null | (() => void); onerror: null } = {
            onsuccess: null,
            onerror: null,
          };
          queueMicrotask(() => {
            request.onsuccess?.(); // the request "succeeds"...
            queueMicrotask(() => tx.onabort?.()); // ...then the transaction aborts.
          });
          return request;
        };
        return {
          put: scheduleAbort,
          delete: scheduleAbort,
          get: () => {
            const request = { onsuccess: null as null | (() => void), onerror: null, result: 0 };
            queueMicrotask(() => request.onsuccess?.());
            return request;
          },
        };
      },
    };
    return { transaction: () => tx } as unknown as IDBDatabase;
  }

  it("put rejects when the transaction aborts after the request succeeded", async () => {
    // Resolving on request-success would treat a rolled-back write as durable.
    const db = abortAfterRequestSuccessDb();
    await expect(
      defaultRemoteBrowserIdentityStore.put(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY, {
        highWater: 1n,
      }),
    ).rejects.toMatchObject({ code: "storage_unavailable" });
  });

  it("reserveGeneration rejects when the transaction aborts after the request succeeded", async () => {
    await expect(
      defaultRemoteBrowserIdentityStore.reserveGeneration(abortAfterRequestSuccessDb()),
    ).rejects.toMatchObject({ code: "storage_unavailable" });
  });
});

describe("remote_browser_identity_source_contract", () => {
  it("contains no key-agreement, derivation, alternate-storage, or private-export surface", () => {
    const raw = readFileSync(
      resolve(import.meta.dirname, "remote-browser-identity-custody.ts"),
      "utf8",
    );
    // Strip `//` and block comments before matching, so the scan targets REAL
    // CODE: honest header comments may describe what is deliberately absent
    // (e.g. "no X25519 / ECDH here") while real code reintroduction still fails.
    const source = raw.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    for (const banned of [
      "X25519",
      "ECDH",
      "deriveKey",
      "deriveBits",
      "localStorage",
      "RTCCertificate",
    ]) {
      expect(source.includes(banned)).toBe(false);
    }
    const probeStart = source.indexOf("export async function probeRemoteBrowserIdentityCapability");
    expect(probeStart).toBeGreaterThan(-1);
    const probeEnd = source.indexOf("\n}\n", probeStart);
    expect(probeEnd).toBeGreaterThan(probeStart);
    const occurrences: number[] = [];
    for (let i = source.indexOf("exportKey"); i !== -1; i = source.indexOf("exportKey", i + 1)) {
      occurrences.push(i);
    }
    expect(occurrences.length).toBeGreaterThan(0);
    for (const index of occurrences) {
      expect(index).toBeGreaterThan(probeStart);
      expect(index).toBeLessThan(probeEnd);
    }
  });
});
