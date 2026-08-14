import {
  canonicalPolicyJson,
  initialServiceVersion1Policy,
  payloadDigestHex,
  type RemoteConnectionPolicyV1,
  type RemotePublicServicePolicyV1,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { runImport } from "../../../../scripts/remote-public-policy";
import { importPolicyJws } from "./remote-public-policy";
import type {
  InsertScheduledPolicyArgs,
  PolicyStore,
  StoredPolicyRow,
} from "./remote-public-policy-storage";

// ---------------------------------------------------------------------------
// ES256 signing (low-S) — same normalization loop as the fixture generator.
// ---------------------------------------------------------------------------

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;
const toBig = (b: Uint8Array) => b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
const toBytes = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  let n = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};
const te = new TextEncoder();
const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

type Role = "current" | "previous" | "next";
interface TestKey {
  kid: string;
  role: Role;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  x: string;
  y: string;
}

async function makeKey(kid: string, role: Role): Promise<TestKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    kid,
    role,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    x: jwk.x!,
    y: jwk.y!,
  };
}

async function signLowS(key: TestKey, message: Uint8Array): Promise<Uint8Array> {
  for (;;) {
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, message),
    );
    const r = raw.slice(0, 32);
    const s = toBig(raw.slice(32, 64));
    if (toBig(r) === 0n || s === 0n || toBig(r) >= N) continue;
    const sLow = s > HALF_N ? N - s : s;
    if (sLow === 0n) continue;
    const out = new Uint8Array(64);
    out.set(r, 0);
    out.set(toBytes(sLow), 32);
    if (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key.publicKey, out, message))
      return out;
  }
}

function ringJson(...keys: TestKey[]): string {
  return JSON.stringify({
    keys: keys.map((k) => ({
      kid: k.kid,
      kty: "EC",
      crv: "P-256",
      x: k.x,
      y: k.y,
      use: "sig",
      key_ops: ["verify"],
      flycockpit_role: k.role,
    })),
  });
}

const POLICY_ID = b64url(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));

function envelope(over: Partial<RemotePublicServicePolicyV1>): RemotePublicServicePolicyV1 {
  return {
    schemaVersion: 1,
    policyId: POLICY_ID,
    serviceVersion: "1",
    previousDigest: null,
    issuedAt: "1000000",
    notBefore: "1000000",
    changeClass: "narrowing_or_equal",
    policy: initialServiceVersion1Policy(),
    ...over,
  };
}

async function sign(key: TestKey, env: RemotePublicServicePolicyV1): Promise<string> {
  const headerB64 = b64url(
    te.encode(
      JSON.stringify({ alg: "ES256", kid: key.kid, typ: "flycockpit-public-remote-policy+jws" }),
    ),
  );
  const payloadB64 = b64url(te.encode(canonicalPolicyJson(env)));
  const sig = await signLowS(key, te.encode(`${headerB64}.${payloadB64}`));
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

function narrowedPolicy(): RemoteConnectionPolicyV1 {
  return {
    ...initialServiceVersion1Policy(),
    minimumClientCustody: "hardware",
    allowedTurnRegions: ["europe", "north_america"],
    metadataRetentionDays: "14",
  };
}

// ---------------------------------------------------------------------------
// In-memory PolicyStore — real for the three import methods, unused elsewhere.
// ---------------------------------------------------------------------------

interface FakeStore extends PolicyStore {
  rows: Map<string, StoredPolicyRow>;
  insertCount: number;
}

function makeStore(): FakeStore {
  const rows = new Map<string, StoredPolicyRow>();
  const unused = (name: string) => (): never => {
    throw new Error(`unexpected ${name} during import`);
  };
  const store: FakeStore = {
    rows,
    insertCount: 0,
    async loadPolicyTip() {
      let tip: StoredPolicyRow | null = null;
      for (const row of rows.values())
        if (!tip || BigInt(row.serviceVersion) > BigInt(tip.serviceVersion)) tip = row;
      return tip;
    },
    async loadPolicyByServiceVersion(serviceVersion: string) {
      return rows.get(serviceVersion) ?? null;
    },
    async insertScheduledPolicy(args: InsertScheduledPolicyArgs) {
      store.insertCount += 1;
      const row: StoredPolicyRow = {
        policyId: args.policyId,
        serviceVersion: args.serviceVersion,
        changeClass: args.changeClass,
        compactJws: args.compactJws,
        payloadDigest: args.payloadDigest,
        previousDigest: args.previousDigest,
        notBefore: args.notBefore,
        state: "scheduled",
      };
      rows.set(args.serviceVersion, row);
      return row;
    },
    seedConsumerGroups: unused("seedConsumerGroups"),
    loadRequiredConsumerIds: unused("loadRequiredConsumerIds"),
    registerReplicaLease: unused("registerReplicaLease"),
    renewReplicaLease: unused("renewReplicaLease"),
    drainReplicaLease: unused("drainReplicaLease"),
    removeReplicaLease: unused("removeReplicaLease"),
    markExpiredLeasesStale: unused("markExpiredLeasesStale"),
    reapStaleLease: unused("reapStaleLease"),
    recordGroupAck: unused("recordGroupAck"),
    loadActivatableRows: unused("loadActivatableRows"),
    activateNarrowingRow: unused("activateNarrowingRow"),
    prepareWideningRow: unused("prepareWideningRow"),
    markPolicyActive: unused("markPolicyActive"),
    markConvergenceFailed: unused("markConvergenceFailed"),
    advanceWideningPointer: unused("advanceWideningPointer"),
    markScheduledFailed: unused("markScheduledFailed"),
  };
  return store;
}

const NOW = 1_000_000n;

describe("importPolicyJws", () => {
  it("accepts a valid current-key v1 and returns a decimal-string acknowledgement", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const env = envelope({});
    const compactJws = await sign(current, env);
    const ack = await importPolicyJws({
      compactJws,
      jwksJson: ringJson(current),
      now: NOW,
      store,
    });
    expect(ack).toEqual({
      policyId: POLICY_ID,
      serviceVersion: "1",
      state: "scheduled",
      notBefore: "1000000",
      digest: await payloadDigestHex(env),
    });
    expect(ack.serviceVersion).toBe("1");
    expect(store.insertCount).toBe(1);
  });

  it("is idempotent for a byte-identical retry (no second row)", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const env = envelope({});
    const compactJws = await sign(current, env);
    const jwksJson = ringJson(current);
    const first = await importPolicyJws({ compactJws, jwksJson, now: NOW, store });
    const second = await importPolicyJws({ compactJws, jwksJson, now: NOW, store });
    expect(second).toEqual(first);
    expect(store.insertCount).toBe(1);
  });

  it("rejects a same-version submission with divergent bytes", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const jwksJson = ringJson(current);
    await importPolicyJws({
      compactJws: await sign(current, envelope({})),
      jwksJson,
      now: NOW,
      store,
    });
    const divergent = envelope({ notBefore: "1000030" });
    await expect(
      importPolicyJws({ compactJws: await sign(current, divergent), jwksJson, now: NOW, store }),
    ).rejects.toThrow(/divergent bytes/);
    expect(store.insertCount).toBe(1);
  });

  it("fails closed on a tampered payload with no row written", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const good = await sign(current, envelope({}));
    const [h, , s] = good.split(".");
    const otherPayload = b64url(te.encode(canonicalPolicyJson(envelope({ notBefore: "1000005" }))));
    await expect(
      importPolicyJws({
        compactJws: `${h}.${otherPayload}.${s}`,
        jwksJson: ringJson(current),
        now: NOW,
        store,
      }),
    ).rejects.toThrow();
    expect(store.insertCount).toBe(0);
  });

  it("fails closed on a next-key signature under import", async () => {
    const current = await makeKey("k-current", "current");
    const next = await makeKey("k-next", "next");
    const store = makeStore();
    await expect(
      importPolicyJws({
        compactJws: await sign(next, envelope({})),
        jwksJson: ringJson(current, next),
        now: NOW,
        store,
      }),
    ).rejects.toThrow();
    expect(store.insertCount).toBe(0);
  });

  it("fails closed on an unknown kid", async () => {
    const current = await makeKey("k-current", "current");
    const stray = await makeKey("k-stray", "current");
    const store = makeStore();
    await expect(
      importPolicyJws({
        compactJws: await sign(stray, envelope({})),
        jwksJson: ringJson(current),
        now: NOW,
        store,
      }),
    ).rejects.toThrow();
    expect(store.insertCount).toBe(0);
  });

  it("rejects a future issuedAt beyond the skew window", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    await expect(
      importPolicyJws({
        compactJws: await sign(current, envelope({ issuedAt: "2000000", notBefore: "2000000" })),
        jwksJson: ringJson(current),
        now: NOW,
        store,
      }),
    ).rejects.toThrow();
    expect(store.insertCount).toBe(0);
  });

  it("rejects a notBefore beyond the 30-day window", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    await expect(
      importPolicyJws({
        compactJws: await sign(
          current,
          envelope({ notBefore: (1_000_000 + 40 * 86_400).toString() }),
        ),
        jwksJson: ringJson(current),
        now: NOW,
        store,
      }),
    ).rejects.toThrow();
    expect(store.insertCount).toBe(0);
  });

  async function seedV1(current: TestKey, store: FakeStore): Promise<string> {
    const env = envelope({});
    await importPolicyJws({
      compactJws: await sign(current, env),
      jwksJson: ringJson(current),
      now: NOW,
      store,
    });
    return payloadDigestHex(env);
  }

  it("enforces the previousDigest chain and the version increment", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const v1Digest = await seedV1(current, store);
    const jwksJson = ringJson(current);

    // v2 with the correct predecessor digest + class succeeds.
    const goodV2 = envelope({
      serviceVersion: "2",
      previousDigest: v1Digest,
      changeClass: "narrowing_or_equal",
      policy: narrowedPolicy(),
    });
    const ack = await importPolicyJws({
      compactJws: await sign(current, goodV2),
      jwksJson,
      now: NOW,
      store,
    });
    expect(ack.serviceVersion).toBe("2");

    // v3 without its v2? — actually skip to v4 to prove the missing predecessor.
    const skipped = envelope({
      serviceVersion: "4",
      previousDigest: v1Digest,
      changeClass: "narrowing_or_equal",
      policy: narrowedPolicy(),
    });
    await expect(
      importPolicyJws({ compactJws: await sign(current, skipped), jwksJson, now: NOW, store }),
    ).rejects.toThrow(/predecessor/);

    // Wrong previousDigest for v3.
    const wrongPrev = envelope({
      serviceVersion: "3",
      previousDigest: "0".repeat(64),
      changeClass: "widening",
      policy: initialServiceVersion1Policy(),
    });
    await expect(
      importPolicyJws({ compactJws: await sign(current, wrongPrev), jwksJson, now: NOW, store }),
    ).rejects.toThrow(/previousDigest/);
  });

  it("rejects a mixed change and a claimed-class mismatch", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const v1Digest = await seedV1(current, store);
    const jwksJson = ringJson(current);

    const mixedPolicy: RemoteConnectionPolicyV1 = {
      ...initialServiceVersion1Policy(),
      minimumClientCustody: "hardware", // narrowed
      limits: { ...initialServiceVersion1Policy().limits, registeredDaemons: "20" }, // widened
    };
    await expect(
      importPolicyJws({
        compactJws: await sign(
          current,
          envelope({
            serviceVersion: "2",
            previousDigest: v1Digest,
            changeClass: "widening",
            policy: mixedPolicy,
          }),
        ),
        jwksJson,
        now: NOW,
        store,
      }),
    ).rejects.toThrow(/mixed/);

    // Pure narrowing declared as widening → class mismatch.
    await expect(
      importPolicyJws({
        compactJws: await sign(
          current,
          envelope({
            serviceVersion: "2",
            previousDigest: v1Digest,
            changeClass: "widening",
            policy: narrowedPolicy(),
          }),
        ),
        jwksJson,
        now: NOW,
        store,
      }),
    ).rejects.toThrow(/changeClass/);
  });

  it("runImport (the CLI core) drives the same production path", async () => {
    const current = await makeKey("k-current", "current");
    const store = makeStore();
    const env = envelope({});
    const ack = await runImport({
      compactJws: await sign(current, env),
      jwksJson: ringJson(current),
      now: NOW,
      store,
    });
    expect(ack.policyId).toBe(POLICY_ID);
    expect(store.insertCount).toBe(1);
  });
});
