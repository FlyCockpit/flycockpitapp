import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CustodyClass,
  decodePossessionProof,
  encodeCustodyEvidence,
  PresenceMode,
  type RemoteIdentityCustodyPolicyRequestV1,
  remoteIdentitySha256,
  type SubjectKindV1,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import type {
  NativeAttestationReport,
  RemoteIdentityCustodyModule,
} from "../modules/remote-identity-custody";
import * as productionModule from "./remote-native-identity-custody";
import {
  type NativeCustodyStore,
  NativeIdentityCustodyProvider,
  type NativeIdentityCustodyProviderOptions,
  type ProcessDeathInjector,
  type ProcessDeathPoint,
  RemoteNativeIdentityCustodyError,
} from "./remote-native-identity-custody";
import {
  FakeRemoteIdentityCustodyModule,
  InMemoryNativeCustodyStore,
} from "./remote-native-identity-custody.test-support";

const DAEMON: SubjectKindV1 = 2;
const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE_DIR = join(HERE, "..", "modules", "remote-identity-custody");

const FIXTURE_PATH = join(
  HERE,
  "..",
  "..",
  "..",
  "packages",
  "cockpit-protocol",
  "fixtures",
  "remote-identity-custody-signing-v1.json",
);
const SIGNING_FIXTURE = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8")) as {
  unsignedProof: string;
  message: string;
};

// P-256 half-order n/2 — the actual low-S boundary the production codec enforces.
const P256_HALF_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n >> 1n;

function fixtureBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
}

/** Prove a signature is canonical low-S via the production codec + real n/2. */
function assertLowSViaCodec(signature: Uint8Array): void {
  const proof = new Uint8Array(239);
  proof.set(fixtureBytes(SIGNING_FIXTURE.unsignedProof));
  proof.set(signature, 175);
  decodePossessionProof(proof);
  const s = signature.slice(32, 64).reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
  expect(s <= P256_HALF_ORDER).toBe(true);
}

function fixedReport(report: NativeAttestationReport): NativeIdentityCustodyProviderOptions {
  const module = new FakeRemoteIdentityCustodyModule({ attestation: () => report });
  return {
    module,
    store: new InMemoryNativeCustodyStore(),
    clock: () => 1_700_000_000n,
    profile: report.profile,
  };
}

// ---------------------------------------------------------------------------
// Criterion 11: report-driven policy gate. Classification comes from the
// module's attestation, never a local profile constant.
// ---------------------------------------------------------------------------

describe("remote_native_identity_report_driven_policy", () => {
  it("rejects a software-keystore report when the policy requires hardware_or_external", async () => {
    const opts = fixedReport({
      custodyClass: CustodyClass.os_protected,
      presenceMode: PresenceMode.unattended_unlocked_device,
      securityLevel: "software",
      profile: "android-software-keystore",
    });
    const provider = new NativeIdentityCustodyProvider(opts);

    await expect(
      provider.generate(DAEMON, {
        minCustodyClass: CustodyClass.hardware_or_external,
        allowUserPresenceRequired: false,
      }),
    ).rejects.toMatchObject({ code: "policy_denied" });

    // No durable record and no orphan key survive a rejected generation.
    expect((opts.store as InMemoryNativeCustodyStore).size).toBe(0);
    expect((opts.module as FakeRemoteIdentityCustodyModule).size).toBe(0);
  });

  it("accepts a hardware report that meets the requested minimum", async () => {
    const opts = fixedReport({
      custodyClass: CustodyClass.hardware_or_external,
      presenceMode: PresenceMode.unattended_after_first_unlock,
      securityLevel: "secure_enclave",
      profile: "ios-secure-enclave",
    });
    const provider = new NativeIdentityCustodyProvider(opts);
    const record = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    });
    expect(record.custodyClass).toBe(CustodyClass.hardware_or_external);
    expect(record.evidence.custodyClass).toBe(CustodyClass.hardware_or_external);
  });

  it("refuses a user_presence_required key on the unattended one-tap path", async () => {
    const opts = fixedReport({
      custodyClass: CustodyClass.hardware_or_external,
      presenceMode: PresenceMode.user_presence_required,
      securityLevel: "secure_enclave",
      profile: "ios-secure-enclave",
    });
    const provider = new NativeIdentityCustodyProvider(opts);

    await expect(
      provider.generate(DAEMON, {
        minCustodyClass: CustodyClass.os_protected,
        allowUserPresenceRequired: false,
      }),
    ).rejects.toMatchObject({ code: "presence_required_unavailable" });
  });

  it("represents user_presence_required and accepts it when the policy allows it", async () => {
    const opts = fixedReport({
      custodyClass: CustodyClass.hardware_or_external,
      presenceMode: PresenceMode.user_presence_required,
      securityLevel: "secure_enclave",
      profile: "ios-secure-enclave",
    });
    const provider = new NativeIdentityCustodyProvider(opts);
    const record = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.os_protected,
      allowUserPresenceRequired: true,
    });
    expect(record.presenceMode).toBe(PresenceMode.user_presence_required);
  });

  it("treats an out-of-range attested discriminant as corrupted", async () => {
    const opts = fixedReport({
      custodyClass: 9,
      presenceMode: PresenceMode.unattended_unlocked_device,
      securityLevel: "software",
      profile: "android-software-keystore",
    });
    const provider = new NativeIdentityCustodyProvider(opts);
    await expect(
      provider.generate(DAEMON, {
        minCustodyClass: CustodyClass.os_protected,
        allowUserPresenceRequired: false,
      }),
    ).rejects.toMatchObject({ code: "corrupted" });
  });

  it("denies a generate that requested presence but attests unattended (no silent downgrade)", async () => {
    // Model a native module that IGNORED requireUserPresence and produced an
    // unattended key. Without the generate-side presence binding the caller would
    // believe every signature needs a live user when in fact none does.
    const module = new FakeRemoteIdentityCustodyModule({
      attestation: () => ({
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.unattended_after_first_unlock,
        securityLevel: "secure_enclave",
        profile: "ios-secure-enclave",
      }),
    });
    const store = new InMemoryNativeCustodyStore();
    const provider = new NativeIdentityCustodyProvider({
      module,
      store,
      clock: () => 1_700_000_000n,
      profile: "ios-secure-enclave",
      requireUserPresence: true,
    });

    await expect(
      provider.generate(DAEMON, {
        minCustodyClass: CustodyClass.hardware_or_external,
        allowUserPresenceRequired: true,
      }),
    ).rejects.toMatchObject({ code: "policy_denied" });
    // The downgraded key is retired; nothing durable survives.
    expect(store.size).toBe(0);
    expect(module.size).toBe(0);
  });

  it("fails closed on a structurally invalid policy BEFORE any key allocation", async () => {
    const opts = fixedReport({
      custodyClass: CustodyClass.hardware_or_external,
      presenceMode: PresenceMode.unattended_after_first_unlock,
      securityLevel: "secure_enclave",
      profile: "ios-secure-enclave",
    });
    const provider = new NativeIdentityCustodyProvider(opts);
    const store = opts.store as InMemoryNativeCustodyStore;
    const module = opts.module as FakeRemoteIdentityCustodyModule;

    // Raw-input discriminants that must fail closed: a non-finite / out-of-enum
    // custody class would make `report.custodyClass < policy.minCustodyClass`
    // short-circuit to `false`, and a non-boolean presence flag would corrupt the
    // `!policy.allowUserPresenceRequired` gate.
    const badPolicies: unknown[] = [
      { minCustodyClass: undefined, allowUserPresenceRequired: false },
      { minCustodyClass: null, allowUserPresenceRequired: false },
      { minCustodyClass: Number.NaN, allowUserPresenceRequired: false },
      { minCustodyClass: 2.5, allowUserPresenceRequired: false },
      { minCustodyClass: 99, allowUserPresenceRequired: false },
      { minCustodyClass: CustodyClass.os_protected, allowUserPresenceRequired: "yes" },
      { minCustodyClass: CustodyClass.os_protected, allowUserPresenceRequired: undefined },
    ];
    for (const bad of badPolicies) {
      await expect(
        provider.generate(DAEMON, bad as RemoteIdentityCustodyPolicyRequestV1),
      ).rejects.toMatchObject({ code: "policy_denied" });
    }
    // The guard runs before key creation: nothing was ever allocated.
    expect(store.size).toBe(0);
    expect(module.size).toBe(0);
  });

  it("records the injected clock as observedAt on BOTH generate and rotate", async () => {
    let tick = 1_000n;
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = new NativeIdentityCustodyProvider({
      module,
      store,
      clock: () => tick,
      profile: "ios-secure-enclave",
    });
    const created = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.os_protected,
      allowUserPresenceRequired: false,
    });
    expect(created.evidence.observedAt).toBe(1_000n);
    tick = 2_000n;
    const rotated = await provider.rotate(created.handleId);
    expect(rotated.evidence.observedAt).toBe(2_000n);
  });
});

// ---------------------------------------------------------------------------
// Criterion 12: durability + monotonic generation + process death.
// ---------------------------------------------------------------------------

function providerOver(
  module: FakeRemoteIdentityCustodyModule,
  store: InMemoryNativeCustodyStore,
  deathInjector?: ProcessDeathInjector,
): NativeIdentityCustodyProvider {
  return new NativeIdentityCustodyProvider({
    module,
    store,
    clock: () => 1_700_000_000n,
    profile: "ios-secure-enclave",
    deathInjector,
  });
}

describe("remote_native_identity_durability", () => {
  it("records survive a provider restart over the same store", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);

    const created = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    });

    // A brand-new provider over the same durable store recovers the handle.
    const restarted = providerOver(module, store);
    const reopened = await restarted.reopen(created.handleId);
    expect(reopened.publicKey.x).toEqual(created.publicKey.x);
    expect(reopened.publicKey.y).toEqual(created.publicKey.y);
    expect(reopened.custodyClass).toBe(created.custodyClass);
  });

  it("consumes a strictly increasing generation on each generate", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const policy = {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    };
    const first = await provider.generate(DAEMON, policy);
    const second = await provider.generate(DAEMON, policy);
    expect(first.evidence.generation).toBe(1n);
    expect(second.evidence.generation).toBe(2n);
  });

  it("process death mid-generate is RECONCILED on restart (orphan key retired, not skipped)", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const crash: ProcessDeathInjector = {
      reached(point: ProcessDeathPoint) {
        if (point === "before_record_persist") {
          throw new Error("simulated process death");
        }
      },
    };
    const dying = providerOver(module, store, crash);
    const policy = {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    };

    await expect(dying.generate(DAEMON, policy)).rejects.toThrow("simulated process death");

    // Immediately after the crash: an orphan native key exists, no record was
    // published, and a write-ahead pending op remains so recovery can find it.
    expect(await store.loadHighWaterMark()).toBe(1n);
    expect(store.size).toBe(0);
    expect(module.size).toBe(1);
    expect((await store.loadPendingOps()).length).toBe(1);

    // Recovery RECONCILES: the orphan key is retired (not merely skipped), then
    // the next generate makes exactly one live key + record.
    const recovered = providerOver(module, store);
    const next = await recovered.generate(DAEMON, policy);
    expect(next.evidence.generation).toBe(2n);
    expect(module.size).toBe(1);
    expect(store.size).toBe(1);
    expect((await store.loadPendingOps()).length).toBe(0);
    const reopened = await recovered.reopen(next.handleId);
    expect(reopened.handleId).toEqual(next.handleId);
  });

  it("process death mid-rotate after publish is RECONCILED (superseded key retired)", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const policy = {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    };
    const original = await providerOver(module, store).generate(DAEMON, policy);

    // Crash AFTER the new record is durable but BEFORE the old key/record retire.
    const crash: ProcessDeathInjector = {
      reached(point: ProcessDeathPoint) {
        if (point === "after_record_persist") {
          throw new Error("simulated process death");
        }
      },
    };
    await expect(providerOver(module, store, crash).rotate(original.handleId)).rejects.toThrow(
      "simulated process death",
    );

    // Mixed state right after crash: two keys, two records, one pending op.
    expect(module.size).toBe(2);
    expect(store.size).toBe(2);
    expect((await store.loadPendingOps()).length).toBe(1);
    const records = await store.listRecords();
    const newHandle = records.find((r) => hexOf(r.handleId) !== hexOf(original.handleId))?.handleId;
    expect(newHandle).toBeDefined();

    // Recovery reconciles: the superseded OLD key + record are retired, leaving
    // exactly one live key + record (the new generation).
    const recovered = providerOver(module, store);
    const reopened = await recovered.reopen(newHandle as Uint8Array);
    expect(module.size).toBe(1);
    expect(store.size).toBe(1);
    expect((await store.loadPendingOps()).length).toBe(0);
    expect(reopened.handleId).toEqual(newHandle);
    await expect(recovered.reopen(original.handleId)).rejects.toMatchObject({ code: "not_found" });
  });

  it("destroy then generate never reuses a generation across a restart", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const policy = {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    };

    const created = await provider.generate(DAEMON, policy);
    expect(created.evidence.generation).toBe(1n);
    await provider.destroy(created.handleId);
    expect(store.size).toBe(0);
    // destroy must not reset the high-water mark.
    expect(await store.loadHighWaterMark()).toBe(1n);

    const restarted = providerOver(module, store);
    const next = await restarted.generate(DAEMON, policy);
    expect(next.evidence.generation).toBe(2n);
  });

  it("rotation publishes the new durable generation and then destroys the old key", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const policy = {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    };

    const original = await provider.generate(DAEMON, policy);
    const rotated = await provider.rotate(original.handleId);

    expect(rotated.evidence.generation).toBe(2n);
    expect(hexOf(rotated.handleId)).not.toBe(hexOf(original.handleId));
    // Old handle destroyed, new handle durable and reopenable.
    await expect(provider.reopen(original.handleId)).rejects.toMatchObject({ code: "not_found" });
    const reopened = await provider.reopen(rotated.handleId);
    expect(reopened.publicKey.x).toEqual(rotated.publicKey.x);
    expect(store.size).toBe(1);
  });

  it("signs after a restart and rejects a destroyed handle", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const created = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    });

    const restarted = providerOver(module, store);
    const sig = await restarted.signPossessionProof(
      created.handleId,
      fixtureBytes(SIGNING_FIXTURE.message),
    );
    expect(sig.length).toBe(64);
    // Canonical low-S proven through the production codec + real n/2 (not bit-7).
    assertLowSViaCodec(sig);

    await restarted.destroy(created.handleId);
    await expect(
      restarted.signPossessionProof(created.handleId, new Uint8Array(48)),
    ).rejects.toMatchObject({ code: "not_found" });
  });
});

// ---------------------------------------------------------------------------
// Fail-closed reopen, atomic generation reservation, presence preservation.
// ---------------------------------------------------------------------------

describe("remote_native_identity_fail_closed_and_concurrency", () => {
  const policy = {
    minCustodyClass: CustodyClass.hardware_or_external,
    allowUserPresenceRequired: false,
  };

  it("reserves distinct generations for concurrent generate calls", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const a = providerOver(module, store);
    const b = providerOver(module, store);
    const [g1, g2] = await Promise.all([a.generate(DAEMON, policy), b.generate(DAEMON, policy)]);
    expect(g1.evidence.generation).not.toBe(g2.evidence.generation);
    expect(new Set([g1.evidence.generation, g2.evidence.generation]).size).toBe(2);
  });

  it("reopen fails closed when the durable key was lost from the keystore", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const created = await provider.generate(DAEMON, policy);
    // Key loss (app reinstall / keystore invalidation): the durable RECORD
    // survives, but the key is gone. reopen must not report a usable identity.
    await module.destroyGeneration(created.handleId);
    await expect(provider.reopen(created.handleId)).rejects.toMatchObject({ code: "not_found" });
  });

  it("rotation refuses a presence downgrade and keeps the old presence-gated key", async () => {
    const module = new FakeRemoteIdentityCustodyModule({
      attestation: () => ({
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.user_presence_required,
        securityLevel: "secure_enclave",
        profile: "ios-secure-enclave",
      }),
      // A misbehaving native rotate that drops the presence requirement.
      rotateAttestation: (previous) => ({
        ...previous,
        presenceMode: PresenceMode.unattended_after_first_unlock,
      }),
    });
    const store = new InMemoryNativeCustodyStore();
    const provider = new NativeIdentityCustodyProvider({
      module,
      store,
      clock: () => 1_700_000_000n,
      profile: "ios-secure-enclave",
      requireUserPresence: true,
    });
    const created = await provider.generate(DAEMON, {
      minCustodyClass: CustodyClass.os_protected,
      allowUserPresenceRequired: true,
    });
    expect(created.presenceMode).toBe(PresenceMode.user_presence_required);
    // A presenceMode that no longer EXACTLY matches the record is corruption
    // (the exact-equality binding rejects any difference, up or down).
    await expect(provider.rotate(created.handleId)).rejects.toMatchObject({
      code: "corrupted",
    });
    // Fail closed: the original presence-gated key is intact and reopenable.
    const reopened = await provider.reopen(created.handleId);
    expect(reopened.presenceMode).toBe(PresenceMode.user_presence_required);
  });

  it("rotation refuses a rotate under a DIFFERENT configured profile (policy_denied)", async () => {
    const store = new InMemoryNativeCustodyStore();
    const honest = new FakeRemoteIdentityCustodyModule(); // ios-secure-enclave
    const created = await new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: "ios-secure-enclave",
    }).generate(DAEMON, {
      minCustodyClass: CustodyClass.hardware_or_external,
      allowUserPresenceRequired: false,
    });
    // A provider reconstructed under a different configured profile must not be
    // able to rotate (and keep using) the prior profile's identity.
    await expect(
      new NativeIdentityCustodyProvider({
        module: honest,
        store,
        clock: () => 1n,
        profile: "android-strongbox",
      }).rotate(created.handleId),
    ).rejects.toMatchObject({ code: "policy_denied" });
    // The original identity survives intact under its own profile.
    const reopened = await new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: "ios-secure-enclave",
    }).reopen(created.handleId);
    expect(reopened.custodyClass).toBe(CustodyClass.hardware_or_external);
  });

  it("rejects a spoofed report whose custody class is inconsistent with its security level", async () => {
    // A hostile bridge claims hardware custody while the security level is only
    // software — this must NOT be encoded as hardware custody.
    const module = new FakeRemoteIdentityCustodyModule({
      attestation: () => ({
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.unattended_unlocked_device,
        securityLevel: "software",
        profile: "android-software-keystore",
      }),
    });
    const store = new InMemoryNativeCustodyStore();
    const provider = new NativeIdentityCustodyProvider({
      module,
      store,
      clock: () => 1n,
      profile: "android-software-keystore",
    });
    await expect(provider.generate(DAEMON, policy)).rejects.toMatchObject({ code: "corrupted" });
    // The spoofed key was retired; nothing was persisted.
    expect(module.size).toBe(0);
    expect(store.size).toBe(0);
  });

  it("rejects a report whose profile does not match the requested profile", async () => {
    const module = new FakeRemoteIdentityCustodyModule({
      attestation: () => ({
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.unattended_after_first_unlock,
        securityLevel: "secure_enclave",
        profile: "ios-secure-enclave",
      }),
    });
    const provider = new NativeIdentityCustodyProvider({
      module,
      store: new InMemoryNativeCustodyStore(),
      clock: () => 1n,
      profile: "android-strongbox", // requests a DIFFERENT profile than reported
    });
    await expect(
      provider.generate(DAEMON, {
        minCustodyClass: CustodyClass.os_protected,
        allowUserPresenceRequired: false,
      }),
    ).rejects.toMatchObject({ code: "policy_denied" });
  });

  it("reopen rejects a record whose persisted evidence does not match its metadata", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const provider = providerOver(module, store);
    const created = await provider.generate(DAEMON, policy);
    const record = await store.loadRecord(created.handleId);
    expect(record).toBeDefined();
    // Tamper: keep the hardware metadata but swap in evidence for os_protected.
    const providerEvidence = Uint8Array.from([1, 2, 3, 4]);
    const tampered = encodeCustodyEvidence({
      subjectKind: DAEMON,
      subjectId: created.handleId,
      generation: 1n,
      custodyClass: CustodyClass.os_protected,
      presenceMode: PresenceMode.unattended_after_first_unlock,
      providerEvidence,
      evidenceDigest: await remoteIdentitySha256(providerEvidence),
      observedAt: 1n,
    });
    await store.saveRecord({ ...(record as NonNullable<typeof record>), evidence: tampered });
    await expect(provider.reopen(created.handleId)).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reopen fails closed when the persisted record is unreadable (corrupt generation)", async () => {
    const brokenStore: NativeCustodyStore = {
      async reserveNextGeneration() {
        return 1n;
      },
      async loadHighWaterMark() {
        return 1n;
      },
      async savePendingOp() {},
      async loadPendingOps() {
        return [];
      },
      async clearPendingOp() {},
      async loadRecord() {
        throw new SyntaxError("Cannot convert corrupt-generation to a BigInt");
      },
      async listRecords() {
        return [];
      },
      async saveRecord() {},
      async deleteRecord() {},
    };
    const provider = new NativeIdentityCustodyProvider({
      module: new FakeRemoteIdentityCustodyModule(),
      store: brokenStore,
      clock: () => 1n,
      profile: "ios-secure-enclave",
    });
    await expect(provider.reopen(new Uint8Array(16).fill(7))).rejects.toMatchObject({
      code: "corrupted",
    });
  });

  it("the conformance fake's private key is non-extractable", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const gen = await module.generateP256(
      new Uint8Array(16).fill(0x5e),
      "ios-secure-enclave",
      false,
    );
    const key = module.privateKeyHandleForTest(gen.handleId);
    expect(key?.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", key as CryptoKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// reopen anti-spoof + write-ahead reconciliation edge cases.
// ---------------------------------------------------------------------------

describe("remote_native_identity_reconciliation_and_reopen_spoof", () => {
  const policy = {
    minCustodyClass: CustodyClass.hardware_or_external,
    allowUserPresenceRequired: false,
  };
  const IOS = "ios-secure-enclave";
  const providerWith = (module: RemoteIdentityCustodyModule, store: NativeCustodyStore) =>
    new NativeIdentityCustodyProvider({ module, store, clock: () => 1n, profile: IOS });

  it("reopen rejects a live report inconsistent with the stored security level (spoof)", async () => {
    const store = new InMemoryNativeCustodyStore();
    const honest = new FakeRemoteIdentityCustodyModule();
    const created = await providerWith(honest, store).generate(DAEMON, policy);
    const live = await honest.publicKey(created.handleId);
    // Hostile bridge: SAME public key, but claims hardware custody over a
    // "software" security level. reopen must run the same anti-spoof validation.
    const spoof: RemoteIdentityCustodyModule = {
      generateP256: () => Promise.reject(new Error("unused")),
      signP256: () => Promise.reject(new Error("unused")),
      publicKey: async () => ({
        x: live.x,
        y: live.y,
        attestation: {
          custodyClass: CustodyClass.hardware_or_external,
          presenceMode: PresenceMode.unattended_after_first_unlock,
          securityLevel: "software",
          profile: IOS,
        },
      }),
      rotateP256: () => Promise.reject(new Error("unused")),
      destroyGeneration: async () => {},
    };
    await expect(providerWith(spoof, store).reopen(created.handleId)).rejects.toMatchObject({
      code: "corrupted",
    });
  });

  it("write-ahead marker precedes key creation: a crash right after key create is reconciled", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const store = new InMemoryNativeCustodyStore();
    const crash: ProcessDeathInjector = {
      reached(point: ProcessDeathPoint) {
        if (point === "after_key_create") {
          throw new Error("simulated process death");
        }
      },
    };
    await expect(providerOver(module, store, crash).generate(DAEMON, policy)).rejects.toThrow(
      "simulated process death",
    );
    // The marker was written BEFORE the key, so even a crash immediately after
    // key creation leaves a discoverable orphan (marker present, no record).
    // (With the old marker-after-key order this pending count would be 0.)
    expect(module.size).toBe(1);
    expect(store.size).toBe(0);
    expect((await store.loadPendingOps()).length).toBe(1);

    const recovered = providerOver(module, store);
    const next = await recovered.generate(DAEMON, policy);
    expect(next.evidence.generation).toBe(2n);
    expect(module.size).toBe(1); // orphan retired
    expect(store.size).toBe(1);
    expect((await store.loadPendingOps()).length).toBe(0);
  });

  it("propagates a transient retire failure (marker kept); the SAME provider retries on the next op", async () => {
    const inner = new FakeRemoteIdentityCustodyModule();
    let destroyCalls = 0;
    const flaky: RemoteIdentityCustodyModule = {
      generateP256: (h, p, r) => inner.generateP256(h, p, r),
      signP256: (h, m) => inner.signP256(h, m),
      publicKey: (h) => inner.publicKey(h),
      rotateP256: (h, n) => inner.rotateP256(h, n),
      destroyGeneration: async (h) => {
        destroyCalls += 1;
        if (destroyCalls === 1) {
          throw new RemoteNativeIdentityCustodyError(
            "provider_unavailable",
            "transient keystore failure",
          );
        }
        return inner.destroyGeneration(h);
      },
    };
    const store = new InMemoryNativeCustodyStore();
    const crash: ProcessDeathInjector = {
      reached(point: ProcessDeathPoint) {
        if (point === "after_key_create") {
          throw new Error("crash");
        }
      },
    };
    await expect(
      new NativeIdentityCustodyProvider({
        module: flaky,
        store,
        clock: () => 1n,
        profile: IOS,
        deathInjector: crash,
      }).generate(DAEMON, policy),
    ).rejects.toThrow("crash");
    expect((await store.loadPendingOps()).length).toBe(1);
    expect(inner.size).toBe(1);

    const recovering = providerWith(flaky, store);
    // First op: reconcile's orphan retire FAILS → reconcile PROPAGATES → the op
    // throws, the latch stays UNSET, and the marker is KEPT (never a leaked key).
    await expect(recovering.generate(DAEMON, policy)).rejects.toMatchObject({
      code: "provider_unavailable",
    });
    expect((await store.loadPendingOps()).length).toBe(1);
    expect(inner.size).toBe(1);

    // Next op on the SAME provider: reconciliation is RETRIED; the retire now
    // succeeds → the orphan is retired, the marker cleared, and the op proceeds.
    const gen2 = await recovering.generate(DAEMON, policy);
    expect(gen2.evidence.generation).toBe(2n);
    expect((await store.loadPendingOps()).length).toBe(0);
    expect(inner.size).toBe(1);
  });

  it("propagates a per-marker loadRecord failure; the SAME provider retries on the next op", async () => {
    const module = new FakeRemoteIdentityCustodyModule();
    const base = new InMemoryNativeCustodyStore();
    const crash: ProcessDeathInjector = {
      reached(point: ProcessDeathPoint) {
        if (point === "after_record_persist") {
          throw new Error("crash");
        }
      },
    };
    // Crash after the record persisted but before the marker cleared → a marker
    // over an existing record remains.
    await expect(
      new NativeIdentityCustodyProvider({
        module,
        store: base,
        clock: () => 1n,
        profile: IOS,
        deathInjector: crash,
      }).generate(DAEMON, policy),
    ).rejects.toThrow("crash");
    expect((await base.loadPendingOps()).length).toBe(1);

    let failNextLoad = true;
    const flakyStore: NativeCustodyStore = {
      reserveNextGeneration: () => base.reserveNextGeneration(),
      loadHighWaterMark: () => base.loadHighWaterMark(),
      savePendingOp: (op) => base.savePendingOp(op),
      loadPendingOps: () => base.loadPendingOps(),
      clearPendingOp: (h) => base.clearPendingOp(h),
      loadRecord: async (h) => {
        if (failNextLoad) {
          failNextLoad = false;
          throw new Error("transient record read");
        }
        return base.loadRecord(h);
      },
      listRecords: () => base.listRecords(),
      saveRecord: (r) => base.saveRecord(r),
      deleteRecord: (h) => base.deleteRecord(h),
    };
    const recovering = new NativeIdentityCustodyProvider({
      module,
      store: flakyStore,
      clock: () => 1n,
      profile: IOS,
    });
    // First op: reconcile's loadRecord throws → PROPAGATE → op throws, marker kept.
    await expect(recovering.generate(DAEMON, policy)).rejects.toThrow("transient record read");
    expect((await base.loadPendingOps()).length).toBe(1);
    // Next op: reconciliation retried; loadRecord succeeds → the stale marker is
    // cleared and the op proceeds.
    const gen = await recovering.generate(DAEMON, policy);
    expect((await base.loadPendingOps()).length).toBe(0);
    expect(gen.evidence.generation).toBe(2n);
  });

  it("a transient reconcile failure does not latch the reconciler; the next op retries it", async () => {
    const base = new InMemoryNativeCustodyStore();
    let loadPendingCalls = 0;
    let failNext = true;
    const flakyStore: NativeCustodyStore = {
      reserveNextGeneration: () => base.reserveNextGeneration(),
      loadHighWaterMark: () => base.loadHighWaterMark(),
      savePendingOp: (op) => base.savePendingOp(op),
      loadPendingOps: async () => {
        loadPendingCalls += 1;
        if (failNext) {
          failNext = false;
          throw new Error("transient read failure");
        }
        return base.loadPendingOps();
      },
      clearPendingOp: (h) => base.clearPendingOp(h),
      loadRecord: (h) => base.loadRecord(h),
      listRecords: () => base.listRecords(),
      saveRecord: (r) => base.saveRecord(r),
      deleteRecord: (h) => base.deleteRecord(h),
    };
    const provider = providerWith(new FakeRemoteIdentityCustodyModule(), flakyStore);
    // First op: reconcile's read throws → op fails, latch NOT set.
    await expect(provider.generate(DAEMON, policy)).rejects.toThrow("transient read failure");
    expect(loadPendingCalls).toBe(1);
    // Next op: reconciliation is RETRIED (not skipped) and succeeds.
    // (If the latch were set before reconcile completed, this stays 1.)
    const created = await provider.generate(DAEMON, policy);
    expect(loadPendingCalls).toBe(2);
    expect(created.evidence.generation).toBe(1n);
  });

  it("rejects a module that returns a different handle than the one requested", async () => {
    const inner = new FakeRemoteIdentityCustodyModule();
    const swap = (h: Uint8Array) => h.map((b) => b ^ 0xff);
    // A lying module: it creates/returns a DIFFERENT handle than the caller
    // assigned (and wrote into the write-ahead marker).
    const swapping: RemoteIdentityCustodyModule = {
      generateP256: (h, p, r) => inner.generateP256(swap(h), p, r),
      signP256: (h, m) => inner.signP256(h, m),
      publicKey: (h) => inner.publicKey(h),
      rotateP256: (h, n) => inner.rotateP256(h, swap(n)),
      destroyGeneration: (h) => inner.destroyGeneration(h),
    };
    const store = new InMemoryNativeCustodyStore();
    await expect(providerWith(swapping, store).generate(DAEMON, policy)).rejects.toMatchObject({
      code: "corrupted",
    });
    // No record persisted; the actually-created (swapped) key was retired; the
    // marker is cleared — no undiscoverable orphan. (Without the check, the
    // record would persist under the swapped handle and generate would succeed.)
    expect(store.size).toBe(0);
    expect(inner.size).toBe(0);
    expect((await store.loadPendingOps()).length).toBe(0);
  });

  it("handle-swap + transient destroy failure leaves a marker covering the RETURNED key", async () => {
    const inner = new FakeRemoteIdentityCustodyModule();
    const swap = (h: Uint8Array) => h.map((b) => b ^ 0xff);
    let destroyCalls = 0;
    const swapping: RemoteIdentityCustodyModule = {
      generateP256: (h, p, r) => inner.generateP256(swap(h), p, r),
      signP256: (h, m) => inner.signP256(h, m),
      publicKey: (h) => inner.publicKey(h),
      rotateP256: (h, n) => inner.rotateP256(h, swap(n)),
      destroyGeneration: async (h) => {
        destroyCalls += 1;
        if (destroyCalls === 1) {
          throw new RemoteNativeIdentityCustodyError("provider_unavailable", "transient");
        }
        return inner.destroyGeneration(h);
      },
    };
    const store = new InMemoryNativeCustodyStore();
    await expect(providerWith(swapping, store).generate(DAEMON, policy)).rejects.toMatchObject({
      code: "corrupted",
    });
    // The swapped key B could NOT be destroyed (transient) → its live key remains
    // and a recovery marker now names B (not the requested handle), so restart
    // reconciliation can still retire it. (Without the fix: B leaks with NO
    // marker — pending would be 0 and inner.size would stay 1 forever.)
    expect(inner.size).toBe(1);
    expect((await store.loadPendingOps()).length).toBe(1);

    // A later reconcile (destroy now succeeds) retires the leaked key B.
    await expect(
      providerWith(swapping, store).reopen(new Uint8Array(16).fill(1)),
    ).rejects.toMatchObject({ code: "not_found" });
    expect(inner.size).toBe(0);
    expect((await store.loadPendingOps()).length).toBe(0);
  });

  it("reopen rejects a restart report that UPGRADES the stored custody class (spoof)", async () => {
    const store = new InMemoryNativeCustodyStore();
    const teeReport = (): NativeAttestationReport => ({
      custodyClass: CustodyClass.os_protected,
      presenceMode: PresenceMode.unattended_unlocked_device,
      securityLevel: "tee",
      profile: "android-tee",
    });
    const honest = new FakeRemoteIdentityCustodyModule({ attestation: teeReport });
    const created = await new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: "android-tee",
    }).generate(DAEMON, {
      minCustodyClass: CustodyClass.os_protected,
      allowUserPresenceRequired: false,
    });
    const live = await honest.publicKey(created.handleId);
    // Spoof: SAME public key, but UPGRADED to StrongBox/hardware. Exact-equality
    // reopen must reject a "stronger" class, not accept it.
    const spoof: RemoteIdentityCustodyModule = {
      generateP256: () => Promise.reject(new Error("unused")),
      signP256: () => Promise.reject(new Error("unused")),
      publicKey: async () => ({
        x: live.x,
        y: live.y,
        attestation: {
          custodyClass: CustodyClass.hardware_or_external,
          presenceMode: PresenceMode.unattended_unlocked_device,
          securityLevel: "strongbox",
          profile: "android-tee",
        },
      }),
      rotateP256: () => Promise.reject(new Error("unused")),
      destroyGeneration: async () => {},
    };
    await expect(
      new NativeIdentityCustodyProvider({
        module: spoof,
        store,
        clock: () => 1n,
        profile: "android-tee",
      }).reopen(created.handleId),
    ).rejects.toMatchObject({ code: "corrupted" });
  });

  it("reopen rejects a provider reconstructed under a different configured profile", async () => {
    const store = new InMemoryNativeCustodyStore();
    const honest = new FakeRemoteIdentityCustodyModule(); // ios-secure-enclave
    const created = await new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: IOS,
    }).generate(DAEMON, policy);
    // The record and live report both say "ios-secure-enclave", but this provider
    // is configured for a DIFFERENT profile → reject (not usable under it).
    await expect(
      new NativeIdentityCustodyProvider({
        module: honest,
        store,
        clock: () => 1n,
        profile: "android-strongbox",
      }).reopen(created.handleId),
    ).rejects.toMatchObject({ code: "policy_denied" });
  });

  it("sign and destroy are also rejected under a different configured profile", async () => {
    // The configured-profile binding lives at the SINGLE load funnel, so it
    // covers sign and destroy too — not just reopen/rotate.
    const store = new InMemoryNativeCustodyStore();
    const honest = new FakeRemoteIdentityCustodyModule(); // ios-secure-enclave
    const created = await new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: IOS,
    }).generate(DAEMON, policy);
    const wrong = new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: "android-strongbox",
    });
    await expect(
      wrong.signPossessionProof(created.handleId, new Uint8Array(48).fill(7)),
    ).rejects.toMatchObject({ code: "policy_denied" });
    await expect(wrong.destroy(created.handleId)).rejects.toMatchObject({ code: "policy_denied" });
    // The identity remains intact and usable under its own configured profile.
    const ok = new NativeIdentityCustodyProvider({
      module: honest,
      store,
      clock: () => 1n,
      profile: IOS,
    });
    const sig = await ok.signPossessionProof(created.handleId, new Uint8Array(48).fill(7));
    expect(sig).toHaveLength(64);
  });
});

// ---------------------------------------------------------------------------
// Criterion 20: the old tautological guard functions are gone; classification
// is report-driven, not constant-vs-itself.
// ---------------------------------------------------------------------------

describe("remote_native_identity_no_tautologies", () => {
  it("no longer exports the removed self-referential guard functions", async () => {
    const custody = await import("./remote-native-identity-custody");
    expect("nativeX25519BridgeAbsenceGuard" in custody).toBe(false);
    expect("nativePrivateMaterialGuard" in custody).toBe(false);
    expect("nativeFoundationConsumptionGuard" in custody).toBe(false);
    expect("NativeCustodyPolicyGate" in custody).toBe(false);
    expect("nativeCustodyReport" in custody).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Criterion 10: source-scan of the local Expo module.
// ---------------------------------------------------------------------------

/**
 * Strip `//` line comments and `/* … *​/` block comments so the forbidden-token
 * scan targets REAL CODE, not prose. This lets the sources describe what they
 * deliberately avoid (e.g. "no X25519 / key agreement here") in honest comments
 * while still failing loudly if a forbidden API is reintroduced in code.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
}

/**
 * The (comment-stripped) body of a named method, starting immediately after its
 * opening brace with leading whitespace trimmed — so `.startsWith(...)` reveals
 * the method's FIRST executable statement. `keyword` is "func" (Swift) or "fun"
 * (Kotlin). Since these signatures carry no brace before the body (`[String:
 * Any]` / `Map<String, Any>` contain none), the first `{` after the name is the
 * body brace.
 */
function methodBody(source: string, keyword: string, name: string): string {
  const decl = new RegExp(`\\b${keyword}\\s+${name}\\s*\\(`);
  const m = decl.exec(source);
  if (!m) {
    throw new Error(`method not found: ${keyword} ${name}`);
  }
  const brace = source.indexOf("{", m.index);
  if (brace === -1) {
    throw new Error(`no body brace for ${keyword} ${name}`);
  }
  return source.slice(brace + 1).replace(/^\s+/, "");
}

describe("remote_identity_custody_module_source_scan", () => {
  const swift = stripComments(
    readFileSync(join(MODULE_DIR, "ios", "RemoteIdentityCustodyModule.swift"), "utf-8"),
  );
  const kotlin = stripComments(
    readFileSync(
      join(
        MODULE_DIR,
        "android",
        "src",
        "main",
        "java",
        "expo",
        "modules",
        "remoteidentitycustody",
        "RemoteIdentityCustodyModule.kt",
      ),
      "utf-8",
    ),
  );
  const indexTs = readFileSync(join(MODULE_DIR, "index.ts"), "utf-8");
  const config = readFileSync(join(MODULE_DIR, "expo-module.config.json"), "utf-8");

  const FIVE = ["destroyGeneration", "generateP256", "publicKey", "rotateP256", "signP256"];
  // Private-key export vectors that neither native source may use. (The public
  // key is read via SecKeyCopyPublicKey / ECPublicKey affine coordinates, never
  // via a raw private-material export.)
  const FORBIDDEN_PRIVATE_EXPORT = ["kSecReturnData", "getEncoded", "PKCS8"];

  it("Swift source uses the required Secure Enclave / Keychain signing APIs", () => {
    expect(swift).toContain("SecKeyCreateRandomKey");
    expect(swift).toContain("kSecAttrTokenIDSecureEnclave");
    expect(swift).toContain("ThisDeviceOnly");
    expect(swift).toContain("kSecAttrAccessibleWhenUnlockedThisDeviceOnly");
    expect(swift).toContain("ecdsaSignatureMessageX962SHA256");
  });

  it("Kotlin source uses the required Keystore / StrongBox signing APIs", () => {
    expect(kotlin).toContain("KeyGenParameterSpec");
    expect(kotlin).toContain("setIsStrongBoxBacked");
    expect(kotlin).toContain("setUserAuthenticationRequired");
    expect(kotlin).toContain("SHA256withECDSA");
  });

  it("neither native source syncs keys, uses X25519, or exports private material", () => {
    for (const source of [swift, kotlin]) {
      expect(source).not.toContain("kSecAttrSynchronizable");
      expect(source).not.toContain("X25519");
      for (const forbidden of FORBIDDEN_PRIVATE_EXPORT) {
        expect(source).not.toContain(forbidden);
      }
    }
  });

  it("each native module exposes EXACTLY the five methods", () => {
    const swiftNames = [...swift.matchAll(/AsyncFunction\("(\w+)"\)/g)].map((m) => m[1]!).sort();
    const kotlinNames = [...kotlin.matchAll(/AsyncFunction\("(\w+)"\)/g)].map((m) => m[1]!).sort();
    expect(swiftNames).toEqual(FIVE);
    expect(kotlinNames).toEqual(FIVE);
  });

  // The five AsyncFunction entries delegate to these five private methods; each
  // must INVOKE the fail-closed guard as its FIRST statement — not merely define
  // the guard somewhere. If a method's first statement were ever anything else,
  // an unimplemented native backing could return a plausible-but-wrong result.
  const SWIFT_METHODS = ["generate", "sign", "publicKeyReport", "rotate", "destroy"];
  const KOTLIN_METHODS = ["generate", "sign", "publicKeyReport", "rotate", "destroy"];

  it("every Swift entry method invokes requireNativeBackingWired() first", () => {
    for (const name of SWIFT_METHODS) {
      expect(methodBody(swift, "func", name).startsWith("try requireNativeBackingWired()")).toBe(
        true,
      );
    }
    // The guard itself throws unconditionally.
    expect(methodBody(swift, "func", "requireNativeBackingWired").startsWith("throw")).toBe(true);
  });

  it("every Kotlin entry method invokes requireNativeBackingWired() first", () => {
    for (const name of KOTLIN_METHODS) {
      expect(methodBody(kotlin, "fun", name).startsWith("requireNativeBackingWired()")).toBe(true);
    }
    expect(methodBody(kotlin, "fun", "requireNativeBackingWired").startsWith("throw")).toBe(true);
  });

  it("native profile/presence recovery fails closed (never a hardcoded downgrade)", () => {
    // profileForTag / profileForAlias must THROW as their first statement rather
    // than guess a profile, which would silently downgrade a presence-gated or
    // hardware key to unattended/software.
    expect(methodBody(swift, "func", "profileForTag").startsWith("throw")).toBe(true);
    expect(methodBody(kotlin, "fun", "profileForAlias").startsWith("throw")).toBe(true);
  });

  it("the TS interface declares exactly the five methods", () => {
    const interfaceBody = indexTs.slice(indexTs.indexOf("interface RemoteIdentityCustodyModule"));
    const closed = interfaceBody.slice(0, interfaceBody.indexOf("\n}"));
    const methods = [...closed.matchAll(/^\s{2}(\w+)\(/gm)].map((m) => m[1]!).sort();
    expect(methods).toEqual(FIVE);
  });

  it("the expo module config registers the Swift and Kotlin modules", () => {
    const parsed = JSON.parse(config) as {
      apple: { modules: string[] };
      android: { modules: string[] };
    };
    expect(parsed.apple.modules).toContain("RemoteIdentityCustodyModule");
    expect(parsed.android.modules).toContain(
      "expo.modules.remoteidentitycustody.RemoteIdentityCustodyModule",
    );
  });
});

describe("remote_native_identity_production_module_exports_only_real_provider", () => {
  const PROD_SOURCE = readFileSync(join(HERE, "remote-native-identity-custody.ts"), "utf-8");

  it("the production module does not export any in-memory or fake custody double", () => {
    // A test double reachable as a production export could be wired as a real
    // custody backend and silently ship volatile/fake identity. The doubles live
    // in the sibling `.test-support` file; the production module must not export
    // them (nor even define them).
    const exportedNames = Object.keys(productionModule);
    for (const name of exportedNames) {
      expect(name).not.toMatch(/InMemory|Fake|Mock|Stub/i);
    }
    expect(exportedNames).toContain("NativeIdentityCustodyProvider");
    expect(exportedNames).toContain("RemoteNativeIdentityCustodyError");
    // Runtime shape: the doubles are absent from the production namespace.
    const prod = productionModule as Record<string, unknown>;
    expect(prod.InMemoryNativeCustodyStore).toBeUndefined();
    expect(prod.FakeRemoteIdentityCustodyModule).toBeUndefined();
    expect(prod.normalizeLowSP1363).toBeUndefined();
  });

  it("the production source neither exports nor defines the test doubles", () => {
    for (const symbol of [
      "InMemoryNativeCustodyStore",
      "FakeRemoteIdentityCustodyModule",
      "FakeRemoteIdentityCustodyModuleOptions",
    ]) {
      expect(PROD_SOURCE).not.toContain(`class ${symbol}`);
      expect(PROD_SOURCE).not.toContain(`interface ${symbol}`);
    }
    // normalizeLowSP1363 is a test-support helper now; it must not be defined or
    // exported by the production module.
    expect(PROD_SOURCE).not.toContain("function normalizeLowSP1363");
    expect(PROD_SOURCE).not.toContain("normalizeLowSP1363");
  });

  it("the test-support doubles resolve from the sibling test-support module", () => {
    expect(new InMemoryNativeCustodyStore()).toBeInstanceOf(InMemoryNativeCustodyStore);
    expect(new FakeRemoteIdentityCustodyModule()).toBeInstanceOf(FakeRemoteIdentityCustodyModule);
  });
});

function hexOf(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
