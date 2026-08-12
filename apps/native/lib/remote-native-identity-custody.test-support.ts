/**
 * TEST-ONLY support doubles for the native identity-custody provider.
 *
 * These are NOT production custody: the {@link InMemoryNativeCustodyStore} is a
 * volatile store and {@link FakeRemoteIdentityCustodyModule} is a WebCrypto
 * conformance fake that stands in for the OS keystore. They live OUTSIDE the
 * production module (`remote-native-identity-custody.ts`) so they can never be
 * imported and shipped as a real custody backend — the production module
 * exports only the real provider, its interfaces, and the error type. A
 * source-scan test asserts the production module exports no in-memory/fake
 * store. `.test-support.ts` is excluded from the app bundle by convention.
 */
import {
  CustodyClass,
  PresenceMode,
  type RemoteIdentityP256PublicKeyV1,
  type SubjectKindV1,
} from "@flycockpit/cockpit-protocol";
import type {
  NativeAttestationReport,
  NativeGenerateResult,
  NativeSecurityLevel,
  RemoteIdentityCustodyModule,
} from "../modules/remote-identity-custody";
import {
  type NativeCustodyStore,
  type PendingCustodyOp,
  type PersistedCustodyRecord,
  RemoteNativeIdentityCustodyError,
} from "./remote-native-identity-custody";

// ---------------------------------------------------------------------------
// In-memory persistent store (test double). Values are serialized to strings to
// simulate a real key/value durable store and to force the codec to re-run on
// every load; the object survives a provider "restart" (a new provider built
// over the same store instance).
// ---------------------------------------------------------------------------

interface SerializedRecord {
  handleId: string;
  subjectKind: SubjectKindV1;
  x: string;
  y: string;
  custodyClass: number;
  presenceMode: number;
  securityLevel: NativeSecurityLevel;
  profile: string;
  generation: string;
  evidence: string;
}

interface SerializedPendingOp {
  handleId: string;
  generation: string;
  supersedes?: string;
}

/**
 * TEST-ONLY in-memory {@link NativeCustodyStore}. There is NO production,
 * platform-backed store yet: the production store must be backed by the
 * module-owned native durable storage (iOS non-synchronizable ThisDeviceOnly
 * Keychain metadata item / Android app-private SharedPreferences), which is an
 * unimplemented native TODO (see
 * `apps/native/modules/remote-identity-custody/NATIVE-PLATFORM-TODO.md`). Do NOT
 * ship this class as a real durable store — its state is volatile.
 */
export class InMemoryNativeCustodyStore implements NativeCustodyStore {
  private highWaterMark = "0";
  private readonly records = new Map<string, SerializedRecord>();
  private readonly pending = new Map<string, SerializedPendingOp>();

  async reserveNextGeneration(): Promise<bigint> {
    // Atomic: there is NO `await` between the read and the write, so concurrent
    // callers each run to completion before the next starts (modeling a single
    // native atomic increment). Two providers can never reserve the same value.
    const next = BigInt(this.highWaterMark) + 1n;
    this.highWaterMark = next.toString();
    return next;
  }

  async loadHighWaterMark(): Promise<bigint> {
    return BigInt(this.highWaterMark);
  }

  async savePendingOp(op: PendingCustodyOp): Promise<void> {
    this.pending.set(hex(op.handleId), {
      handleId: hex(op.handleId),
      generation: op.generation.toString(),
      supersedes: op.supersedes ? hex(op.supersedes) : undefined,
    });
  }

  async loadPendingOps(): Promise<readonly PendingCustodyOp[]> {
    return [...this.pending.values()].map((raw) => ({
      handleId: fromHex(raw.handleId),
      generation: BigInt(raw.generation),
      supersedes: raw.supersedes ? fromHex(raw.supersedes) : undefined,
    }));
  }

  async clearPendingOp(handleId: Uint8Array): Promise<void> {
    this.pending.delete(hex(handleId));
  }

  async loadRecord(handleId: Uint8Array): Promise<PersistedCustodyRecord | undefined> {
    const raw = this.records.get(hex(handleId));
    return raw ? deserializeRecord(raw) : undefined;
  }

  async listRecords(): Promise<readonly PersistedCustodyRecord[]> {
    return [...this.records.values()].map(deserializeRecord);
  }

  async saveRecord(record: PersistedCustodyRecord): Promise<void> {
    this.records.set(hex(record.handleId), serializeRecord(record));
  }

  async deleteRecord(handleId: Uint8Array): Promise<void> {
    this.records.delete(hex(handleId));
  }

  /** Test helper: number of live durable records. */
  get size(): number {
    return this.records.size;
  }
}

function serializeRecord(record: PersistedCustodyRecord): SerializedRecord {
  return {
    handleId: hex(record.handleId),
    subjectKind: record.subjectKind,
    x: hex(record.publicKey.x),
    y: hex(record.publicKey.y),
    custodyClass: record.custodyClass,
    presenceMode: record.presenceMode,
    securityLevel: record.securityLevel,
    profile: record.profile,
    generation: record.generation.toString(),
    evidence: hex(record.evidence),
  };
}

function deserializeRecord(raw: SerializedRecord): PersistedCustodyRecord {
  return {
    handleId: fromHex(raw.handleId),
    subjectKind: raw.subjectKind,
    publicKey: { x: fromHex(raw.x), y: fromHex(raw.y) },
    custodyClass: raw.custodyClass,
    presenceMode: raw.presenceMode,
    securityLevel: raw.securityLevel,
    profile: raw.profile,
    generation: BigInt(raw.generation),
    evidence: fromHex(raw.evidence),
  };
}

// ---------------------------------------------------------------------------
// Conformance fake for the native module, backed by real WebCrypto P-256 keys.
// Non-extractable in spirit: the private CryptoKey is never exported. Keys live
// for the lifetime of the fake, which stands in for the OS keystore and so
// survives a provider "restart".
// ---------------------------------------------------------------------------

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_ORDER = P256_ORDER >> 1n;

export interface FakeRemoteIdentityCustodyModuleOptions {
  /** Override the attestation report per (profile, requireUserPresence). */
  readonly attestation?: (profile: string, requireUserPresence: boolean) => NativeAttestationReport;
  /**
   * Override the attestation a rotated key reports, given the previous key's
   * attestation. Defaults to preserving it (a faithful native `rotateP256`
   * recreates the key with the SAME profile/presence). Tests use this to force
   * a downgrade and assert the provider refuses it.
   */
  readonly rotateAttestation?: (previous: NativeAttestationReport) => NativeAttestationReport;
}

interface FakeKeyEntry {
  readonly privateKey: CryptoKey;
  readonly publicKey: RemoteIdentityP256PublicKeyV1;
  readonly attestation: NativeAttestationReport;
}

export class FakeRemoteIdentityCustodyModule implements RemoteIdentityCustodyModule {
  private readonly keys = new Map<string, FakeKeyEntry>();
  private readonly attestationFor: (
    profile: string,
    requireUserPresence: boolean,
  ) => NativeAttestationReport;
  private readonly rotateAttestationFor?: (
    previous: NativeAttestationReport,
  ) => NativeAttestationReport;

  constructor(options: FakeRemoteIdentityCustodyModuleOptions = {}) {
    this.attestationFor = options.attestation ?? defaultAttestation;
    this.rotateAttestationFor = options.rotateAttestation;
  }

  async generateP256(
    handleId: Uint8Array,
    profile: string,
    requireUserPresence: boolean,
  ): Promise<NativeGenerateResult> {
    const attestation = this.attestationFor(profile, requireUserPresence);
    return this.create(handleId, attestation);
  }

  async signP256(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array> {
    const entry = this.keys.get(hex(handleId));
    if (!entry) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    // WebCrypto ECDSA already returns P1363 (r || s); normalize to low-S here.
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        entry.privateKey,
        new Uint8Array(signingMessage),
      ),
    );
    return normalizeLowSP1363(raw);
  }

  async publicKey(
    handleId: Uint8Array,
  ): Promise<{ x: Uint8Array; y: Uint8Array; attestation: NativeAttestationReport }> {
    const entry = this.keys.get(hex(handleId));
    if (!entry) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    return { x: entry.publicKey.x, y: entry.publicKey.y, attestation: entry.attestation };
  }

  async rotateP256(handleId: Uint8Array, newHandleId: Uint8Array): Promise<NativeGenerateResult> {
    const entry = this.keys.get(hex(handleId));
    if (!entry) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    // Fresh key under the caller-supplied new handle; the old key is retained
    // until destroyed. A faithful native rotateP256 recovers the previous key's
    // profile/presence and recreates with the same guarantees (preserved here).
    const attestation = this.rotateAttestationFor
      ? this.rotateAttestationFor(entry.attestation)
      : entry.attestation;
    return this.create(newHandleId, attestation);
  }

  async destroyGeneration(handleId: Uint8Array): Promise<void> {
    if (!this.keys.delete(hex(handleId))) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
  }

  /** Test helper: number of live keys held by the fake keystore. */
  get size(): number {
    return this.keys.size;
  }

  /**
   * Test-only accessor for a handle's private `CryptoKey`, used to ASSERT it is
   * non-extractable (a real keystore key never leaves the device). It is not a
   * private-bytes export — the key is non-extractable, so exporting it rejects.
   */
  privateKeyHandleForTest(handleId: Uint8Array): CryptoKey | undefined {
    return this.keys.get(hex(handleId))?.privateKey;
  }

  private async create(
    handleId: Uint8Array,
    attestation: NativeAttestationReport,
  ): Promise<NativeGenerateResult> {
    // Non-extractable private key: a correct implementation can never export the
    // PKCS#8 private bytes, so the fake models the real keystore invariant.
    const keyPair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const publicKey: RemoteIdentityP256PublicKeyV1 = {
      x: base64UrlToBytes(jwk.x ?? ""),
      y: base64UrlToBytes(jwk.y ?? ""),
    };
    this.keys.set(hex(handleId), { privateKey: keyPair.privateKey, publicKey, attestation });
    const providerEvidence = fakeProviderEvidence(handleId, attestation);
    return { handleId: Uint8Array.from(handleId), publicKey, attestation, providerEvidence };
  }
}

function defaultAttestation(
  profile: string,
  requireUserPresence: boolean,
): NativeAttestationReport {
  const presence = (unattended: number): number =>
    requireUserPresence ? PresenceMode.user_presence_required : unattended;
  switch (profile) {
    case "ios-secure-enclave":
      return {
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: presence(PresenceMode.unattended_after_first_unlock),
        securityLevel: "secure_enclave",
        profile,
      };
    case "ios-keychain":
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: presence(PresenceMode.unattended_after_first_unlock),
        securityLevel: "keychain",
        profile,
      };
    case "android-strongbox":
      return {
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: presence(PresenceMode.unattended_unlocked_device),
        securityLevel: "strongbox",
        profile,
      };
    case "android-tee":
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: presence(PresenceMode.unattended_unlocked_device),
        securityLevel: "tee",
        profile,
      };
    default:
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: presence(PresenceMode.unattended_unlocked_device),
        securityLevel: "software",
        profile,
      };
  }
}

function fakeProviderEvidence(
  handleId: Uint8Array,
  attestation: NativeAttestationReport,
): Uint8Array {
  const header = new TextEncoder().encode(
    `flycockpit.fake-custody.v1\0${attestation.securityLevel}\0${attestation.profile}\0`,
  );
  const out = new Uint8Array(header.length + handleId.length);
  out.set(header);
  out.set(handleId, header.length);
  return out;
}

/**
 * Normalize a 64-byte P1363 signature to low-S. Zero-r, zero-s, or an
 * out-of-range r/s are corruption and are never normalized away.
 */
export function normalizeLowSP1363(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new RemoteNativeIdentityCustodyError("corrupted", "signature is not 64 bytes");
  }
  const r = bytesToBigInt(signature.subarray(0, 32));
  let s = bytesToBigInt(signature.subarray(32, 64));
  if (r === 0n || s === 0n || r >= P256_ORDER || s >= P256_ORDER) {
    throw new RemoteNativeIdentityCustodyError("corrupted", "signature component out of range");
  }
  if (s > P256_HALF_ORDER) {
    s = P256_ORDER - s;
  }
  const out = new Uint8Array(64);
  out.set(signature.subarray(0, 32), 0);
  out.set(bigIntToBytes(s, 32), 32);
  return out;
}

// --- byte helpers ----------------------------------------------------------

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function fromHex(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  return value;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
