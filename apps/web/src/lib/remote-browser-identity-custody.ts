/**
 * Browser-origin remote identity custody — an origin-bound, non-extractable,
 * durable P-256 signing custody with no private-key export.
 *
 * This adapter implements the shared `RemoteIdentityCustodyProviderV1` contract
 * from `@flycockpit/cockpit-protocol` (the identity foundation seam) and reports
 * the shared closed `CustodyClass` / `PresenceMode` discriminants. It owns only
 * the durable P-256 signing handle; the shared Rust-WASM Noise core (not this
 * provider) owns all per-child key agreement.
 *
 * Custody is `origin_protected`, never hardware- or OS-protected. The single
 * durable P-256 private handle is non-extractable; its loss requires
 * re-enrollment, not sync/backup/escrow. This adapter performs no key agreement
 * and no key derivation, and it never uses web storage or peer-connection
 * certificates for custody: the durable handle lives only in IndexedDB as a
 * non-extractable WebCrypto key. Private key bytes never cross this seam.
 */

import {
  CustodyClass,
  type CustodyEvidenceV1,
  decodeCustodyEvidence,
  encodeCustodyEvidence,
  PresenceMode,
  type RemoteIdentityCustodyGenerationV1,
  type RemoteIdentityCustodyPolicyRequestV1,
  type RemoteIdentityCustodyProviderV1,
  type RemoteIdentityCustodyReopenV1,
  type RemoteIdentityP256PublicKeyV1,
  remoteIdentitySha256,
  type SubjectKindV1,
} from "@flycockpit/cockpit-protocol";
import { extractRemoteBrowserIdentityP256PublicKey } from "./remote-browser-identity-public-key";

/** The custody class this provider reports: origin-bound only. */
export const REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS = CustodyClass.origin_protected;

/** The presence mode this provider reports. */
export const REMOTE_BROWSER_IDENTITY_PRESENCE_MODE = PresenceMode.unattended;

/** IndexedDB database name (origin-scoped). */
export const REMOTE_BROWSER_IDENTITY_DB_NAME = "flycockpit-remote-identity" as const;

/** IndexedDB object store name. */
export const REMOTE_BROWSER_IDENTITY_STORE = "p256-custody" as const;

/** The single durable-generation record key. */
export const REMOTE_BROWSER_IDENTITY_RECORD_KEY = "current-generation" as const;

/**
 * The monotonic generation high-water key. Its record is stored under a key
 * distinct from the generation record so that `destroy` — which deletes only
 * the generation record — never resets the high-water mark. A fresh generate
 * after destroy therefore still advances past every prior generation.
 */
export const REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY = "generation-sequence" as const;

/**
 * A fixed, domain-separated probe message used ONLY to bind a persisted public
 * key to its stored non-extractable private handle via a local sign+verify
 * round-trip. It never leaves the provider and is not a protocol message.
 */
const REMOTE_BROWSER_IDENTITY_PUBLIC_KEY_BINDING_PROBE = new TextEncoder().encode(
  "flycockpit.remote-browser-identity.public-key-binding-probe.v1",
);

/** A custody-provider failure. The provider completes capability proof
 * before any server allocation and returns an actionable typed failure; it
 * never generates a weaker replacement. */
export class RemoteBrowserIdentityCustodyError extends Error {
  readonly code:
    | "unsupported_engine"
    | "non_extractable_unavailable"
    | "not_found"
    | "storage_unavailable"
    | "private_bytes_not_exportable"
    | "origin_changed"
    | "corrupted"
    | "policy_denied";

  constructor(code: RemoteBrowserIdentityCustodyError["code"], message: string) {
    super(message);
    this.name = "RemoteBrowserIdentityCustodyError";
    this.code = code;
  }
}

/** The bounded public metadata persisted alongside the non-extractable handle. */
export interface RemoteBrowserIdentityPublicMetadata {
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly subjectKind: SubjectKindV1;
  // A bigint so the monotonic counter stays exact above Number.MAX_SAFE_INTEGER.
  readonly generation: bigint;
  readonly origin: string;
  readonly evidenceDigest: string;
}

/** The result of a capability probe. */
export interface RemoteBrowserIdentityCapability {
  readonly nonExtractableP256: boolean;
  readonly indexedDb: boolean;
  readonly supported: boolean;
}

/**
 * Feature-detect native WebCrypto non-extractable `ECDSA/P-256` before
 * enrollment. This probe generates a throwaway non-extractable key, verifies
 * it is non-extractable (the sole negative-proof key read in this module), then
 * discards it. It never persists anything.
 *
 * Returns an unsupported result when WebCrypto or non-extractable P-256 is
 * unavailable. Never substitutes a polyfill or an extractable key.
 */
export async function probeRemoteBrowserIdentityCapability(): Promise<RemoteBrowserIdentityCapability> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    return { nonExtractableP256: false, indexedDb: false, supported: false };
  }
  let nonExtractableP256 = false;
  try {
    const keyPair = await subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      /* extractable */ false,
      ["sign", "verify"],
    );
    nonExtractableP256 =
      !!keyPair.privateKey &&
      keyPair.privateKey.extractable === false &&
      (await subtle
        .exportKey("pkcs8", keyPair.privateKey)
        .then(() => false)
        .catch(() => true));
  } catch {
    nonExtractableP256 = false;
  }
  const indexedDb = typeof indexedDB !== "undefined";
  return {
    nonExtractableP256,
    indexedDb,
    supported: nonExtractableP256 && indexedDb,
  };
}

/** Open (or create) the IndexedDB database for durable P-256 custody. */
function openIdentityDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(
        new RemoteBrowserIdentityCustodyError("storage_unavailable", "IndexedDB is not available"),
      );
      return;
    }
    const request = indexedDB.open(REMOTE_BROWSER_IDENTITY_DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(REMOTE_BROWSER_IDENTITY_STORE)) {
        db.createObjectStore(REMOTE_BROWSER_IDENTITY_STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(
        new RemoteBrowserIdentityCustodyError(
          "storage_unavailable",
          `IndexedDB open failed: ${request.error?.message ?? "unknown"}`,
        ),
      );
  });
}

/** Lowercase-hex encode bytes (used only for bounded public metadata). */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Constant-shape byte equality for 16-byte handle ids. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Allocate a random, nonzero 16-byte durable handle id. */
function randomHandleId(): Uint8Array {
  const id = new Uint8Array(16);
  crypto.getRandomValues(id);
  if (id.every((b) => b === 0)) id[0] = 1;
  return id;
}

/** Deterministic provider-evidence bytes: an ASCII label, origin, generation. */
function buildProviderEvidence(origin: string, generation: bigint): Uint8Array {
  return new TextEncoder().encode(
    `flycockpit.remote-browser-identity.custody-evidence.v1|${origin}|generation=${generation}`,
  );
}

/**
 * Fail closed on a structurally invalid policy request BEFORE any key
 * allocation. A caller crossing the untyped runtime boundary can supply
 * `undefined`/`null`/`NaN` for `minCustodyClass` or a non-boolean for
 * `allowUserPresenceRequired`. Without this guard such a request bypasses the
 * `minCustodyClass > class` denial entirely — `undefined > 1`, `NaN > 1`, and
 * `null > 1` all evaluate to `false` — so the provider would mint an identity
 * against a policy it never validly evaluated. Requiring a finite, in-range
 * closed-enum class and a real boolean presence flag closes that hole.
 */
function validatePolicyRequest(policy: RemoteIdentityCustodyPolicyRequestV1): void {
  const minCustodyClass = policy?.minCustodyClass;
  if (
    typeof minCustodyClass !== "number" ||
    !Number.isInteger(minCustodyClass) ||
    minCustodyClass < CustodyClass.origin_protected ||
    minCustodyClass > CustodyClass.hardware_or_external
  ) {
    throw new RemoteBrowserIdentityCustodyError(
      "policy_denied",
      "policy.minCustodyClass must be a finite CustodyClass enum value",
    );
  }
  if (typeof policy.allowUserPresenceRequired !== "boolean") {
    throw new RemoteBrowserIdentityCustodyError(
      "policy_denied",
      "policy.allowUserPresenceRequired must be a boolean",
    );
  }
}

/** secp256r1 group order n and its floor(n/2), as bigints. */
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

function bytesToBigBe(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigToBytesBe(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Normalize a 64-byte P1363 (`r || s`) ECDSA/P-256 signature to low-S form.
 *
 * WebCrypto `sign` returns a valid P1363 signature but does NOT low-S-normalize
 * it, so roughly half of the signatures it produces have `s > n/2` and are
 * rejected by the shared possession-proof codec. This interprets `s` as a
 * big-endian integer and, when `s > n/2`, replaces it with `n - s` (which
 * preserves signature validity). It throws a typed `corrupted` error — never
 * returns a mangled signature — when `r`/`s` is zero or `r >= n` or `s >= n`.
 */
export function normalizeLowSP1363(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new RemoteBrowserIdentityCustodyError("corrupted", "signature must be 64 bytes");
  }
  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);
  const rValue = bytesToBigBe(r);
  const sValue = bytesToBigBe(s);
  // Reject an out-of-range r OR s. An `s >= n` must NEVER be "normalized": n - s
  // would be negative and produce malformed output, so it is corruption.
  if (rValue === 0n || sValue === 0n || rValue >= P256_N || sValue >= P256_N) {
    throw new RemoteBrowserIdentityCustodyError("corrupted", "unusable ECDSA signature");
  }
  const normalizedS = sValue > P256_HALF_N ? P256_N - sValue : sValue;
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(bigToBytesBe(normalizedS, 32), 32);
  return out;
}

/** The persisted durable-generation record: the non-extractable CryptoKey
 * handle, the durable handle id, the public-key coordinates, and bounded public
 * metadata. Private key bytes are NEVER persisted. */
export interface RemoteBrowserIdentityPersistedRecord {
  readonly handleId: Uint8Array;
  readonly keyHandle: CryptoKey;
  readonly publicKeyX: Uint8Array;
  readonly publicKeyY: Uint8Array;
  readonly metadata: RemoteBrowserIdentityPublicMetadata;
}

/** The persisted monotonic generation high-water record. */
export interface RemoteBrowserIdentitySequenceRecord {
  // A bigint so `current + 1` stays exact above Number.MAX_SAFE_INTEGER.
  readonly highWater: bigint;
}

/** The union of values the durable store may hold. */
export type RemoteBrowserIdentityStoredRecord =
  | RemoteBrowserIdentityPersistedRecord
  | RemoteBrowserIdentitySequenceRecord;

function isGenerationRecord(
  value: RemoteBrowserIdentityStoredRecord,
): value is RemoteBrowserIdentityPersistedRecord {
  return "keyHandle" in value;
}

/** A store operation seam injected for tests. It carries both the generation
 * record and the monotonic sequence record under their distinct keys. */
export interface RemoteBrowserIdentityStore {
  open(): Promise<unknown>;
  get(db: unknown, key: string): Promise<RemoteBrowserIdentityStoredRecord | undefined>;
  put(db: unknown, key: string, value: RemoteBrowserIdentityStoredRecord): Promise<void>;
  delete(db: unknown, key: string): Promise<void>;
  /**
   * Atomically reserve the next monotonic generation and return it. The read of
   * the current high-water mark and the write of `+1` happen inside ONE
   * IndexedDB `readwrite` transaction, which IndexedDB serializes against every
   * other transaction touching the store. This closes the read/modify/write
   * race where two tabs both read high-water 0 and both persist 1 — producing a
   * duplicate `(certificateId, generation)` pair. `destroy` never touches the
   * sequence key, so the reserved value is never reused.
   */
  reserveGeneration(db: unknown): Promise<bigint>;
}

/** The default IndexedDB-backed store. */
export const defaultRemoteBrowserIdentityStore: RemoteBrowserIdentityStore = {
  async open() {
    return openIdentityDb();
  },
  async get(db, key) {
    return new Promise((resolve, reject) => {
      const database = db as IDBDatabase;
      const tx = database.transaction(REMOTE_BROWSER_IDENTITY_STORE, "readonly");
      const store = tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE);
      const request = store.get(key);
      request.onsuccess = () =>
        resolve(request.result as RemoteBrowserIdentityStoredRecord | undefined);
      request.onerror = () =>
        reject(
          new RemoteBrowserIdentityCustodyError(
            "storage_unavailable",
            `IndexedDB get failed: ${request.error?.message ?? "unknown"}`,
          ),
        );
    });
  },
  async put(db, key, value) {
    return new Promise((resolve, reject) => {
      const database = db as IDBDatabase;
      const tx = database.transaction(REMOTE_BROWSER_IDENTITY_STORE, "readwrite");
      tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE).put(value, key);
      // Resolve only when the TRANSACTION COMMITS, not when the request
      // succeeds. A quota/abort after the request succeeds still rolls the write
      // back, so treating request-success as durable would cache a lost record.
      tx.oncomplete = () => resolve();
      failWriteTransaction(tx, "put", reject);
    });
  },
  async delete(db, key) {
    return new Promise((resolve, reject) => {
      const database = db as IDBDatabase;
      const tx = database.transaction(REMOTE_BROWSER_IDENTITY_STORE, "readwrite");
      tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE).delete(key);
      tx.oncomplete = () => resolve();
      failWriteTransaction(tx, "delete", reject);
    });
  },
  async reserveGeneration(db) {
    return new Promise((resolve, reject) => {
      const database = db as IDBDatabase;
      // ONE readwrite transaction: read the sequence, then write +1. IndexedDB
      // serializes readwrite transactions over the same store, so concurrent
      // reservations cannot observe the same high-water mark. The reservation is
      // durable only once the transaction COMMITS — a rolled-back reservation is
      // never handed out (which would let its generation be reused).
      const tx = database.transaction(REMOTE_BROWSER_IDENTITY_STORE, "readwrite");
      const store = tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE);
      const getRequest = store.get(REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
      let next = 0n;
      getRequest.onsuccess = () => {
        const current = getRequest.result as RemoteBrowserIdentitySequenceRecord | undefined;
        next = (current?.highWater ?? 0n) + 1n;
        store.put({ highWater: next }, REMOTE_BROWSER_IDENTITY_SEQUENCE_KEY);
      };
      tx.oncomplete = () => resolve(next);
      failWriteTransaction(tx, "reserveGeneration", reject);
    });
  },
};

/** Reject on transaction abort or error (rolls the write back). */
function failWriteTransaction(
  tx: IDBTransaction,
  op: string,
  reject: (error: RemoteBrowserIdentityCustodyError) => void,
): void {
  const fail = () =>
    reject(
      new RemoteBrowserIdentityCustodyError(
        "storage_unavailable",
        `IndexedDB ${op} did not commit: ${tx.error?.message ?? "aborted"}`,
      ),
    );
  tx.onabort = fail;
  tx.onerror = fail;
}

/** Options for the browser identity custody provider. */
export interface RemoteBrowserIdentityCustodyProviderOptions {
  readonly origin: string;
  readonly store?: RemoteBrowserIdentityStore;
  /** Injected capability override (tests). When omitted, the provider
   * probes the live browser engine. */
  readonly capability?: RemoteBrowserIdentityCapability;
  /** Injected clock seam for evidence `observedAt`. Never `Date.now()` in
   * tests; the default reads the wall clock. */
  readonly now?: () => bigint;
  /** Injected failure hook exercised at the persistence boundary. */
  readonly onBeforePersist?: () => Promise<void>;
}

/**
 * The browser-origin durable-P-256 custody provider.
 *
 * Implements the shared `RemoteIdentityCustodyProviderV1` contract: durable
 * non-extractable P-256 signing handles that never return private bytes and
 * report `origin_protected` / `unattended`. Private bytes never cross this seam.
 */
export class RemoteBrowserIdentityCustodyProvider implements RemoteIdentityCustodyProviderV1 {
  private readonly origin: string;
  private readonly store: RemoteBrowserIdentityStore;
  private readonly capability: RemoteBrowserIdentityCapability | undefined;
  private readonly now: () => bigint;
  private readonly onBeforePersist: () => Promise<void>;
  private db: unknown | undefined;

  constructor(options: RemoteBrowserIdentityCustodyProviderOptions) {
    this.origin = options.origin;
    this.store = options.store ?? defaultRemoteBrowserIdentityStore;
    this.capability = options.capability;
    this.now = options.now ?? (() => BigInt(Date.now()));
    this.onBeforePersist = options.onBeforePersist ?? (async () => {});
  }

  /** Ensure the storage backend is open. */
  async ensureOpen(): Promise<unknown> {
    if (this.db === undefined) {
      this.db = await this.store.open();
    }
    return this.db;
  }

  /** Generate a non-extractable P-256 key pair and read its public coordinates,
   * failing typed before any storage write on capability/custody shortfall. */
  private async mintKeyPair(): Promise<{
    keyHandle: CryptoKey;
    publicKey: RemoteIdentityP256PublicKeyV1;
  }> {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      /* extractable */ false,
      ["sign", "verify"],
    );
    if (keyPair.privateKey.extractable) {
      throw new RemoteBrowserIdentityCustodyError(
        "non_extractable_unavailable",
        "generated P-256 key is extractable; rejected",
      );
    }
    const publicKey = await extractRemoteBrowserIdentityP256PublicKey(keyPair.publicKey);
    return { keyHandle: keyPair.privateKey, publicKey };
  }

  /** Build, validate, and codec-round-trip the custody evidence for a record. */
  private async buildEvidence(
    subjectKind: SubjectKindV1,
    handleId: Uint8Array,
    generation: bigint,
  ): Promise<{ evidence: CustodyEvidenceV1; evidenceDigestHex: string }> {
    const providerEvidence = buildProviderEvidence(this.origin, generation);
    const evidenceDigest = await remoteIdentitySha256(providerEvidence);
    const input: CustodyEvidenceV1 = {
      subjectKind,
      subjectId: handleId,
      generation,
      custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
      presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
      providerEvidence,
      evidenceDigest,
      observedAt: this.now(),
    };
    const evidence = decodeCustodyEvidence(encodeCustodyEvidence(input));
    return { evidence, evidenceDigestHex: toHex(evidenceDigest) };
  }

  /**
   * Generate a fresh durable non-extractable P-256 signing identity. Enforces
   * the requested policy and detects a non-extractable-incapable engine before
   * any server allocation; never generates a weaker replacement. Private bytes
   * never cross this seam.
   */
  async generate(
    subjectKind: SubjectKindV1,
    policy: RemoteIdentityCustodyPolicyRequestV1,
  ): Promise<RemoteIdentityCustodyGenerationV1> {
    // Fail closed on a structurally invalid policy BEFORE any key allocation.
    validatePolicyRequest(policy);
    const capability = this.capability ?? (await probeRemoteBrowserIdentityCapability());
    if (!capability.supported) {
      throw new RemoteBrowserIdentityCustodyError(
        "unsupported_engine",
        "browser engine does not support non-extractable ECDSA P-256 + IndexedDB",
      );
    }
    if (policy.minCustodyClass > REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS) {
      throw new RemoteBrowserIdentityCustodyError(
        "policy_denied",
        "browser custody is origin_protected and cannot satisfy a higher custody class",
      );
    }
    const { keyHandle, publicKey } = await this.mintKeyPair();
    const handleId = randomHandleId();
    const db = await this.ensureOpen();
    // Atomically reserve the next generation (single IndexedDB transaction), so
    // concurrent tabs can never mint the same (certificateId, generation).
    const generation = await this.store.reserveGeneration(db);
    const { evidence, evidenceDigestHex } = await this.buildEvidence(
      subjectKind,
      handleId,
      generation,
    );
    const record: RemoteBrowserIdentityPersistedRecord = {
      handleId,
      keyHandle,
      publicKeyX: publicKey.x,
      publicKeyY: publicKey.y,
      metadata: {
        custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
        presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
        subjectKind,
        generation,
        origin: this.origin,
        evidenceDigest: evidenceDigestHex,
      },
    };
    // The sequence was already persisted by reserveGeneration; only the durable
    // generation record remains to write.
    await this.onBeforePersist();
    await this.store.put(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY, record);
    return {
      handleId,
      publicKey,
      custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
      presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
      evidence,
    };
  }

  /** Reopen the durable generation record, validating custody invariants and
   * the caller-supplied handle id, without ever returning private bytes. */
  private async reopenRecord(handleId: Uint8Array): Promise<RemoteBrowserIdentityPersistedRecord> {
    const db = await this.ensureOpen();
    const persisted = await this.store.get(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!persisted || !isGenerationRecord(persisted)) {
      throw new RemoteBrowserIdentityCustodyError(
        "not_found",
        "no durable P-256 generation record found",
      );
    }
    if (persisted.keyHandle.extractable) {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted key handle is extractable; rejected",
      );
    }
    if (persisted.metadata.origin !== this.origin) {
      throw new RemoteBrowserIdentityCustodyError(
        "origin_changed",
        "persisted handle origin does not match current origin",
      );
    }
    if (!bytesEqual(persisted.handleId, handleId)) {
      throw new RemoteBrowserIdentityCustodyError(
        "not_found",
        "durable handle id does not match the persisted record",
      );
    }
    // Reconstruct and validate the persisted metadata against the fixed browser
    // contract and the ACTUAL key — never trust the stored bytes. A tampered
    // IndexedDB record could otherwise claim a stronger custody class or a
    // presence mode the browser cannot provide, or advertise a public key that
    // does not correspond to the stored private handle.
    await this.validatePersistedRecord(persisted);
    return persisted;
  }

  /**
   * Validate a persisted record's untrusted metadata: the custody/presence
   * discriminants must equal the fixed browser contract, the generation must be
   * a real monotonic bigint, and the advertised public key must actually
   * correspond to the stored non-extractable private handle (proven by a
   * sign+verify round-trip, since the private bytes can never be exported).
   * Any mismatch is `corrupted` — a downgrade or a substituted key is never
   * reported as a genuine hardware identity.
   */
  private async validatePersistedRecord(
    record: RemoteBrowserIdentityPersistedRecord,
  ): Promise<void> {
    if (
      record.metadata.custodyClass !== REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS ||
      record.metadata.presenceMode !== REMOTE_BROWSER_IDENTITY_PRESENCE_MODE
    ) {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted custody discriminants do not match the fixed browser contract",
      );
    }
    if (typeof record.metadata.generation !== "bigint" || record.metadata.generation < 1n) {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted generation is not a valid monotonic counter",
      );
    }
    if (record.publicKeyX.length !== 32 || record.publicKeyY.length !== 32) {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted public key coordinates are not 32 bytes",
      );
    }
    // Re-derive the binding from the actual key: import the advertised public
    // key and verify a signature the stored PRIVATE handle produces over a fixed
    // probe. If the public key was swapped, verification fails.
    let publicCryptoKey: CryptoKey;
    try {
      const uncompressed = new Uint8Array(65);
      uncompressed[0] = 0x04;
      uncompressed.set(record.publicKeyX, 1);
      uncompressed.set(record.publicKeyY, 33);
      publicCryptoKey = await crypto.subtle.importKey(
        "raw",
        uncompressed,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
    } catch {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted public key is not a valid P-256 point",
      );
    }
    const probe = REMOTE_BROWSER_IDENTITY_PUBLIC_KEY_BINDING_PROBE;
    const probeSignature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      record.keyHandle,
      probe,
    );
    const bound = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicCryptoKey,
      probeSignature,
      probe,
    );
    if (!bound) {
      throw new RemoteBrowserIdentityCustodyError(
        "corrupted",
        "persisted public key does not correspond to the stored private handle",
      );
    }
  }

  async reopen(handleId: Uint8Array): Promise<RemoteIdentityCustodyReopenV1> {
    const record = await this.reopenRecord(handleId);
    return {
      handleId: record.handleId,
      publicKey: { x: record.publicKeyX, y: record.publicKeyY },
      custodyClass: record.metadata.custodyClass,
      presenceMode: record.metadata.presenceMode,
    };
  }

  /**
   * Load the handle for signing by ALWAYS re-reading the persisted record and
   * validating it — never trusting the in-memory cache. There is a single
   * `current-generation` record, so a concurrent/other provider instance can
   * overwrite it; a cached key whose record was replaced must NOT keep signing a
   * live untracked identity. `reopenRecord` fails closed (`not_found`) when the
   * persisted record's handle no longer matches the requested one.
   */
  private async loadHandle(handleId: Uint8Array): Promise<RemoteBrowserIdentityPersistedRecord> {
    return this.reopenRecord(handleId);
  }

  /**
   * Rotate the durable handle to a fresh non-extractable P-256 key and the next
   * monotonic generation, consuming the persisted sequence. The old private key
   * is destroyed only after the new record is committed; a failure at the
   * persistence boundary exposes only the complete old generation.
   */
  async rotate(handleId: Uint8Array): Promise<RemoteIdentityCustodyGenerationV1> {
    const existing = await this.reopenRecord(handleId);
    const { keyHandle, publicKey } = await this.mintKeyPair();
    const db = await this.ensureOpen();
    const generation = await this.store.reserveGeneration(db);
    const { evidence, evidenceDigestHex } = await this.buildEvidence(
      existing.metadata.subjectKind,
      existing.handleId,
      generation,
    );
    const record: RemoteBrowserIdentityPersistedRecord = {
      handleId: existing.handleId,
      keyHandle,
      publicKeyX: publicKey.x,
      publicKeyY: publicKey.y,
      metadata: {
        custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
        presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
        subjectKind: existing.metadata.subjectKind,
        generation,
        origin: this.origin,
        evidenceDigest: evidenceDigestHex,
      },
    };
    // The sequence was already persisted by reserveGeneration.
    await this.onBeforePersist();
    await this.store.put(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY, record);
    return {
      handleId: existing.handleId,
      publicKey,
      custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
      presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
      evidence,
    };
  }

  /** Destroy the durable handle and its private key irreversibly. The monotonic
   * high-water record is deliberately never deleted. */
  async destroy(handleId: Uint8Array): Promise<void> {
    const db = await this.ensureOpen();
    const persisted = await this.store.get(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (persisted && isGenerationRecord(persisted) && !bytesEqual(persisted.handleId, handleId)) {
      throw new RemoteBrowserIdentityCustodyError(
        "not_found",
        "durable handle id does not match the persisted record",
      );
    }
    await this.store.delete(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY);
  }

  /**
   * Sign the possession-proof signing message (`domain || unsigned`) with the
   * durable handle, returning a low-S P1363 signature over `SHA-256(message)`.
   * WebCrypto hashes the message; the raw signature is low-S-normalized before
   * it is returned. Never returns private bytes.
   */
  async signPossessionProof(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array> {
    const record = await this.loadHandle(handleId);
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      record.keyHandle,
      new Uint8Array(signingMessage),
    );
    return normalizeLowSP1363(new Uint8Array(signature));
  }

  /** Sign the enrollment-confirmation signing message. Same low-S contract. */
  async signEnrollmentConfirmation(
    handleId: Uint8Array,
    signingMessage: Uint8Array,
  ): Promise<Uint8Array> {
    return this.signPossessionProof(handleId, signingMessage);
  }

  get custodyClass(): number {
    return REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS;
  }

  get presenceMode(): number {
    return REMOTE_BROWSER_IDENTITY_PRESENCE_MODE;
  }
}
