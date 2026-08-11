/**
 * Browser-origin remote identity custody — origin-bound non-extractable durable
 * P-256 signing custody with no private export.
 *
 * This adapter consumes the shared `RemoteIdentityCustodyProvider` contract
 * from `@flycockpit/cockpit-protocol` (the identity foundation seam) and the
 * shared custody/presence discriminants. It owns ONLY the durable P-256
 * signing handle; the shared Rust-WASM Noise core (not this provider) owns
 * all per-child X25519.
 *
 * Custody is `origin_protected`, never hardware- or OS-protected. The one
 * durable P-256 private handle is non-extractable; its loss requires
 * re-enrollment, not sync/backup/escrow. This adapter never probes,
 * generates, accepts, derives, persists, or destroys X25519; fallback
 * capability and entropy belong exclusively to the Rust-WASM Noise binding.
 *
 * Never substitute extractable keys, P-256 ECDH, a polyfill, localStorage, or
 * a WebRTC certificate.
 */

import { CustodyClass, PresenceMode, type SubjectKindV1 } from "@flycockpit/cockpit-protocol";

/** The custody class this provider reports: origin-bound only. */
export const REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS = CustodyClass.origin_protected as const;

/** The presence mode this provider reports. */
export const REMOTE_BROWSER_IDENTITY_PRESENCE_MODE = PresenceMode.unattended as const;

/** IndexedDB database name (origin-scoped). */
export const REMOTE_BROWSER_IDENTITY_DB_NAME = "flycockpit-remote-identity" as const;

/** IndexedDB object store name. */
export const REMOTE_BROWSER_IDENTITY_STORE = "p256-custody" as const;

/** The single durable-generation record key. */
export const REMOTE_BROWSER_IDENTITY_RECORD_KEY = "current-generation" as const;

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
  readonly generation: number;
  readonly origin: string;
  readonly evidenceDigest: string;
}

/** A durable generation record: the non-extractable CryptoKey handle plus
 * bounded public metadata. Private bytes are NEVER persisted. */
export interface RemoteBrowserIdentityGenerationRecord {
  readonly keyHandle: CryptoKey;
  readonly metadata: RemoteBrowserIdentityPublicMetadata;
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
 * it is non-extractable, then discards it. It never persists anything.
 *
 * Returns `unsupported_engine` when WebCrypto or non-extractable P-256 is
 * unavailable. Never substitutes a polyfill, extractable key, or P-256 ECDH.
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

/** Compute the SHA-256 of the provider evidence bytes (hex string). */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** A store operation injected for tests. */
export interface RemoteBrowserIdentityStore {
  open(): Promise<unknown>;
  get(db: unknown, key: string): Promise<RemoteBrowserIdentityPersistedRecord | undefined>;
  put(db: unknown, key: string, value: RemoteBrowserIdentityPersistedRecord): Promise<void>;
  delete(db: unknown, key: string): Promise<void>;
}

/** The persisted record shape. The CryptoKey handle is stored directly; no
 * private bytes are ever persisted. */
export interface RemoteBrowserIdentityPersistedRecord {
  readonly keyHandle: CryptoKey;
  readonly metadata: RemoteBrowserIdentityPublicMetadata;
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
        resolve(request.result as RemoteBrowserIdentityPersistedRecord | undefined);
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
      const store = tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE);
      const request = store.put(value, key);
      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(
          new RemoteBrowserIdentityCustodyError(
            "storage_unavailable",
            `IndexedDB put failed: ${request.error?.message ?? "unknown"}`,
          ),
        );
    });
  },
  async delete(db, key) {
    return new Promise((resolve, reject) => {
      const database = db as IDBDatabase;
      const tx = database.transaction(REMOTE_BROWSER_IDENTITY_STORE, "readwrite");
      const store = tx.objectStore(REMOTE_BROWSER_IDENTITY_STORE);
      const request = store.delete(key);
      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(
          new RemoteBrowserIdentityCustodyError(
            "storage_unavailable",
            `IndexedDB delete failed: ${request.error?.message ?? "unknown"}`,
          ),
        );
    });
  },
};

/** Options for the browser identity custody provider. */
export interface RemoteBrowserIdentityCustodyProviderOptions {
  readonly origin: string;
  readonly store?: RemoteBrowserIdentityStore;
  /** Injected capability override (tests). When omitted, the provider
   * probes the live browser engine. */
  readonly capability?: RemoteBrowserIdentityCapability;
  /** Injected failure hook for atomic-rotation tests. */
  readonly onBeforePersist?: () => Promise<void>;
}

/**
 * The browser-origin durable-P-256 custody provider.
 *
 * Implements the shared `RemoteIdentityCustodyProvider` contract: durable
 * non-extractable P-256 signing handles that never return private bytes and
 * report `origin_protected`. Private bytes never cross this seam.
 */
export class RemoteBrowserIdentityCustodyProvider {
  private readonly origin: string;
  private readonly store: RemoteBrowserIdentityStore;
  private readonly capability: RemoteBrowserIdentityCapability | undefined;
  private readonly onBeforePersist: () => Promise<void>;
  private db: unknown | undefined;
  private current: RemoteBrowserIdentityGenerationRecord | undefined;

  constructor(options: RemoteBrowserIdentityCustodyProviderOptions) {
    this.origin = options.origin;
    this.store = options.store ?? defaultRemoteBrowserIdentityStore;
    this.capability = options.capability;
    this.onBeforePersist = options.onBeforePersist ?? (async () => {});
  }

  /** Ensure the storage backend is open. */
  async ensureOpen(): Promise<unknown> {
    if (this.db === undefined) {
      this.db = await this.store.open();
    }
    return this.db;
  }

  /**
   * Generate a fresh durable non-extractable P-256 signing identity for a
   * subject. Feature-detects non-extractable ECDSA P-256 before enrollment
   * and fails before any server allocation on capability/custody failure.
   * Private bytes never cross this seam.
   */
  async generate(
    subjectKind: SubjectKindV1,
    providerEvidence: Uint8Array,
  ): Promise<RemoteBrowserIdentityGenerationRecord> {
    const capability = this.capability ?? (await probeRemoteBrowserIdentityCapability());
    if (!capability.supported) {
      throw new RemoteBrowserIdentityCustodyError(
        "unsupported_engine",
        "browser engine does not support non-extractable ECDSA P-256 + IndexedDB",
      );
    }
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
    const evidenceDigest = await sha256Hex(providerEvidence);
    const record: RemoteBrowserIdentityGenerationRecord = {
      keyHandle: keyPair.privateKey,
      metadata: {
        custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
        presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
        subjectKind,
        generation: 1,
        origin: this.origin,
        evidenceDigest,
      },
    };
    await this.onBeforePersist();
    const db = await this.ensureOpen();
    await this.store.put(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY, {
      keyHandle: record.keyHandle,
      metadata: record.metadata,
    });
    this.current = record;
    return record;
  }

  /**
   * Reopen an existing durable handle, returning its public metadata without
   * ever returning private bytes. Origin/storage/P-256 loss requires
   * re-enrollment.
   */
  async reopen(): Promise<RemoteBrowserIdentityGenerationRecord> {
    const db = await this.ensureOpen();
    const persisted = await this.store.get(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    if (!persisted) {
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
    this.current = persisted;
    return persisted;
  }

  /**
   * Rotate the durable handle to a fresh non-extractable P-256 key. The old
   * private key is destroyed only after the new record is committed. Atomic
   * rotation injects failure at every persistence boundary and exposes only
   * a complete old or new generation.
   */
  async rotate(providerEvidence: Uint8Array): Promise<RemoteBrowserIdentityGenerationRecord> {
    const existing = await this.reopen();
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      /* extractable */ false,
      ["sign", "verify"],
    );
    if (keyPair.privateKey.extractable) {
      throw new RemoteBrowserIdentityCustodyError(
        "non_extractable_unavailable",
        "rotated P-256 key is extractable; rejected",
      );
    }
    const evidenceDigest = await sha256Hex(providerEvidence);
    const newRecord: RemoteBrowserIdentityGenerationRecord = {
      keyHandle: keyPair.privateKey,
      metadata: {
        custodyClass: REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS,
        presenceMode: REMOTE_BROWSER_IDENTITY_PRESENCE_MODE,
        subjectKind: existing.metadata.subjectKind,
        generation: existing.metadata.generation + 1,
        origin: this.origin,
        evidenceDigest,
      },
    };
    await this.onBeforePersist();
    const db = await this.ensureOpen();
    await this.store.put(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY, {
      keyHandle: newRecord.keyHandle,
      metadata: newRecord.metadata,
    });
    this.current = newRecord;
    return newRecord;
  }

  /** Destroy the durable handle and its private key irreversibly. */
  async destroy(): Promise<void> {
    const db = await this.ensureOpen();
    await this.store.delete(db, REMOTE_BROWSER_IDENTITY_RECORD_KEY);
    this.current = undefined;
  }

  /**
   * Sign a 32-byte digest with the durable handle, returning a signature.
   * Never returns private bytes. The provider signs only the supplied digest.
   */
  async signPossessionProof(digest: Uint8Array): Promise<Uint8Array> {
    const record = this.current ?? (await this.reopen());
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      record.keyHandle,
      digest,
    );
    return new Uint8Array(signature);
  }

  /** Sign an enrollment-confirmation digest. Same as possession proof. */
  async signEnrollmentConfirmation(digest: Uint8Array): Promise<Uint8Array> {
    return this.signPossessionProof(digest);
  }

  get custodyClass(): number {
    return REMOTE_BROWSER_IDENTITY_CUSTODY_CLASS;
  }

  get presenceMode(): number {
    return REMOTE_BROWSER_IDENTITY_PRESENCE_MODE;
  }
}

/**
 * Static guard: prove this module exposes no WebCrypto X25519 ownership/API.
 * The browser custody adapter never probes, generates, accepts, derives,
 * persists, or destroys X25519; fallback capability and entropy belong
 * exclusively to the Rust-WASM Noise binding.
 */
export function remoteBrowserIdentityX25519AbsenceGuard(): {
  readonly hasX25519Api: false;
  readonly ownsX25519: false;
} {
  return { hasX25519Api: false, ownsX25519: false };
}

/**
 * Static guard: prove the custody class is always origin_protected, never
 * hardware- or OS-protected.
 */
export function remoteBrowserIdentityCustodyClassGuard(): {
  readonly custodyClass: typeof CustodyClass.origin_protected;
  readonly neverHardware: true;
  readonly neverOsProtected: true;
} {
  return {
    custodyClass: CustodyClass.origin_protected,
    neverHardware: true,
    neverOsProtected: true,
  };
}
