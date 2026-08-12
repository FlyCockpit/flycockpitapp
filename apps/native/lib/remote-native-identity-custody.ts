/**
 * Native OS-protected remote identity custody — the app-layer provider over the
 * local Expo Module `RemoteIdentityCustody`.
 *
 * The provider consumes the module's typed interface (opaque handles, public
 * keys, low-S P1363 signatures, and platform attestation reports — never
 * private bytes) and enforces the caller's requested custody policy against the
 * module's REPORTED attestation. Classification is report-driven: the provider
 * never decides custody from a local profile constant, so a module that reports
 * a software keystore cannot pass a hardware policy.
 *
 * Durability is owned by an injectable {@link NativeCustodyStore}: a persisted
 * monotonic generation high-water mark (never reset by destroy) and a durable
 * record per handle. Because the store is injected, a "restart" is just a new
 * provider over the same store. Process death is injectable via
 * {@link ProcessDeathInjector} so tests can assert that a crash between key
 * creation and record persist never exposes mixed state.
 *
 * The Rust-native Noise binding separately owns fresh per-child X25519; this
 * module has no X25519 operation and holds only the durable P-256 signing
 * handle.
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
import type {
  NativeAttestationReport,
  NativeGenerateResult,
  NativeSecurityLevel,
  RemoteIdentityCustodyModule,
} from "../modules/remote-identity-custody";

export class RemoteNativeIdentityCustodyError extends Error {
  readonly code:
    | "unsupported_platform"
    | "provider_unavailable"
    | "policy_denied"
    | "not_found"
    | "private_bytes_not_exportable"
    | "presence_required_unavailable"
    | "corrupted";

  constructor(code: RemoteNativeIdentityCustodyError["code"], message: string) {
    super(message);
    this.name = "RemoteNativeIdentityCustodyError";
    this.code = code;
  }
}

/**
 * A durable record persisted per handle. In production this is backed by the
 * platform durable store (iOS non-synchronizable ThisDeviceOnly Keychain
 * generic-password metadata; Android app-private SharedPreferences); in tests
 * it is the in-memory store below. The evidence is the codec-validated
 * {@link CustodyEvidenceV1} bytes, so the codec is exercised on every restart.
 */
export interface PersistedCustodyRecord {
  readonly handleId: Uint8Array;
  readonly subjectKind: SubjectKindV1;
  readonly publicKey: RemoteIdentityP256PublicKeyV1;
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly securityLevel: NativeSecurityLevel;
  readonly profile: string;
  readonly generation: bigint;
  readonly evidence: Uint8Array;
}

/**
 * The injectable durable store, owned by the platform module in production
 * (iOS non-synchronizable ThisDeviceOnly Keychain generic-password item;
 * Android app-private SharedPreferences). The high-water mark is a monotonic
 * generation counter that `destroy` never resets; `generate` and `rotate` both
 * consume the next value.
 */
/**
 * A durable write-ahead marker for an in-flight generate/rotate. It is written
 * BEFORE the record it will finalize, so a crash mid-operation is RECONCILED on
 * the next startup (the orphan/superseded key is retired) rather than silently
 * skipped. `supersedes` is set for a rotation: once the new record is durable,
 * the superseded old key+record are retired.
 */
export interface PendingCustodyOp {
  readonly handleId: Uint8Array;
  readonly generation: bigint;
  readonly supersedes?: Uint8Array;
}

export interface NativeCustodyStore {
  /**
   * Atomically reserve the next monotonic generation and return it. The read of
   * the current high-water mark and the write of `+1` MUST be a single atomic
   * operation (native atomic increment / one durable transaction) so two
   * concurrent providers can never observe the same value and mint a duplicate
   * `(certificateId, generation)` pair.
   */
  reserveNextGeneration(): Promise<bigint>;
  /** Read the current high-water mark (diagnostics/tests). Never resets it. */
  loadHighWaterMark(): Promise<bigint>;
  /** Write-ahead: mark an in-flight generate/rotate before its record persists. */
  savePendingOp(op: PendingCustodyOp): Promise<void>;
  /** All uncommitted pending ops, for startup reconciliation. */
  loadPendingOps(): Promise<readonly PendingCustodyOp[]>;
  /** Clear a pending op once its operation is fully committed or reconciled. */
  clearPendingOp(handleId: Uint8Array): Promise<void>;
  loadRecord(handleId: Uint8Array): Promise<PersistedCustodyRecord | undefined>;
  listRecords(): Promise<readonly PersistedCustodyRecord[]>;
  saveRecord(record: PersistedCustodyRecord): Promise<void>;
  deleteRecord(handleId: Uint8Array): Promise<void>;
}

/** Injectable process-death points, in provider write order. */
export type ProcessDeathPoint =
  | "after_reserve_generation"
  | "after_pending_marker"
  | "after_key_create"
  | "before_record_persist"
  | "after_record_persist";

export interface ProcessDeathInjector {
  reached(point: ProcessDeathPoint): void | Promise<void>;
}

export interface NativeIdentityCustodyProviderOptions {
  readonly module: RemoteIdentityCustodyModule;
  readonly store: NativeCustodyStore;
  /** Monotonic wall clock for evidence `observedAt`. */
  readonly clock: () => bigint;
  /** The native profile string to request (e.g. "ios-secure-enclave"). */
  readonly profile: string;
  /** Whether the requested native key is user-presence-gated. */
  readonly requireUserPresence?: boolean;
  readonly deathInjector?: ProcessDeathInjector;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Fail closed on a structurally invalid policy request BEFORE any key
 * allocation. A caller crossing the untyped runtime boundary can supply
 * `undefined`/`null`/`NaN` for `minCustodyClass` or a non-boolean for
 * `allowUserPresenceRequired`. Without this guard `report.custodyClass <
 * undefined` (and `< NaN`, `< null`→`< 0`) short-circuits the shortfall denial
 * to `false`, and `!policy.allowUserPresenceRequired` on a non-boolean silently
 * mis-evaluates the presence gate — so a spoofed-looking request could mint an
 * identity that was never validly evaluated. Requiring a finite in-range
 * closed-enum class and a real boolean presence flag closes that hole.
 */
function validateNativePolicyRequest(policy: RemoteIdentityCustodyPolicyRequestV1): void {
  const minCustodyClass = policy?.minCustodyClass;
  if (
    typeof minCustodyClass !== "number" ||
    !Number.isInteger(minCustodyClass) ||
    minCustodyClass < CustodyClass.origin_protected ||
    minCustodyClass > CustodyClass.hardware_or_external
  ) {
    throw new RemoteNativeIdentityCustodyError(
      "policy_denied",
      "policy.minCustodyClass must be a finite CustodyClass enum value",
    );
  }
  if (typeof policy.allowUserPresenceRequired !== "boolean") {
    throw new RemoteNativeIdentityCustodyError(
      "policy_denied",
      "policy.allowUserPresenceRequired must be a boolean",
    );
  }
}

export class NativeIdentityCustodyProvider implements RemoteIdentityCustodyProviderV1 {
  private readonly module: RemoteIdentityCustodyModule;
  private readonly store: NativeCustodyStore;
  private readonly clock: () => bigint;
  private readonly profile: string;
  private readonly requireUserPresence: boolean;
  private readonly deathInjector?: ProcessDeathInjector;
  private reconciled = false;

  constructor(options: NativeIdentityCustodyProviderOptions) {
    this.module = options.module;
    this.store = options.store;
    this.clock = options.clock;
    this.profile = options.profile;
    this.requireUserPresence = options.requireUserPresence ?? false;
    this.deathInjector = options.deathInjector;
  }

  async generate(
    subjectKind: SubjectKindV1,
    policy: RemoteIdentityCustodyPolicyRequestV1,
  ): Promise<RemoteIdentityCustodyGenerationV1> {
    // Fail closed on a structurally invalid policy BEFORE any key allocation.
    validateNativePolicyRequest(policy);
    // Retire any orphan/superseded keys left by a prior crash before proceeding.
    await this.ensureReconciled();
    // Reserve the next generation FIRST (atomic), so a crash can never let a
    // later generation reuse this number.
    const generation = await this.reserveGeneration();
    await this.death("after_reserve_generation");

    // TRUE write-ahead: the provider assigns the handle and records the INTENT
    // BEFORE the key exists. A crash anywhere after this — including between the
    // marker and key creation, or after key creation before the record — is
    // reconcilable, because the marker already names the (to-be) durable key.
    const handleId = randomHandle();
    await this.store.savePendingOp({ handleId, generation });
    await this.death("after_pending_marker");

    const native = await this.module.generateP256(handleId, this.profile, this.requireUserPresence);
    await this.death("after_key_create");
    await this.assertReturnedHandle(native.handleId, handleId, generation);
    try {
      // Classification comes ONLY from the module's attestation, which must be
      // internally consistent and bound to the REQUESTED profile.
      this.enforcePolicy(native.attestation, policy, this.profile);
    } catch (error) {
      // Policy shortfall / spoofed report: retire the just-created key. Only
      // clear the marker if the key is confirmed gone; otherwise leave it for
      // reconciliation to retry (never a leaked live key).
      await this.retireAndClear(handleId);
      throw error;
    }

    const { evidence, encoded } = await this.buildEvidence(subjectKind, native, generation);
    const record = this.toRecord(subjectKind, native, generation, encoded);

    await this.death("before_record_persist");
    await this.store.saveRecord(record);
    await this.death("after_record_persist");
    // The operation is complete; clear the write-ahead marker.
    await this.store.clearPendingOp(handleId);

    return this.toGeneration(record, evidence);
  }

  async reopen(handleId: Uint8Array): Promise<RemoteIdentityCustodyReopenV1> {
    await this.ensureReconciled();
    const record = await this.loadValidatedRecord(handleId);
    if (!record) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    // Fail closed: confirm the durable key STILL EXISTS in the keystore and its
    // public key + attestation match the record. After key loss (app reinstall,
    // biometric enrollment change, keystore invalidation) the metadata record
    // can survive while the key is gone; we must not report a usable identity
    // that would only fail at signing time.
    let live: { x: Uint8Array; y: Uint8Array; attestation: NativeAttestationReport };
    try {
      live = await this.module.publicKey(handleId);
    } catch {
      throw new RemoteNativeIdentityCustodyError(
        "not_found",
        "durable key is no longer present in the keystore",
      );
    }
    if (!bytesEqual(live.x, record.publicKey.x) || !bytesEqual(live.y, record.publicKey.y)) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "keystore public key does not match the durable record",
      );
    }
    // Every path that accepts a live report runs the SAME exact-equality binding.
    this.assertLiveReportMatches(live.attestation, record);
    return {
      handleId: record.handleId,
      publicKey: record.publicKey,
      custodyClass: record.custodyClass,
      presenceMode: record.presenceMode,
    };
  }

  async rotate(handleId: Uint8Array): Promise<RemoteIdentityCustodyGenerationV1> {
    await this.ensureReconciled();
    const existing = await this.loadValidatedRecord(handleId);
    if (!existing) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }

    const generation = await this.reserveGeneration();
    await this.death("after_reserve_generation");

    // TRUE write-ahead: assign the new handle and record the intent (with
    // `supersedes`) BEFORE creating the new key.
    const newHandleId = randomHandle();
    await this.store.savePendingOp({ handleId: newHandleId, generation, supersedes: handleId });
    await this.death("after_pending_marker");

    const native = await this.module.rotateP256(handleId, newHandleId);
    await this.death("after_key_create");
    await this.assertReturnedHandle(native.handleId, newHandleId, generation);
    try {
      // The rotated key must EXACTLY match the existing identity (profile,
      // securityLevel, custodyClass, presenceMode) AND the configured profile —
      // no downgrade, no upgrade, no profile drift, no reconstruction under a
      // different configured profile.
      this.assertLiveReportMatches(native.attestation, existing);
    } catch (error) {
      // Retire the staged new key and (if gone) clear the marker; the old key +
      // record are untouched, so the identity survives intact.
      await this.retireAndClear(newHandleId);
      throw error;
    }

    const { evidence, encoded } = await this.buildEvidence(
      existing.subjectKind,
      native,
      generation,
    );
    const record = this.toRecord(existing.subjectKind, native, generation, encoded);

    // Publish the new generation only after it is durable, then retire the old.
    await this.death("before_record_persist");
    await this.store.saveRecord(record);
    await this.death("after_record_persist");

    await this.module.destroyGeneration(handleId);
    await this.store.deleteRecord(handleId);
    await this.store.clearPendingOp(newHandleId);

    return this.toGeneration(record, evidence);
  }

  async destroy(handleId: Uint8Array): Promise<void> {
    await this.ensureReconciled();
    const record = await this.loadValidatedRecord(handleId);
    if (!record) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    await this.module.destroyGeneration(handleId);
    // The high-water mark is deliberately NOT reset: a later generate must
    // never reuse this handle's generation number.
    await this.store.deleteRecord(handleId);
  }

  async signPossessionProof(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array> {
    return this.sign(handleId, signingMessage);
  }

  async signEnrollmentConfirmation(
    handleId: Uint8Array,
    signingMessage: Uint8Array,
  ): Promise<Uint8Array> {
    return this.sign(handleId, signingMessage);
  }

  private async sign(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array> {
    await this.ensureReconciled();
    const record = await this.loadValidatedRecord(handleId);
    if (!record) {
      throw new RemoteNativeIdentityCustodyError("not_found", "durable handle not found");
    }
    return this.module.signP256(handleId, signingMessage);
  }

  // --- internals -----------------------------------------------------------

  private async reserveGeneration(): Promise<bigint> {
    // A single atomic store reservation — never a read/modify/write across
    // separate operations, which could let two providers reserve the same value.
    return this.store.reserveNextGeneration();
  }

  /**
   * Discover and retire orphan/superseded durable keys left by a crash mid
   * generate/rotate, so no mixed state survives a restart. Runs once per
   * provider before its first operation.
   */
  private async ensureReconciled(): Promise<void> {
    if (this.reconciled) {
      return;
    }
    // Set the latch ONLY after reconciliation completes without throwing. If a
    // transient read/cleanup failure aborts it, the latch stays false and the
    // next operation retries reconciliation (never silently skips it).
    await this.reconcile();
    this.reconciled = true;
  }

  private async reconcile(): Promise<void> {
    // ANY failure — loadPendingOps, a per-marker loadRecord, or a per-marker
    // retire — PROPAGATES. `ensureReconciled` then leaves the latch UNSET, so the
    // next operation retries reconciliation rather than proceeding while an
    // orphan/rotation marker is still unresolved.
    for (const op of await this.store.loadPendingOps()) {
      // loadRecord is NOT caught: an unreadable record means reconciliation did
      // not complete, so we must fail (and retry) rather than skip the marker.
      const finalRecord = await this.store.loadRecord(op.handleId);
      if (!finalRecord) {
        // The key was created but its record never persisted → orphan. Clear the
        // marker ONLY if the key is confirmed gone; otherwise FAIL (marker kept)
        // so the next reconcile retries — never a leaked key with no marker.
        if (!(await this.retireKey(op.handleId))) {
          throw new RemoteNativeIdentityCustodyError(
            "provider_unavailable",
            "reconciliation could not retire an orphan key; will retry",
          );
        }
        await this.store.clearPendingOp(op.handleId);
      } else if (op.supersedes) {
        // A rotation whose NEW record is durable: finish retiring the OLD one.
        // Same rule — only advance once the old key is confirmed gone.
        if (!(await this.retireKey(op.supersedes))) {
          throw new RemoteNativeIdentityCustodyError(
            "provider_unavailable",
            "reconciliation could not retire a superseded key; will retry",
          );
        }
        await this.store.deleteRecord(op.supersedes);
        await this.store.clearPendingOp(op.handleId);
      } else {
        // A completed generate whose marker was never cleared → just clear it.
        await this.store.clearPendingOp(op.handleId);
      }
    }
  }

  /**
   * Destroy a durable key, returning whether it is CONFIRMED GONE. A successful
   * destroy or an already-not-found key returns `true`; a transient keystore
   * failure returns `false` so the caller keeps the write-ahead marker for retry
   * (never clears a marker while a live key may still exist).
   */
  private async retireKey(handleId: Uint8Array): Promise<boolean> {
    try {
      await this.module.destroyGeneration(handleId);
      return true;
    } catch (error) {
      if (error instanceof RemoteNativeIdentityCustodyError && error.code === "not_found") {
        return true;
      }
      return false;
    }
  }

  /** Retire a key and clear its marker only if the key is confirmed gone. */
  private async retireAndClear(handleId: Uint8Array): Promise<void> {
    if (await this.retireKey(handleId)) {
      await this.store.clearPendingOp(handleId);
    }
  }

  /**
   * Verify the module returned the SAME handle the provider assigned and wrote
   * into the write-ahead marker. A lying/buggy module returning a different
   * handle would store the record under one handle while reconciliation covers
   * another — an undiscoverable orphan. Reject before any record is built:
   * retire the key it actually created and clear our (now-meaningless) marker.
   */
  private async assertReturnedHandle(
    returned: Uint8Array,
    expected: Uint8Array,
    generation: bigint,
  ): Promise<void> {
    if (bytesEqual(returned, expected)) {
      return;
    }
    // The module created a key under a handle we did not request. Never orphan
    // the ACTUAL live key: only drop the marker for `expected` (which covers a
    // key that was never created) once the RETURNED key is destroy-confirmed. If
    // destroying it fails transiently, re-point the recovery marker at the
    // RETURNED handle so restart reconciliation retires it.
    if (!(await this.retireKey(returned))) {
      await this.store.savePendingOp({ handleId: returned, generation });
    }
    await this.store.clearPendingOp(expected);
    throw new RemoteNativeIdentityCustodyError(
      "corrupted",
      "native module returned a handle different from the one requested",
    );
  }

  /**
   * The single load funnel: read the persisted record and validate it before
   * anything trusts it. Decodes the persisted evidence through the production
   * codec and cross-checks it against the metadata; converts any
   * malformed/mismatched/inconsistent state to a `corrupted` fail-closed error.
   */
  private async loadValidatedRecord(
    handleId: Uint8Array,
  ): Promise<PersistedCustodyRecord | undefined> {
    let record: PersistedCustodyRecord | undefined;
    try {
      record = await this.store.loadRecord(handleId);
    } catch {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "persisted custody record could not be read",
      );
    }
    if (!record) {
      return undefined;
    }
    // Metadata discriminants must be valid closed enums and internally
    // consistent (securityLevel <-> custodyClass).
    this.validateReport(record);
    // Bind EVERY record-consuming path (reopen, rotate, sign, destroy) to this
    // provider's CONFIGURED profile: a provider configured for one profile must
    // never operate on — or keep using — another profile's durable identity.
    if (record.profile !== this.profile) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        "durable record profile does not match the configured provider profile",
      );
    }
    // Decode the persisted evidence and cross-check every bound field.
    let evidence: CustodyEvidenceV1;
    try {
      evidence = decodeCustodyEvidence(record.evidence);
    } catch {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "persisted custody evidence failed to decode",
      );
    }
    if (
      evidence.subjectKind !== record.subjectKind ||
      evidence.generation !== record.generation ||
      evidence.custodyClass !== record.custodyClass ||
      evidence.presenceMode !== record.presenceMode ||
      !bytesEqual(evidence.subjectId, record.handleId)
    ) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "persisted custody evidence does not match its metadata",
      );
    }
    return record;
  }

  /**
   * The single EXACT-equality binding for a LIVE report accepted on an existing
   * identity (rotate, reopen): the report's profile, securityLevel, custodyClass,
   * and presenceMode must equal the persisted record EXACTLY, and the profile
   * must also equal this provider's CONFIGURED profile. No "stronger is fine"
   * ordering, no profile drift, no reconstruction under a different profile.
   */
  private assertLiveReportMatches(
    report: NativeAttestationReport,
    record: PersistedCustodyRecord,
  ): void {
    this.validateReport(report);
    if (report.profile !== record.profile || report.profile !== this.profile) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        "attested profile does not match the durable record or the configured profile",
      );
    }
    if (
      report.securityLevel !== record.securityLevel ||
      report.custodyClass !== record.custodyClass ||
      report.presenceMode !== record.presenceMode
    ) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "attested report does not exactly match the durable record",
      );
    }
  }

  private enforcePolicy(
    report: NativeAttestationReport,
    policy: RemoteIdentityCustodyPolicyRequestV1,
    expectedProfile: string,
  ): void {
    this.validateReport(report);
    // Bind the report to the REQUESTED profile: a report for a different profile
    // than the one asked for is rejected, never trusted.
    if (report.profile !== expectedProfile) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        "attested profile does not match the requested profile",
      );
    }
    if (
      report.presenceMode === PresenceMode.user_presence_required &&
      !policy.allowUserPresenceRequired
    ) {
      throw new RemoteNativeIdentityCustodyError(
        "presence_required_unavailable",
        "attested key requires user presence but the requested policy forbids it",
      );
    }
    // Bind the caller's requested presence to the attested presence mode on
    // GENERATE: when `requireUserPresence` was requested, the module MUST have
    // honored it. A key requested presence-gated but attesting as unattended is a
    // SILENT DOWNGRADE — the caller would believe every signature needs a live
    // user when in fact none does. It is denied, never reported as satisfying the
    // request. (The opposite direction — an unattended request that attests as
    // presence-required — is governed by `allowUserPresenceRequired` above, which
    // lets a caller tolerate but not require presence gating.)
    const reportedPresenceRequired = report.presenceMode === PresenceMode.user_presence_required;
    if (this.requireUserPresence && !reportedPresenceRequired) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        "requested a user-presence-gated key but the attested key is unattended",
      );
    }
    if (report.custodyClass < policy.minCustodyClass) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        `attested custody class ${report.custodyClass} is below the requested minimum ${policy.minCustodyClass}`,
      );
    }
  }

  private validateReport(report: NativeAttestationReport): void {
    if (
      !Number.isInteger(report.custodyClass) ||
      report.custodyClass < CustodyClass.origin_protected ||
      report.custodyClass > CustodyClass.hardware_or_external
    ) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "attestation reported an out-of-range custody class",
      );
    }
    if (
      !Number.isInteger(report.presenceMode) ||
      report.presenceMode < PresenceMode.unattended ||
      report.presenceMode > PresenceMode.user_presence_required
    ) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "attestation reported an out-of-range presence mode",
      );
    }
    // The custody class must be internally consistent with the reported security
    // level, so a spoofed `{ custodyClass: hardware, securityLevel: software }`
    // bridge report cannot masquerade as hardware custody.
    const expected = expectedCustodyClass(report.securityLevel);
    if (expected === undefined) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        `attestation reported an unknown security level: ${String(report.securityLevel)}`,
      );
    }
    if (report.custodyClass !== expected) {
      throw new RemoteNativeIdentityCustodyError(
        "corrupted",
        "attested custody class is inconsistent with the reported security level",
      );
    }
  }

  private async buildEvidence(
    subjectKind: SubjectKindV1,
    native: NativeGenerateResult,
    generation: bigint,
  ): Promise<{ evidence: CustodyEvidenceV1; encoded: Uint8Array }> {
    // Provider evidence comes ONLY from the module's attestation output, never
    // from caller bytes; the digest is SHA-256 of exactly those bytes.
    const providerEvidence = native.providerEvidence;
    const evidenceDigest = await remoteIdentitySha256(providerEvidence);
    const evidence: CustodyEvidenceV1 = {
      subjectKind,
      subjectId: native.handleId,
      generation,
      custodyClass: native.attestation.custodyClass,
      presenceMode: native.attestation.presenceMode,
      providerEvidence,
      evidenceDigest,
      observedAt: this.clock(),
    };
    // encodeCustodyEvidence validates the digest, the 16-byte nonzero subjectId,
    // and the closed discriminants; a bad report throws here.
    const encoded = encodeCustodyEvidence(evidence);
    return { evidence, encoded };
  }

  private toRecord(
    subjectKind: SubjectKindV1,
    native: NativeGenerateResult,
    generation: bigint,
    encodedEvidence: Uint8Array,
  ): PersistedCustodyRecord {
    return {
      handleId: native.handleId,
      subjectKind,
      publicKey: native.publicKey,
      custodyClass: native.attestation.custodyClass,
      presenceMode: native.attestation.presenceMode,
      securityLevel: native.attestation.securityLevel,
      profile: native.attestation.profile,
      generation,
      evidence: encodedEvidence,
    };
  }

  private toGeneration(
    record: PersistedCustodyRecord,
    evidence: CustodyEvidenceV1,
  ): RemoteIdentityCustodyGenerationV1 {
    return {
      handleId: record.handleId,
      publicKey: record.publicKey,
      custodyClass: record.custodyClass,
      presenceMode: record.presenceMode,
      evidence,
    };
  }

  private async death(point: ProcessDeathPoint): Promise<void> {
    if (this.deathInjector) {
      await this.deathInjector.reached(point);
    }
  }
}

/**
 * The custody class a given security level is allowed to claim. StrongBox and
 * Secure Enclave are `hardware_or_external`; TEE, software keystore, and iOS
 * Keychain are `os_protected`. Any other value is unknown (fail closed).
 */
function expectedCustodyClass(securityLevel: NativeSecurityLevel | string): number | undefined {
  switch (securityLevel) {
    case "secure_enclave":
    case "strongbox":
      return CustodyClass.hardware_or_external;
    case "keychain":
    case "tee":
    case "software":
      return CustodyClass.os_protected;
    default:
      return undefined;
  }
}

// --- byte helpers ----------------------------------------------------------

function randomHandle(): Uint8Array {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  if (bytes.every((b) => b === 0)) {
    bytes[0] = 1;
  }
  return bytes;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
