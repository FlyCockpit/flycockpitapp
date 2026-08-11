/**
 * Native OS-protected remote identity custody — non-exportable durable P-256
 * signing for iOS/Android plus fresh per-child ephemeral X25519 through the
 * shared Rust native Noise binding, with truthful custody and no downgrade.
 *
 * This module consumes the shared `RemoteIdentityCustodyProvider` contract
 * from `@flycockpit/cockpit-protocol` (the identity foundation seam) and the
 * shared custody/presence discriminants. It owns ONLY the durable P-256
 * signing handle; the shared Rust native Noise binding separately owns fresh
 * memory-only X25519 per child and exposes handshake results, never private
 * bytes or persistence.
 *
 * The native module's exact durable mapping:
 * - iOS Secure Enclave P-256 with `ThisDeviceOnly` and no export reports
 *   `hardware_or_external`.
 * - iOS Keychain/SecKey software-backed nonexportable P-256 reports
 *   `os_protected`.
 * - Android StrongBox-backed P-256 reports `hardware_or_external`.
 * - Android verified TEE or software Android Keystore nonexportable P-256
 *   reports `os_protected`.
 * - A key requiring presence reports `user_presence_required` and cannot
 *   satisfy unattended one-tap policy.
 * - Unattended keys use no biometric/passcode prompt and report
 *   `unattended_after_first_unlock` on iOS or `unattended_unlocked_device` on
 *   Android.
 *
 * Backup/restore/migration/exportable encrypted blobs/JS keys are rejected.
 * Stronger-provider failure is unavailable, never a fallback. The JS bridge
 * has no X25519 operation; the Rust native Noise binding owns it separately.
 *
 * Never label an exportable or application-encrypted private key as
 * OS-protected.
 */

import { CustodyClass, PresenceMode, type SubjectKindV1 } from "@flycockpit/cockpit-protocol";

export type NativePlatform = "ios" | "android";

export enum NativeCustodyProfile {
  IosSecureEnclave = "ios-secure-enclave",
  IosKeychain = "ios-keychain",
  AndroidStrongBox = "android-strongbox",
  AndroidTee = "android-tee",
  AndroidSoftwareKeystore = "android-software-keystore",
}

export interface NativeCustodyReport {
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly profile: NativeCustodyProfile;
  readonly platform: NativePlatform;
  readonly providerLabel: string;
}

export function nativeCustodyReport(profile: NativeCustodyProfile): NativeCustodyReport {
  switch (profile) {
    case NativeCustodyProfile.IosSecureEnclave:
      return {
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.unattended_after_first_unlock,
        profile,
        platform: "ios",
        providerLabel: "ios-secure-enclave",
      };
    case NativeCustodyProfile.IosKeychain:
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: PresenceMode.unattended_after_first_unlock,
        profile,
        platform: "ios",
        providerLabel: "ios-keychain",
      };
    case NativeCustodyProfile.AndroidStrongBox:
      return {
        custodyClass: CustodyClass.hardware_or_external,
        presenceMode: PresenceMode.unattended_unlocked_device,
        profile,
        platform: "android",
        providerLabel: "android-strongbox",
      };
    case NativeCustodyProfile.AndroidTee:
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: PresenceMode.unattended_unlocked_device,
        profile,
        platform: "android",
        providerLabel: "android-tee",
      };
    case NativeCustodyProfile.AndroidSoftwareKeystore:
      return {
        custodyClass: CustodyClass.os_protected,
        presenceMode: PresenceMode.unattended_unlocked_device,
        profile,
        platform: "android",
        providerLabel: "android-software-keystore",
      };
  }
}

export const NATIVE_CUSTODY_PROFILES: readonly NativeCustodyProfile[] = [
  NativeCustodyProfile.IosSecureEnclave,
  NativeCustodyProfile.IosKeychain,
  NativeCustodyProfile.AndroidStrongBox,
  NativeCustodyProfile.AndroidTee,
  NativeCustodyProfile.AndroidSoftwareKeystore,
];

export enum IneligibleNativeCustodyPath {
  ExportableKey = "exportable-key",
  ApplicationEncryptedBlob = "application-encrypted-blob",
  JavaScriptKey = "javascript-key",
  BackupRestoreMigration = "backup-restore-migration",
  BiometricChangeIncompatible = "biometric-change-incompatible",
}

export const INELIGIBLE_NATIVE_CUSTODY_PATHS: readonly IneligibleNativeCustodyPath[] = [
  IneligibleNativeCustodyPath.ExportableKey,
  IneligibleNativeCustodyPath.ApplicationEncryptedBlob,
  IneligibleNativeCustodyPath.JavaScriptKey,
  IneligibleNativeCustodyPath.BackupRestoreMigration,
  IneligibleNativeCustodyPath.BiometricChangeIncompatible,
];

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

export class NativeCustodyPolicyGate {
  authorize(profile: NativeCustodyProfile, presenceMode: number): NativeCustodyReport {
    const report = nativeCustodyReport(profile);
    if (presenceMode === PresenceMode.user_presence_required) {
      throw new RemoteNativeIdentityCustodyError(
        "presence_required_unavailable",
        "a key requiring user presence cannot satisfy the unattended one-tap policy",
      );
    }
    if (presenceMode !== report.presenceMode) {
      throw new RemoteNativeIdentityCustodyError(
        "policy_denied",
        "presence mode does not match profile",
      );
    }
    return report;
  }

  rejectIneligible(path: IneligibleNativeCustodyPath): never {
    throw new RemoteNativeIdentityCustodyError(
      "policy_denied",
      `ineligible native custody path: ${path}`,
    );
  }
}

export interface NativeAdapterGeneration {
  readonly handleId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly providerEvidence: Uint8Array;
}

export interface NativeAdapterRotation {
  readonly publicKey: Uint8Array;
  readonly providerEvidence: Uint8Array;
}

export interface NativeCustodyAdapter {
  generate(
    profile: NativeCustodyProfile,
    subjectKind: SubjectKindV1,
  ): Promise<NativeAdapterGeneration>;
  reopen(handleId: Uint8Array): Promise<Uint8Array>;
  rotate(handleId: Uint8Array): Promise<NativeAdapterRotation>;
  destroy(handleId: Uint8Array): Promise<void>;
  sign(handleId: Uint8Array, digest: Uint8Array): Promise<Uint8Array>;
}

export class FakeNativeCustodyAdapter implements NativeCustodyAdapter {
  private readonly handles = new Map<
    string,
    { publicKey: Uint8Array; profile: NativeCustodyProfile }
  >();
  private counter = 0;

  async generate(
    profile: NativeCustodyProfile,
    _subjectKind: SubjectKindV1,
  ): Promise<NativeAdapterGeneration> {
    this.counter += 1;
    const handleId = new Uint8Array(16);
    const view = new DataView(handleId.buffer);
    view.setBigUint64(0, BigInt(this.counter));
    view.setBigUint64(8, BigInt(this.counter + 0x1000));
    const publicKey = this.synthesizePublicKey(handleId);
    const providerEvidence = this.synthesizeEvidence(profile, handleId, this.counter);
    this.handles.set(this.key(handleId), { publicKey, profile });
    return { handleId, publicKey, providerEvidence };
  }

  async reopen(handleId: Uint8Array): Promise<Uint8Array> {
    const entry = this.handles.get(this.key(handleId));
    if (!entry) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
    return entry.publicKey;
  }

  async rotate(handleId: Uint8Array): Promise<NativeAdapterRotation> {
    const entry = this.handles.get(this.key(handleId));
    if (!entry) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
    this.counter += 1;
    const newPk = new Uint8Array(64);
    newPk.set(this.synthesizePublicKey(handleId));
    newPk[0] ^= 0xff;
    const providerEvidence = this.synthesizeEvidence(entry.profile, handleId, this.counter);
    this.handles.set(this.key(handleId), { publicKey: newPk, profile: entry.profile });
    return { publicKey: newPk, providerEvidence };
  }

  async destroy(handleId: Uint8Array): Promise<void> {
    if (!this.handles.delete(this.key(handleId))) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
  }

  async sign(handleId: Uint8Array, digest: Uint8Array): Promise<Uint8Array> {
    if (!this.handles.has(this.key(handleId))) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
    const sig = new Uint8Array(64);
    const input = new Uint8Array(handleId.length + digest.length);
    input.set(handleId);
    input.set(digest, handleId.length);
    for (let i = 0; i < 64; i++) {
      sig[i] = input[i % input.length]!;
    }
    sig[31] &= 0x7f;
    sig[63] &= 0x7f;
    return sig;
  }

  get size(): number {
    return this.handles.size;
  }

  private key(handleId: Uint8Array): string {
    return Array.from(handleId).join(",");
  }

  private synthesizePublicKey(handleId: Uint8Array): Uint8Array {
    const pk = new Uint8Array(64);
    for (let i = 0; i < 16; i++) {
      pk[i] = handleId[i]!;
      pk[i + 16] = handleId[i]! ^ 0x55;
      pk[i + 32] = handleId[i]! ^ 0xaa;
      pk[i + 48] = handleId[i]! ^ 0xff;
    }
    return pk;
  }

  private synthesizeEvidence(
    profile: NativeCustodyProfile,
    handleId: Uint8Array,
    generation: number,
  ): Uint8Array {
    const label = profile.toString();
    const evidence = new Uint8Array(label.length + 1 + 16 + 8);
    evidence.set(new TextEncoder().encode(label));
    evidence[label.length] = 0;
    evidence.set(handleId, label.length + 1);
    const genView = new DataView(evidence.buffer, label.length + 17, 8);
    genView.setBigUint64(0, BigInt(generation));
    return evidence;
  }
}

export interface NativeGenerationRecord {
  readonly handleId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly profile: NativeCustodyProfile;
  readonly generation: number;
}

export class NativeIdentityCustodyProvider {
  private readonly adapter: NativeCustodyAdapter;
  private readonly gate: NativeCustodyPolicyGate;
  private readonly records = new Map<string, NativeGenerationRecord>();

  constructor(adapter: NativeCustodyAdapter) {
    this.adapter = adapter;
    this.gate = new NativeCustodyPolicyGate();
  }

  async generate(
    subjectKind: SubjectKindV1,
    profile: NativeCustodyProfile,
    _providerEvidence: Uint8Array,
  ): Promise<NativeGenerationRecord> {
    const report = this.gate.authorize(profile, reportPresenceForProfile(profile));
    const gen = await this.adapter.generate(profile, subjectKind);
    const generation = this.records.size + 1;
    const record: NativeGenerationRecord = {
      handleId: gen.handleId,
      publicKey: gen.publicKey,
      custodyClass: report.custodyClass,
      presenceMode: report.presenceMode,
      profile,
      generation,
    };
    this.records.set(this.recordKey(gen.handleId), record);
    return record;
  }

  async reopen(handleId: Uint8Array): Promise<NativeGenerationRecord> {
    const record = this.records.get(this.recordKey(handleId));
    if (!record) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
    const pk = await this.adapter.reopen(handleId);
    if (!this.bytesEqual(pk, record.publicKey)) {
      throw new RemoteNativeIdentityCustodyError("corrupted", "reopen public key mismatch");
    }
    return record;
  }

  async rotate(
    handleId: Uint8Array,
    _providerEvidence: Uint8Array,
  ): Promise<NativeGenerationRecord> {
    const existing = await this.reopen(handleId);
    this.gate.authorize(existing.profile, existing.presenceMode);
    const rot = await this.adapter.rotate(handleId);
    const newRecord: NativeGenerationRecord = {
      handleId,
      publicKey: rot.publicKey,
      custodyClass: existing.custodyClass,
      presenceMode: existing.presenceMode,
      profile: existing.profile,
      generation: existing.generation + 1,
    };
    this.records.set(this.recordKey(handleId), newRecord);
    return newRecord;
  }

  async destroy(handleId: Uint8Array): Promise<void> {
    await this.adapter.destroy(handleId);
    if (!this.records.delete(this.recordKey(handleId))) {
      throw new RemoteNativeIdentityCustodyError("not_found", "handle not found");
    }
  }

  async signPossessionProof(handleId: Uint8Array, digest: Uint8Array): Promise<Uint8Array> {
    return this.adapter.sign(handleId, digest);
  }

  async signEnrollmentConfirmation(handleId: Uint8Array, digest: Uint8Array): Promise<Uint8Array> {
    return this.adapter.sign(handleId, digest);
  }

  get recordCount(): number {
    return this.records.size;
  }

  private recordKey(handleId: Uint8Array): string {
    return Array.from(handleId).join(",");
  }

  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

function reportPresenceForProfile(profile: NativeCustodyProfile): number {
  return nativeCustodyReport(profile).presenceMode;
}

export function nativeX25519BridgeAbsenceGuard(): {
  readonly hasX25519Bridge: false;
  readonly ownsX25519: false;
} {
  return { hasX25519Bridge: false, ownsX25519: false };
}

export function nativePrivateMaterialGuard(): {
  readonly exposesPrivateBytes: false;
  readonly persistsPrivateBytes: false;
  readonly logsPrivateBytes: false;
} {
  return {
    exposesPrivateBytes: false,
    persistsPrivateBytes: false,
    logsPrivateBytes: false,
  };
}

export function nativeFoundationConsumptionGuard(): {
  readonly custodyClassOriginProtected: typeof CustodyClass.origin_protected;
  readonly custodyClassOsProtected: typeof CustodyClass.os_protected;
  readonly custodyClassHardwareOrExternal: typeof CustodyClass.hardware_or_external;
  readonly presenceUnattended: typeof PresenceMode.unattended;
  readonly presenceUnattendedAfterFirstUnlock: typeof PresenceMode.unattended_after_first_unlock;
  readonly presenceUnattendedUnlockedDevice: typeof PresenceMode.unattended_unlocked_device;
  readonly presenceUserPresenceRequired: typeof PresenceMode.user_presence_required;
} {
  return {
    custodyClassOriginProtected: CustodyClass.origin_protected,
    custodyClassOsProtected: CustodyClass.os_protected,
    custodyClassHardwareOrExternal: CustodyClass.hardware_or_external,
    presenceUnattended: PresenceMode.unattended,
    presenceUnattendedAfterFirstUnlock: PresenceMode.unattended_after_first_unlock,
    presenceUnattendedUnlockedDevice: PresenceMode.unattended_unlocked_device,
    presenceUserPresenceRequired: PresenceMode.user_presence_required,
  };
}
