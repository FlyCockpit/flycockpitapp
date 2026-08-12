/**
 * Typed JS interface for the local Expo Module `RemoteIdentityCustody` (New
 * Architecture, expo-modules-core). The native module owns a durable,
 * non-exportable P-256 signing key per handle inside the platform keystore
 * (iOS Secure Enclave / Keychain, Android Keystore / StrongBox). JS receives
 * ONLY opaque handles, public keys, low-S P1363 signatures, and platform
 * attestation reports — never private key bytes.
 *
 * Exactly FIVE native methods are exposed: `generateP256`, `signP256`,
 * `publicKey`, `rotateP256`, `destroyGeneration`. The Swift and Kotlin
 * implementations are compiled only in CI/EAS; on this workspace they are
 * exercised by a source-scan test. The conformance fake in
 * `apps/native/lib/remote-native-identity-custody.ts` implements this exact
 * interface with real WebCrypto P-256 keys.
 */
// `requireNativeModule` is re-exported by the `expo` package (which owns
// `expo-modules-core`); importing it from `expo` keeps resolution working
// without adding `expo-modules-core` as a direct dependency.
import { requireNativeModule } from "expo";

/** The platform security level backing a durable handle, reported by the OS. */
export type NativeSecurityLevel = "strongbox" | "tee" | "software" | "secure_enclave" | "keychain";

/**
 * The attestation report the native module derives from the created key's real
 * platform metadata — never from caller-supplied bytes. `custodyClass` and
 * `presenceMode` are the foundation-owned closed discriminants
 * (`CustodyClass` / `PresenceMode` from `@flycockpit/cockpit-protocol`).
 */
export interface NativeAttestationReport {
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly securityLevel: NativeSecurityLevel;
  readonly profile: string;
}

/** A durable P-256 public key in uncompressed affine coordinates (each 32 bytes). */
export interface NativeP256PublicKey {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
}

/** The result of `generateP256` / `rotateP256`: a fresh durable handle. */
export interface NativeGenerateResult {
  readonly handleId: Uint8Array;
  readonly publicKey: NativeP256PublicKey;
  readonly attestation: NativeAttestationReport;
  readonly providerEvidence: Uint8Array;
}

/** The result of `publicKey`: the public coordinates plus a fresh attestation. */
export interface NativePublicKeyResult {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
  readonly attestation: NativeAttestationReport;
}

/**
 * The exact native surface. Both the compiled native module and the conformance
 * fake implement this interface with identical semantics.
 */
export interface RemoteIdentityCustodyModule {
  /**
   * Create a fresh durable non-exportable P-256 key in the platform keystore
   * under the CALLER-SUPPLIED `handleId` (its keystore tag/alias), for the
   * requested `profile`, optionally gated on user presence. The caller assigns
   * the handle so it can be written to a durable write-ahead marker BEFORE the
   * key exists — a crash mid-creation is then reconcilable. Returns the handle
   * (echoed), its public key, the actually-created platform attestation, and
   * provider-owned evidence bytes. Never returns private bytes.
   */
  generateP256(
    handleId: Uint8Array,
    profile: string,
    requireUserPresence: boolean,
  ): Promise<NativeGenerateResult>;

  /**
   * Sign `signingMessage` (`domain || unsigned`) with the durable handle's
   * private key. The platform hashes internally (iOS
   * `ecdsaSignatureMessageX962SHA256`, Android `SHA256withECDSA`) and the native
   * code converts the DER signature to a low-S P1363 signature (64 bytes) over
   * `SHA-256(signingMessage)`. A zero/malformed/out-of-range signature is a
   * typed corruption error, never silently normalized.
   */
  signP256(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array>;

  /** Return the durable handle's public key and a fresh attestation report. */
  publicKey(handleId: Uint8Array): Promise<NativePublicKeyResult>;

  /**
   * Create a fresh durable key for the identity behind `handleId`, under the
   * caller-supplied `newHandleId`, preserving the old key's profile/presence.
   * The old key is retained until the caller destroys it, so the new generation
   * is only published after it is itself durable. `newHandleId` is caller-
   * assigned for the same write-ahead reason as `generateP256`.
   */
  rotateP256(handleId: Uint8Array, newHandleId: Uint8Array): Promise<NativeGenerateResult>;

  /** Irreversibly destroy the durable handle and its private key. */
  destroyGeneration(handleId: Uint8Array): Promise<void>;
}

/**
 * Resolve the compiled native module. Called lazily so that type-only importers
 * (the provider and the conformance fake under vitest) never trigger a native
 * lookup. Throws on a platform without the native module installed.
 */
export function requireRemoteIdentityCustodyModule(): RemoteIdentityCustodyModule {
  return requireNativeModule<RemoteIdentityCustodyModule>("RemoteIdentityCustody");
}
