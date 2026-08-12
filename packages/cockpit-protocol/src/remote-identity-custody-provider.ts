/**
 * The shared, platform-neutral durable-P-256 custody provider contract (v1).
 *
 * Browser (origin-bound WebCrypto) and native (iOS Secure Enclave / Android
 * StrongBox) custody providers both implement this interface, making their
 * module headers' "consumes the shared contract" claim true. The Rust seam
 * twin is `cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider`.
 *
 * Signing is MESSAGE-based: providers accept the signing message
 * (`domain || unsigned`, from {@link possessionProofSigningMessage} /
 * {@link enrollmentConfirmationSigningMessage}) and delegate SHA-256 hashing to
 * the platform (WebCrypto `ECDSA{hash:SHA-256}`, iOS
 * `ecdsaSignatureMessageX962SHA256`, Android `SHA256withECDSA`), because
 * WebCrypto cannot sign a raw digest. The returned signature is a low-S P1363
 * signature over `SHA-256(message)`. Private key bytes never cross this seam.
 */
import type { CustodyEvidenceV1, SubjectKindV1 } from "./remote-identity-protocol";

/**
 * A durable P-256 public key in uncompressed affine coordinates (each 32
 * bytes). X25519/DH keys are categorically absent from this surface — the
 * Noise binding owns per-child X25519 separately.
 */
export interface RemoteIdentityP256PublicKeyV1 {
  readonly x: Uint8Array;
  readonly y: Uint8Array;
}

/**
 * The custody policy a caller requests before generation: a minimum custody
 * class (a {@link CustodyClass} value) and whether a user-presence-gated key is
 * acceptable. The provider reports what it actually created (from real platform
 * attestation) and refuses any shortfall — it never downgrades or upgrades to
 * match caller-supplied bytes.
 */
export interface RemoteIdentityCustodyPolicyRequestV1 {
  readonly minCustodyClass: number;
  readonly allowUserPresenceRequired: boolean;
}

/**
 * The typed report returned by generate/rotate: the durable handle id, its
 * public key, the actually-created custody discriminants, and the
 * codec-validated {@link CustodyEvidenceV1}. No private bytes are present.
 */
export interface RemoteIdentityCustodyGenerationV1 {
  readonly handleId: Uint8Array;
  readonly publicKey: RemoteIdentityP256PublicKeyV1;
  readonly custodyClass: number;
  readonly presenceMode: number;
  readonly evidence: CustodyEvidenceV1;
}

/** The custody discriminants and public key reported by reopen. */
export interface RemoteIdentityCustodyReopenV1 {
  readonly handleId: Uint8Array;
  readonly publicKey: RemoteIdentityP256PublicKeyV1;
  readonly custodyClass: number;
  readonly presenceMode: number;
}

/**
 * The platform-neutral durable-P-256 custody provider seam. Every method signs
 * only the foundation-defined message inputs without returning private bytes
 * and reports the foundation-owned closed `CustodyClass` / `PresenceMode`
 * discriminants.
 */
export interface RemoteIdentityCustodyProviderV1 {
  /**
   * Generate a fresh durable non-exportable P-256 signing identity that
   * satisfies the requested policy, reporting its public key, actually-created
   * custody discriminants, and typed evidence. Fails (typed) before any server
   * allocation on capability/policy shortfall; never generates a weaker
   * replacement.
   */
  generate(
    subjectKind: SubjectKindV1,
    policy: RemoteIdentityCustodyPolicyRequestV1,
  ): Promise<RemoteIdentityCustodyGenerationV1>;

  /** Reopen an existing durable handle, returning its public key and custody
   * discriminants without ever returning private bytes. */
  reopen(handleId: Uint8Array): Promise<RemoteIdentityCustodyReopenV1>;

  /** Rotate a durable handle to a fresh key and the next monotonic generation,
   * destroying the old private key only after the new record is durable. */
  rotate(handleId: Uint8Array): Promise<RemoteIdentityCustodyGenerationV1>;

  /** Destroy a durable handle and its private key irreversibly. The persisted
   * monotonic generation high-water mark is never reset by destroy. */
  destroy(handleId: Uint8Array): Promise<void>;

  /** Sign the possession-proof signing message (`domain || unsigned`),
   * returning a low-S P1363 signature over `SHA-256(message)`. */
  signPossessionProof(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array>;

  /** Sign the enrollment-confirmation signing message, returning a low-S P1363
   * signature over `SHA-256(message)`. */
  signEnrollmentConfirmation(handleId: Uint8Array, signingMessage: Uint8Array): Promise<Uint8Array>;
}
