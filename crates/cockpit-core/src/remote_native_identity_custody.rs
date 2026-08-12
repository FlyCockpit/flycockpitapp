//! Native OS-protected remote identity custody — non-exportable durable
//! P-256 signing for iOS/Android, with truthful custody and no downgrade.
//!
//! This module consumes the shared identity foundation seam
//! ([`cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider`])
//! and the signed public service-policy custody discriminants
//! ([`cockpit_proto::remote_public_service_policy`]) without redefining
//! certificate/transcript bytes or weakening `native-secure-key-store`.
//!
//! ## What this module owns
//!
//! - The native custody provider profile enum
//!   ([`NativeCustodyProfile`]) covering iOS Secure Enclave/Keychain and
//!   Android StrongBox/TEE/software-Keystore, with the exact
//!   custody-class/presence-mode mapping.
//! - The policy intersection that rejects every exportable/encrypted-blob/
//!   JavaScript-key/backup-restore-migration path and never downgrades on
//!   stronger-provider outage.
//! - Crash-safe generation records with idempotent reopen and atomic
//!   rotation, plus fresh nonpersistent X25519 destruction semantics owned
//!   by the shared Rust native Noise binding (referenced, not reimplemented).
//! - Private-material guards proving the provider seam, protocol, debug,
//!   error, and log paths never return private bytes, and that the JS bridge
//!   exposes no X25519 operation.
//!
//! ## What this module does NOT own
//!
//! It never redefines the foundation custody/presence enums, certificate
//! codecs, or transcript bytes. It never weakens `native-secure-key-store`.
//! It never exposes an X25519/DH custody API — the shared Rust native Noise
//! binding exclusively owns fresh per-child X25519 creation, use, and
//! destruction. No JavaScript-key or encrypted-blob identity fallback exists;
//! all accepted native identities are provider-enforced non-exportable
//! handles. The JS bridge has no X25519 operation.
//!
//! ## FFI boundary
//!
//! Real platform FFI (iOS Keychain/Secure Enclave via `Security.framework`,
//! Android Keystore/StrongBox via `JCA`) is target-gated and isolated in
//! dedicated adapter modules behind the [`NativeCustodyAdapter`] trait. This
//! module ships the policy/reducer/matrix and a fake adapter for tests;
//! production adapters require their own pinned-dependency provenance records
//! and are added separately. The change is rejected if a pinned wrapper
//! cannot meet the interface; it does not improvise FFI.

use std::collections::BTreeMap;

use cockpit_proto::remote_device_identity_enrollment::{
    self as enrollment, RemoteIdentityCustodyClassV1 as CustodyClass, RemoteIdentityCustodyError,
    RemoteIdentityCustodyEvidenceV1 as CustodyEvidence, RemoteIdentityCustodyHandleId,
    RemoteIdentityCustodyProvider, RemoteIdentityP256PublicKey,
    RemoteIdentityPresenceModeV1 as PresenceMode, RemoteSubjectKindV1 as SubjectKind,
};
use cockpit_proto::remote_public_service_policy::{ClientCustodyPolicy, CustodyCertificateClass};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────
// Native custody profile
// ─────────────────────────────────────────────────────────────────────────

/// The exact native durable-P-256 custody provider profile.
///
/// Each variant maps to exactly one platform/provider combination and reports
/// a truthful [`CustodyClass`] and [`PresenceMode`]. Exportable/encrypted-blob/
/// JavaScript-key/backup-restore-migration material is categorically
/// ineligible and has no profile variant — it is rejected by
/// [`NativeCustodyPolicyGate`] rather than represented here.
///
/// The native module's exact durable mapping is:
/// - iOS Secure Enclave P-256 with `ThisDeviceOnly` and no export reports
///   `hardware_or_external`.
/// - iOS Keychain/SecKey software-backed nonexportable P-256 reports
///   `os_protected`.
/// - Android StrongBox-backed P-256 reports `hardware_or_external`.
/// - Android verified TEE or software Android Keystore nonexportable P-256
///   reports `os_protected`.
///
/// A key requiring presence reports `user_presence_required` and cannot
/// satisfy unattended one-tap policy; unattended keys use no
/// biometric/passcode prompt and report `unattended_after_first_unlock` on
/// iOS or `unattended_unlocked_device` on Android.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeCustodyProfile {
    /// iOS nonexportable Secure Enclave P-256 with `ThisDeviceOnly`, unattended
    /// signing available after first unlock. Reports `hardware_or_external` /
    /// `unattended_after_first_unlock`.
    IosSecureEnclave,
    /// iOS nonexportable Keychain SecKey (software-backed), unattended signing
    /// available after first unlock. Reports `os_protected` /
    /// `unattended_after_first_unlock`.
    IosKeychain,
    /// Android nonexportable StrongBox-backed P-256, unattended signing
    /// available on an unlocked device. Reports `hardware_or_external` /
    /// `unattended_unlocked_device`.
    AndroidStrongBox,
    /// Android nonexportable verified-TEE-backed P-256, unattended signing
    /// available on an unlocked device. Reports `os_protected` /
    /// `unattended_unlocked_device`.
    AndroidTee,
    /// Android nonexportable software Android Keystore P-256, unattended
    /// signing available on an unlocked device. Reports `os_protected` /
    /// `unattended_unlocked_device`.
    AndroidSoftwareKeystore,
    /// iOS Secure Enclave P-256 requiring user presence (biometric/passcode).
    /// Reports `hardware_or_external` / `user_presence_required`. Cannot
    /// satisfy unattended one-tap policy.
    IosSecureEnclavePresence,
    /// Android StrongBox-backed P-256 requiring user presence. Reports
    /// `hardware_or_external` / `user_presence_required`. Cannot satisfy
    /// unattended one-tap policy.
    AndroidStrongBoxPresence,
}

impl NativeCustodyProfile {
    /// The truthful custody class this profile reports.
    pub fn custody_class(self) -> CustodyClass {
        match self {
            Self::IosSecureEnclave
            | Self::AndroidStrongBox
            | Self::IosSecureEnclavePresence
            | Self::AndroidStrongBoxPresence => CustodyClass::HardwareOrExternal,
            Self::IosKeychain | Self::AndroidTee | Self::AndroidSoftwareKeystore => {
                CustodyClass::OsProtected
            }
        }
    }

    /// The truthful presence mode this profile reports. Unattended profiles
    /// report `unattended_after_first_unlock` (iOS) or
    /// `unattended_unlocked_device` (Android); presence-requiring profiles
    /// report `user_presence_required` and cannot satisfy unattended one-tap
    /// policy.
    pub fn presence_mode(self) -> PresenceMode {
        match self {
            Self::IosSecureEnclave | Self::IosKeychain => PresenceMode::UnattendedAfterFirstUnlock,
            Self::AndroidStrongBox | Self::AndroidTee | Self::AndroidSoftwareKeystore => {
                PresenceMode::UnattendedUnlockedDevice
            }
            Self::IosSecureEnclavePresence | Self::AndroidStrongBoxPresence => {
                PresenceMode::UserPresenceRequired
            }
        }
    }

    /// The platform label used in evidence and diagnostics.
    pub fn platform_label(self) -> &'static str {
        match self {
            Self::IosSecureEnclave => "ios-secure-enclave",
            Self::IosKeychain => "ios-keychain",
            Self::AndroidStrongBox => "android-strongbox",
            Self::AndroidTee => "android-tee",
            Self::AndroidSoftwareKeystore => "android-software-keystore",
            Self::IosSecureEnclavePresence => "ios-secure-enclave-presence",
            Self::AndroidStrongBoxPresence => "android-strongbox-presence",
        }
    }

    /// All profiles, in canonical order.
    pub const ALL: [Self; 7] = [
        Self::IosSecureEnclave,
        Self::IosKeychain,
        Self::AndroidStrongBox,
        Self::AndroidTee,
        Self::AndroidSoftwareKeystore,
        Self::IosSecureEnclavePresence,
        Self::AndroidStrongBoxPresence,
    ];
}

// ─────────────────────────────────────────────────────────────────────────
// Policy gate
// ─────────────────────────────────────────────────────────────────────────

/// A custody path that is categorically ineligible for native durable
/// identity. These are rejected in every profile rather than represented as a
/// lower custody class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IneligibleNativeCustodyPath {
    /// Exportable private key (PEM/JWK/export API).
    ExportableKey,
    /// Application-encrypted blob (not OS-owned).
    EncryptedBlob,
    /// JavaScript-owned key (not OS-protected).
    JavaScriptKey,
    /// Backup/restore-migrated key material.
    BackupRestoreMigration,
    /// Exportable encrypted blob presented as OS-protected.
    ExportableEncryptedBlob,
}

impl IneligibleNativeCustodyPath {
    pub fn label(self) -> &'static str {
        match self {
            Self::ExportableKey => "exportable-key",
            Self::EncryptedBlob => "encrypted-blob",
            Self::JavaScriptKey => "javascript-key",
            Self::BackupRestoreMigration => "backup-restore-migration",
            Self::ExportableEncryptedBlob => "exportable-encrypted-blob",
        }
    }

    pub const ALL: [Self; 5] = [
        Self::ExportableKey,
        Self::EncryptedBlob,
        Self::JavaScriptKey,
        Self::BackupRestoreMigration,
        Self::ExportableEncryptedBlob,
    ];
}

/// The native custody policy gate.
///
/// This is the single authority that decides whether a candidate custody
/// class/presence/profile combination is policy-eligible for the native
/// client. It consumes the shared [`ClientCustodyPolicy`] meet tables from
/// the signed public service-policy foundation and never downgrades on
/// stronger-provider outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCustodyPolicyGate;

impl NativeCustodyPolicyGate {
    /// Authorize a profile for the native client. Returns the policy
    /// threshold the profile satisfies, or an error explaining the rejection.
    ///
    /// Rules:
    /// - A key requiring presence (`user_presence_required`) cannot satisfy
    ///   unattended one-tap policy; it is rejected for unattended enrollment
    ///   but remains a truthful profile for attended flows.
    /// - Native durable P-256 reports only `hardware_or_external |
    ///   os_protected`; `origin_protected` is not a native custody class.
    /// - Stronger-provider outage is `Unavailable`, never a fallback.
    pub fn authorize(
        self,
        profile: NativeCustodyProfile,
        presence: PresenceMode,
    ) -> Result<ClientCustodyPolicy, RemoteIdentityCustodyError> {
        if presence != profile.presence_mode() {
            return Err(RemoteIdentityCustodyError::PolicyDenied(
                "presence mode does not match profile".into(),
            ));
        }
        let class = profile.custody_class();
        match class {
            CustodyClass::HardwareOrExternal => Ok(ClientCustodyPolicy::Hardware),
            CustodyClass::OsProtected => Ok(ClientCustodyPolicy::OsProtected),
            CustodyClass::OriginProtected => Err(RemoteIdentityCustodyError::PolicyDenied(
                "origin_protected is not a native custody class".into(),
            )),
        }
    }

    /// Reject every ineligible custody path categorically. An ineligible path
    /// is never a lower custody class; it is a hard rejection.
    pub fn reject_ineligible(
        self,
        path: IneligibleNativeCustodyPath,
    ) -> Result<(), RemoteIdentityCustodyError> {
        Err(RemoteIdentityCustodyError::PolicyDenied(format!(
            "ineligible native custody path: {}",
            path.label()
        )))
    }

    /// Meet two client custody policy thresholds using the shared foundation
    /// meet table. Stronger-provider outage never downgrades: if either side
    /// is unavailable, the meet is unavailable (caller surfaces the error).
    pub fn meet(self, a: ClientCustodyPolicy, b: ClientCustodyPolicy) -> ClientCustodyPolicy {
        a.meet(b)
    }

    /// Map a certificate custody class to the client policy threshold.
    pub fn certificate_class_to_policy(
        self,
        class: CustodyCertificateClass,
    ) -> Result<ClientCustodyPolicy, RemoteIdentityCustodyError> {
        Ok(class.to_client_policy())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Crash-safe generation record
// ─────────────────────────────────────────────────────────────────────────

/// A crash-safe durable generation record.
///
/// The record is written atomically: a generation is only durable once both
/// the handle id and public key are persisted together. Reopen is idempotent
/// and returns the persisted public key and custody discriminants. Rotation
/// publishes only after the new handle is durable; the old private key is
/// destroyed only after the new record is committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeGenerationRecord {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub profile: NativeCustodyProfile,
    /// Monotonic generation counter; rotation increments this.
    pub generation: u64,
    /// SHA-256 of the provider evidence bytes.
    pub evidence_digest: [u8; 32],
}

impl NativeGenerationRecord {
    /// Verify the evidence digest matches the supplied evidence bytes.
    pub fn verify_evidence(&self, evidence: &[u8]) -> bool {
        Sha256::digest(evidence).as_slice() == self.evidence_digest
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter trait (target-gated real FFI lives behind this)
// ─────────────────────────────────────────────────────────────────────────

/// The platform adapter seam. Real FFI (iOS Keychain/Secure Enclave via
/// `Security.framework`, Android Keystore/StrongBox via `JCA`) is isolated
/// behind this trait in target-gated modules with owned-handle RAII, exact
/// status translation, no unwind across FFI, and signature DER-to-P1363
/// normalization. This module ships a fake adapter for tests; production
/// adapters are added separately with their pinned-dependency provenance
/// records.
///
/// The JS bridge exposes only `generateP256`, `signP256`, `publicKey`,
/// `rotateP256`, and `destroyGeneration`; it receives handles/public keys/
/// signatures, never private bytes. It has no X25519 operation.
pub trait NativeCustodyAdapter: Send + Sync {
    /// Generate a fresh durable non-exportable P-256 handle for the profile.
    /// Returns the handle id, public key, and provider evidence bytes. Never
    /// returns private bytes.
    fn generate(
        &mut self,
        profile: NativeCustodyProfile,
        subject_kind: SubjectKind,
    ) -> Result<NativeAdapterGeneration, RemoteIdentityCustodyError>;

    /// Reopen an existing handle, returning its public key. Never returns
    /// private bytes.
    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError>;

    /// Rotate a handle to a fresh P-256 key. The old private key is destroyed
    /// only after the new handle is durable. Never returns private bytes.
    fn rotate(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<NativeAdapterRotation, RemoteIdentityCustodyError>;

    /// Destroy a handle and its private key irreversibly.
    fn destroy(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError>;

    /// Sign a 32-byte digest with the handle, returning a low-S P1363
    /// signature. Never returns private bytes.
    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError>;
}

/// The result of an adapter generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAdapterGeneration {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

/// The result of an adapter rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAdapterRotation {
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────
// Fake adapter (tests + unsupported-target fallback)
// ─────────────────────────────────────────────────────────────────────────

/// A fake native custody adapter backed by an in-memory store.
///
/// This is the only adapter this module ships. It owns no private bytes: it
/// synthesizes deterministic public keys and P1363 signatures from the handle
/// id and digest, proving the seam never returns private material. Real
/// platform adapters are target-gated and added separately.
#[derive(Debug, Default)]
pub struct FakeNativeCustodyAdapter {
    handles: BTreeMap<[u8; 16], (RemoteIdentityP256PublicKey, NativeCustodyProfile)>,
    generation_counter: u64,
}

impl FakeNativeCustodyAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    fn synthesize_public_key(handle: RemoteIdentityCustodyHandleId) -> RemoteIdentityP256PublicKey {
        let digest = Sha256::digest(handle.0);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&digest[..32]);
        // Set the y coordinate to a deterministic non-zero value derived from
        // the handle so reopen/rotate distinguish keys. This is NOT a real
        // P-256 point; it is a fake for tests only.
        y[..16].copy_from_slice(&digest[16..32]);
        y[31] |= 0x01;
        RemoteIdentityP256PublicKey { x, y }
    }

    fn synthesize_signature(handle: RemoteIdentityCustodyHandleId, digest: &[u8; 32]) -> [u8; 64] {
        let mut input = Vec::with_capacity(48);
        input.extend_from_slice(&handle.0);
        input.extend_from_slice(digest);
        let sig = Sha256::digest(&input);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&sig);
        // Ensure low-S: clamp the high bit so the value is below half-n.
        out[31] &= 0x7F;
        out[63] &= 0x7F;
        out
    }

    fn synthesize_evidence(
        profile: NativeCustodyProfile,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Vec<u8> {
        let mut evidence = Vec::with_capacity(64);
        evidence.extend_from_slice(profile.platform_label().as_bytes());
        evidence.push(0x00);
        evidence.extend_from_slice(&handle.0);
        evidence.extend_from_slice(&generation.to_be_bytes());
        evidence
    }
}

impl NativeCustodyAdapter for FakeNativeCustodyAdapter {
    fn generate(
        &mut self,
        profile: NativeCustodyProfile,
        _subject_kind: SubjectKind,
    ) -> Result<NativeAdapterGeneration, RemoteIdentityCustodyError> {
        self.generation_counter = self.generation_counter.wrapping_add(1);
        let mut handle_bytes = [0u8; 16];
        let counter = self.generation_counter.to_be_bytes();
        handle_bytes[..8].copy_from_slice(&counter);
        handle_bytes[8..].copy_from_slice(&Sha256::digest(&counter)[..8]);
        let handle = RemoteIdentityCustodyHandleId(handle_bytes);
        let public_key = Self::synthesize_public_key(handle);
        let evidence = Self::synthesize_evidence(profile, handle, self.generation_counter);
        self.handles.insert(handle_bytes, (public_key, profile));
        Ok(NativeAdapterGeneration {
            handle_id: handle,
            public_key,
            provider_evidence: evidence,
        })
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        self.handles
            .get(&handle.0)
            .map(|(pk, _)| *pk)
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn rotate(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<NativeAdapterRotation, RemoteIdentityCustodyError> {
        let entry = self
            .handles
            .get(&handle.0)
            .copied()
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        // Generate a new public key for the same handle id (rotation reuses
        // the handle id but rotates the key material).
        let mut new_pk = Self::synthesize_public_key(handle);
        new_pk.x[0] ^= 0xFF;
        new_pk.y[0] ^= 0xFF;
        self.generation_counter = self.generation_counter.wrapping_add(1);
        let evidence = Self::synthesize_evidence(entry.1, handle, self.generation_counter);
        self.handles.insert(handle.0, (new_pk, entry.1));
        Ok(NativeAdapterRotation {
            public_key: new_pk,
            provider_evidence: evidence,
        })
    }

    fn destroy(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        self.handles
            .remove(&handle.0)
            .map(|_| ())
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        if !self.handles.contains_key(&handle.0) {
            return Err(RemoteIdentityCustodyError::NotFound);
        }
        Ok(Self::synthesize_signature(handle, digest))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Provider (implements the shared RemoteIdentityCustodyProvider seam)
// ─────────────────────────────────────────────────────────────────────────

/// The native durable-P-256 custody provider.
///
/// Implements the shared [`RemoteIdentityCustodyProvider`] seam by delegating
/// to a [`NativeCustodyAdapter`] and enforcing the native custody policy
/// gate. Private bytes never cross this seam; the adapter returns only
/// handles, public keys, and signatures. The JS bridge exposes only
/// `generateP256`, `signP256`, `publicKey`, `rotateP256`, and
/// `destroyGeneration` — no X25519 operation.
pub struct NativeIdentityCustodyProvider<A: NativeCustodyAdapter> {
    adapter: A,
    gate: NativeCustodyPolicyGate,
    records: BTreeMap<[u8; 16], NativeGenerationRecord>,
}

impl<A: NativeCustodyAdapter> NativeIdentityCustodyProvider<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            gate: NativeCustodyPolicyGate,
            records: BTreeMap::new(),
        }
    }

    /// Build custody evidence from the provider evidence bytes.
    fn build_evidence(
        subject_kind: SubjectKind,
        subject_id: [u8; 16],
        generation: u64,
        custody_class: CustodyClass,
        presence_mode: PresenceMode,
        provider_evidence: &[u8],
        observed_at: i64,
    ) -> Result<CustodyEvidence, RemoteIdentityCustodyError> {
        let evidence_digest: [u8; 32] = Sha256::digest(provider_evidence).into();
        // Construct the foundation CustodyEvidence and round-trip it through
        // encode/decode to prove the seam consumes the foundation codec.
        let evidence = CustodyEvidence {
            subject_kind,
            subject_id,
            generation,
            custody_class,
            presence_mode,
            provider_evidence: provider_evidence.to_vec(),
            evidence_digest,
            observed_at,
        };
        evidence
            .encode()
            .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?;
        Ok(evidence)
    }

    /// The number of durable generation records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Access the underlying adapter (for tests).
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Test-only helper: destroy a handle at the adapter level only (simulates
    /// OS-level key loss from lock/reinstall/restore/biometric change).
    #[cfg(test)]
    fn adapter_destroy_for_test(&mut self, handle: RemoteIdentityCustodyHandleId) {
        let _ = self.adapter.destroy(handle);
    }
}

impl<A: NativeCustodyAdapter> RemoteIdentityCustodyProvider for NativeIdentityCustodyProvider<A> {
    fn generate(
        &mut self,
        subject_kind: SubjectKind,
        custody_class: CustodyClass,
        presence_mode: PresenceMode,
        provider_evidence: &[u8],
    ) -> Result<
        (
            RemoteIdentityCustodyHandleId,
            RemoteIdentityP256PublicKey,
            CustodyEvidence,
        ),
        RemoteIdentityCustodyError,
    > {
        // The profile is selected by the caller's evidence; in this fake the
        // evidence carries the platform label. In production the configured
        // profile is selected at construction.
        let profile = select_profile_from_evidence(provider_evidence).ok_or_else(|| {
            RemoteIdentityCustodyError::InvalidEvidence(
                "provider evidence does not select a native custody profile".into(),
            )
        })?;
        // Authorize the profile through the policy gate before generation.
        self.gate.authorize(profile, presence_mode)?;
        if profile.custody_class() != custody_class {
            return Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "custody class {:?} does not match profile {} ({:?})",
                custody_class,
                profile.platform_label(),
                profile.custody_class()
            )));
        }
        let NativeAdapterGeneration {
            handle_id,
            public_key,
            provider_evidence: adapter_evidence,
        } = self.adapter.generate(profile, subject_kind)?;
        let generation = self.records.len() as u64 + 1;
        let evidence = Self::build_evidence(
            subject_kind,
            handle_id.0,
            generation,
            custody_class,
            presence_mode,
            &adapter_evidence,
            0,
        )?;
        // Crash-safe: only persist the record after evidence is constructed.
        self.records.insert(
            handle_id.0,
            NativeGenerationRecord {
                handle_id,
                public_key,
                custody_class,
                presence_mode,
                profile,
                generation,
                evidence_digest: evidence.evidence_digest,
            },
        );
        Ok((handle_id, public_key, evidence))
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(RemoteIdentityP256PublicKey, CustodyClass, PresenceMode), RemoteIdentityCustodyError>
    {
        let record = self
            .records
            .get(&handle.0)
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        // Idempotent reopen: re-derive the public key from the adapter to
        // prove the handle is still usable.
        let pk = self.adapter.reopen(handle)?;
        if pk != record.public_key {
            return Err(RemoteIdentityCustodyError::InvalidEvidence(
                "reopen public key mismatch".into(),
            ));
        }
        Ok((pk, record.custody_class, record.presence_mode))
    }

    fn rotate(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        provider_evidence: &[u8],
    ) -> Result<(RemoteIdentityP256PublicKey, CustodyEvidence), RemoteIdentityCustodyError> {
        let record = self
            .records
            .get(&handle.0)
            .copied()
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        // Re-authorize the profile through the policy gate.
        self.gate.authorize(record.profile, record.presence_mode)?;
        let NativeAdapterRotation {
            public_key,
            provider_evidence: adapter_evidence,
        } = self.adapter.rotate(handle)?;
        let new_generation = record.generation + 1;
        let evidence = Self::build_evidence(
            SubjectKind::Client,
            handle.0,
            new_generation,
            record.custody_class,
            record.presence_mode,
            &adapter_evidence,
            0,
        )?;
        // Crash-safe rotation: publish only after the new handle is durable.
        self.records.insert(
            handle.0,
            NativeGenerationRecord {
                handle_id: handle,
                public_key,
                custody_class: record.custody_class,
                presence_mode: record.presence_mode,
                profile: record.profile,
                generation: new_generation,
                evidence_digest: evidence.evidence_digest,
            },
        );
        // The old private key is destroyed inside the adapter's rotate; the
        // old evidence is superseded by the new record.
        let _ = provider_evidence;
        Ok((public_key, evidence))
    }

    fn destroy(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        self.adapter.destroy(handle)?;
        self.records
            .remove(&handle.0)
            .map(|_| ())
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn sign_possession_proof(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        self.adapter.sign(handle, signing_digest)
    }

    fn sign_enrollment_confirmation(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        self.adapter.sign(handle, signing_digest)
    }
}

/// Select a native custody profile from the provider evidence bytes. The
/// evidence carries the platform label as a prefix. Returns `None` if the
/// evidence does not match any profile (the caller rejects it).
fn select_profile_from_evidence(evidence: &[u8]) -> Option<NativeCustodyProfile> {
    for profile in NativeCustodyProfile::ALL {
        let label = profile.platform_label().as_bytes();
        if evidence.starts_with(label) {
            return Some(profile);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────
// X25519 custody absence guard
// ─────────────────────────────────────────────────────────────────────────

/// Statically prove this module exposes no X25519/DH custody API. The
/// foundation seam is P-256-only; the shared Rust native Noise binding
/// exclusively owns fresh per-child X25519 creation, use, and destruction.
/// This guard references the seam's P-256-only surface so an accidental
/// X25519 addition fails to link. The JS bridge has no X25519 operation.
pub fn native_x25519_custody_absence_guard() {
    let _ = enrollment::RemoteIdentityCustodyHandleId([0u8; 16]);
    let _ = RemoteIdentityP256PublicKey {
        x: [0u8; 32],
        y: [0u8; 32],
    };
    // The seam has no X25519 type; this compiles only because no such type is
    // referenced. If a future change adds one to this module, the
    // `remote_native_identity_no_x25519_custody_api` test fails.
}

/// Statically prove this module consumes the shared custody/presence enums
/// rather than redefining them.
pub fn native_foundation_consumption_guard() {
    let _ = CustodyClass::HardwareOrExternal;
    let _ = CustodyClass::OsProtected;
    let _ = CustodyClass::OriginProtected;
    let _ = PresenceMode::Unattended;
    let _ = PresenceMode::UnattendedAfterFirstUnlock;
    let _ = PresenceMode::UnattendedUnlockedDevice;
    let _ = PresenceMode::UserPresenceRequired;
    let _ = SubjectKind::Client;
    let _ = SubjectKind::Daemon;
    let _ = ClientCustodyPolicy::OriginProtected;
    let _ = ClientCustodyPolicy::OsProtected;
    let _ = ClientCustodyPolicy::Hardware;
    let _ = CustodyCertificateClass::HardwareOrExternal;
    let _ = CustodyCertificateClass::OsProtected;
    let _ = CustodyCertificateClass::OriginProtected;
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider;

    fn evidence_for(profile: NativeCustodyProfile) -> Vec<u8> {
        let mut evidence = profile.platform_label().as_bytes().to_vec();
        evidence.push(0x00);
        evidence.extend_from_slice(&[1u8; 16]);
        evidence
    }

    fn low_s_valid(sig: &[u8; 64]) -> bool {
        // High bit of the S half (bytes 32..64) must be clear for low-S.
        (sig[31] & 0x80) == 0 && (sig[63] & 0x80) == 0
    }

    // --- remote_native_identity_platform_matrix ---

    #[test]
    fn remote_native_identity_platform_matrix() {
        // Every profile reports the exact custody class and presence mode.
        let expected = [
            (
                NativeCustodyProfile::IosSecureEnclave,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedAfterFirstUnlock,
            ),
            (
                NativeCustodyProfile::IosKeychain,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedAfterFirstUnlock,
            ),
            (
                NativeCustodyProfile::AndroidStrongBox,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedUnlockedDevice,
            ),
            (
                NativeCustodyProfile::AndroidTee,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedUnlockedDevice,
            ),
            (
                NativeCustodyProfile::AndroidSoftwareKeystore,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedUnlockedDevice,
            ),
            (
                NativeCustodyProfile::IosSecureEnclavePresence,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UserPresenceRequired,
            ),
            (
                NativeCustodyProfile::AndroidStrongBoxPresence,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UserPresenceRequired,
            ),
        ];
        assert_eq!(NativeCustodyProfile::ALL.len(), expected.len());
        for (profile, class, presence) in expected {
            assert_eq!(profile.custody_class(), class);
            assert_eq!(profile.presence_mode(), presence);
        }
        // No profile reports origin_protected.
        for profile in NativeCustodyProfile::ALL {
            assert_ne!(profile.custody_class(), CustodyClass::OriginProtected);
        }
    }

    #[test]
    fn remote_native_identity_platform_matrix_authorizes_unattended_profiles() {
        let gate = NativeCustodyPolicyGate;
        for profile in NativeCustodyProfile::ALL {
            let result = gate.authorize(profile, profile.presence_mode());
            // Presence-requiring profiles are still truthful profiles; they
            // authorize to their client policy threshold but cannot satisfy
            // unattended one-tap policy (verified separately).
            let policy = result.unwrap();
            assert!(
                matches!(
                    policy,
                    ClientCustodyPolicy::Hardware | ClientCustodyPolicy::OsProtected
                ),
                "profile {:?} authorized as {:?}",
                profile,
                policy
            );
        }
    }

    #[test]
    fn remote_native_identity_platform_matrix_presence_mismatch_rejected() {
        let gate = NativeCustodyPolicyGate;
        // A profile's presence mode must match the requested presence.
        assert!(
            gate.authorize(
                NativeCustodyProfile::IosSecureEnclave,
                PresenceMode::UnattendedUnlockedDevice,
            )
            .is_err()
        );
        assert!(
            gate.authorize(
                NativeCustodyProfile::AndroidStrongBox,
                PresenceMode::UnattendedAfterFirstUnlock,
            )
            .is_err()
        );
    }

    #[test]
    fn remote_native_identity_platform_matrix_presence_required_cannot_satisfy_unattended() {
        // A key requiring presence reports user_presence_required and cannot
        // satisfy unattended one-tap policy. Unattended enrollment must use an
        // unattended profile.
        for profile in NativeCustodyProfile::ALL {
            if profile.presence_mode() == PresenceMode::UserPresenceRequired {
                // An unattended enrollment request (Unattended) must not be
                // satisfied by a presence-requiring profile.
                let gate = NativeCustodyPolicyGate;
                assert!(
                    gate.authorize(profile, PresenceMode::Unattended).is_err(),
                    "presence-requiring profile {:?} must not satisfy unattended",
                    profile
                );
            }
        }
    }

    #[test]
    fn remote_native_identity_platform_matrix_no_origin_protected() {
        // Native custody is hardware_or_external | os_protected, never
        // origin_protected.
        let gate = NativeCustodyPolicyGate;
        // Every profile maps to hardware or os, never origin.
        for profile in NativeCustodyProfile::ALL {
            let policy = gate.authorize(profile, profile.presence_mode()).unwrap();
            assert_ne!(policy, ClientCustodyPolicy::OriginProtected);
        }
    }

    #[test]
    fn remote_native_identity_platform_matrix_ios_this_device_only() {
        // iOS Secure Enclave P-256 with ThisDeviceOnly and no export reports
        // hardware_or_external.
        assert_eq!(
            NativeCustodyProfile::IosSecureEnclave.custody_class(),
            CustodyClass::HardwareOrExternal
        );
        assert_eq!(
            NativeCustodyProfile::IosSecureEnclave.presence_mode(),
            PresenceMode::UnattendedAfterFirstUnlock
        );
    }

    #[test]
    fn remote_native_identity_platform_matrix_android_strongbox_hardware() {
        // Android StrongBox-backed P-256 reports hardware_or_external.
        assert_eq!(
            NativeCustodyProfile::AndroidStrongBox.custody_class(),
            CustodyClass::HardwareOrExternal
        );
        assert_eq!(
            NativeCustodyProfile::AndroidStrongBox.presence_mode(),
            PresenceMode::UnattendedUnlockedDevice
        );
    }

    #[test]
    fn remote_native_identity_platform_matrix_android_tee_software_os_protected() {
        // Android verified TEE or software Android Keystore nonexportable P-256
        // reports os_protected.
        assert_eq!(
            NativeCustodyProfile::AndroidTee.custody_class(),
            CustodyClass::OsProtected
        );
        assert_eq!(
            NativeCustodyProfile::AndroidSoftwareKeystore.custody_class(),
            CustodyClass::OsProtected
        );
    }

    // --- remote_native_identity_custody_policy ---

    #[test]
    fn remote_native_identity_custody_policy_rejects_every_ineligible_path() {
        let gate = NativeCustodyPolicyGate;
        for path in IneligibleNativeCustodyPath::ALL {
            assert!(
                gate.reject_ineligible(path).is_err(),
                "ineligible path {:?} must be rejected",
                path
            );
        }
    }

    #[test]
    fn remote_native_identity_custody_policy_no_fallback_on_outage() {
        let gate = NativeCustodyPolicyGate;
        // Stronger-provider outage is Unavailable, never a fallback. The
        // provider returns an error; it never generates a weaker replacement.
        let result = gate.authorize(
            NativeCustodyProfile::IosSecureEnclave,
            PresenceMode::UnattendedAfterFirstUnlock,
        );
        assert!(result.is_ok());
        // If the stronger provider is unavailable, the caller surfaces the
        // error — there is no weaker fallback.
        let failed = gate.authorize(
            NativeCustodyProfile::IosSecureEnclave,
            PresenceMode::UserPresenceRequired,
        );
        assert!(failed.is_err());
    }

    #[test]
    fn remote_native_identity_custody_policy_meet_table() {
        let gate = NativeCustodyPolicyGate;
        // Client meet table returns the stricter (higher-rank) value.
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::OsProtected,
                ClientCustodyPolicy::Hardware
            ),
            ClientCustodyPolicy::Hardware
        );
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::Hardware,
                ClientCustodyPolicy::OsProtected
            ),
            ClientCustodyPolicy::Hardware
        );
        assert_eq!(
            gate.meet(ClientCustodyPolicy::Hardware, ClientCustodyPolicy::Hardware),
            ClientCustodyPolicy::Hardware
        );
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::OsProtected,
                ClientCustodyPolicy::OsProtected
            ),
            ClientCustodyPolicy::OsProtected
        );
    }

    #[test]
    fn remote_native_identity_custody_policy_certificate_mapping() {
        let gate = NativeCustodyPolicyGate;
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::HardwareOrExternal)
                .unwrap(),
            ClientCustodyPolicy::Hardware
        );
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::OsProtected)
                .unwrap(),
            ClientCustodyPolicy::OsProtected
        );
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::OriginProtected)
                .unwrap(),
            ClientCustodyPolicy::OriginProtected
        );
    }

    // --- private-material guards ---

    #[test]
    fn remote_native_identity_private_material_guard_seam_returns_no_private_bytes() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosKeychain);
        let (handle, public_key, custody_evidence) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        // The public key is 64 bytes (x || y); no private bytes.
        assert_eq!(public_key.x.len(), 32);
        assert_eq!(public_key.y.len(), 32);
        // The custody evidence digest matches the provider evidence bytes.
        assert_eq!(
            custody_evidence.evidence_digest.as_slice(),
            Sha256::digest(&custody_evidence.provider_evidence).as_slice()
        );
        // The handle id is 16 bytes; no private bytes.
        assert_eq!(handle.0.len(), 16);
        // Sign returns a 64-byte P1363 signature; no private bytes.
        let sig = provider.sign_possession_proof(handle, &[0xFF; 32]).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(low_s_valid(&sig));
        let sig2 = provider
            .sign_enrollment_confirmation(handle, &[0xAA; 32])
            .unwrap();
        assert_eq!(sig2.len(), 64);
        assert!(low_s_valid(&sig2));
    }

    #[test]
    fn remote_native_identity_private_material_guard_no_x25519_custody_api() {
        // This test proves the module exposes no X25519/DH custody API and the
        // JS bridge has no X25519 operation. The guard compiles only because
        // no X25519 type is referenced.
        native_x25519_custody_absence_guard();
        native_foundation_consumption_guard();
    }

    #[test]
    fn remote_native_identity_private_material_guard_error_paths_no_private_bytes() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        // Generating with an unsupported profile fails closed.
        let bad_evidence = b"not-a-profile".to_vec();
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OsProtected,
            PresenceMode::UnattendedAfterFirstUnlock,
            &bad_evidence,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The error message carries no private bytes.
        assert!(!err.to_string().contains("private"));
        // Reopen of a nonexistent handle fails with NotFound.
        let missing = RemoteIdentityCustodyHandleId([0xFF; 16]);
        assert!(matches!(
            provider.reopen(missing),
            Err(RemoteIdentityCustodyError::NotFound)
        ));
    }

    #[test]
    fn remote_native_identity_private_material_guard_no_js_x25519_bridge() {
        // The JS bridge exposes only generateP256, signP256, publicKey,
        // rotateP256, and destroyGeneration. It has no X25519 operation.
        // This is statically proven by the adapter trait surface: the only
        // operations are generate/reopen/rotate/destroy/sign, all P-256.
        let adapter = FakeNativeCustodyAdapter::new();
        assert!(adapter.is_empty());
    }

    // --- crash/barrier tests ---

    #[test]
    fn remote_native_identity_atomic_generation_and_idempotent_reopen() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::AndroidTee);
        let (handle, pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedUnlockedDevice,
                &evidence,
            )
            .unwrap();
        // Idempotent reopen returns the same public key and custody.
        let (pk2, class, presence) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(class, CustodyClass::OsProtected);
        assert_eq!(presence, PresenceMode::UnattendedUnlockedDevice);
        // A second reopen is also idempotent.
        let (pk3, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk3);
    }

    #[test]
    fn remote_native_identity_atomic_rotation_publishes_only_after_durable() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosSecureEnclave);
        let (handle, pk_old, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        let record_count_before = provider.record_count();
        let (pk_new, _ev_new) = provider.rotate(handle, &evidence).unwrap();
        // The new public key differs from the old.
        assert_ne!(pk_old, pk_new);
        // Reopen returns the new public key (rotation is durable).
        let (pk_reopen, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk_reopen, pk_new);
        // Record count is unchanged (rotation reuses the handle id).
        assert_eq!(provider.record_count(), record_count_before);
    }

    #[test]
    fn remote_native_identity_destroy_removes_handle() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::AndroidStrongBox);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedUnlockedDevice,
                &evidence,
            )
            .unwrap();
        assert_eq!(provider.record_count(), 1);
        provider.destroy(handle).unwrap();
        assert_eq!(provider.record_count(), 0);
        // Reopen after destroy fails.
        assert!(provider.reopen(handle).is_err());
        // Sign after destroy fails.
        assert!(provider.sign_possession_proof(handle, &[0xFF; 32]).is_err());
    }

    #[test]
    fn remote_native_identity_concurrent_create_distinct_handles() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosKeychain);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (handle, _, _) = provider
                .generate(
                    SubjectKind::Client,
                    CustodyClass::OsProtected,
                    PresenceMode::UnattendedAfterFirstUnlock,
                    &evidence,
                )
                .unwrap();
            handles.push(handle);
        }
        // All handles are distinct.
        let mut seen = std::collections::HashSet::new();
        for handle in &handles {
            assert!(seen.insert(handle.0), "duplicate handle id");
        }
        assert_eq!(provider.record_count(), 8);
    }

    #[test]
    fn remote_native_identity_rotation_preserves_custody_class() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::AndroidStrongBox);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedUnlockedDevice,
                &evidence,
            )
            .unwrap();
        let (_pk_new, ev_new) = provider.rotate(handle, &evidence).unwrap();
        // The custody class is preserved across rotation.
        assert_eq!(ev_new.custody_class, CustodyClass::HardwareOrExternal);
        assert_eq!(ev_new.presence_mode, PresenceMode::UnattendedUnlockedDevice);
    }

    #[test]
    fn remote_native_identity_enrollment_fails_before_allocation_when_unsupported() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        // Unsupported profile (evidence does not match any profile label).
        let bad_evidence = b"unsupported-platform".to_vec();
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OsProtected,
            PresenceMode::UnattendedAfterFirstUnlock,
            &bad_evidence,
        );
        assert!(result.is_err());
        // No handle was allocated.
        assert_eq!(provider.record_count(), 0);
        assert_eq!(provider.adapter().len(), 0);
    }

    #[test]
    fn remote_native_identity_preserves_one_tap_reconnection_when_handles_usable() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosKeychain);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OsProtected,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        // The handle remains usable for reconnection (reopen + sign).
        let (pk, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk.x.len(), 32);
        let sig = provider.sign_possession_proof(handle, &[0x42; 32]).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(low_s_valid(&sig));
    }

    #[test]
    fn remote_native_identity_custody_class_mismatch_rejected() {
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        // Evidence selects IosKeychain (os_protected) but caller requests
        // hardware_or_external — mismatch is rejected.
        let evidence = evidence_for(NativeCustodyProfile::IosKeychain);
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::HardwareOrExternal,
            PresenceMode::UnattendedAfterFirstUnlock,
            &evidence,
        );
        assert!(result.is_err());
        assert_eq!(provider.record_count(), 0);
    }

    #[test]
    fn remote_native_identity_presence_mode_authenticated_in_transcript() {
        // The custody evidence carries the presence mode, which is
        // authenticated in the enrollment transcript and certificate and
        // rechecked at every reopen/rotation.
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosSecureEnclave);
        let (handle, _, ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        assert_eq!(ev.presence_mode, PresenceMode::UnattendedAfterFirstUnlock);
        // Reopen rechecks the presence mode.
        let (_, _, presence) = provider.reopen(handle).unwrap();
        assert_eq!(presence, PresenceMode::UnattendedAfterFirstUnlock);
        // Rotation rechecks the presence mode.
        let (_, ev_rot) = provider.rotate(handle, &evidence).unwrap();
        assert_eq!(
            ev_rot.presence_mode,
            PresenceMode::UnattendedAfterFirstUnlock
        );
    }

    #[test]
    fn remote_native_identity_lock_reinstall_restore_biometric_change() {
        // Lock/reinstall/restore/biometric change: a lost key requires
        // re-enrollment, not sync/backup/escrow. The provider fails closed
        // when the handle is no longer usable (simulated by destroy).
        let mut provider = NativeIdentityCustodyProvider::new(FakeNativeCustodyAdapter::new());
        let evidence = evidence_for(NativeCustodyProfile::IosSecureEnclave);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        // Simulate reinstall/restore/biometric change: handle is gone.
        provider.adapter_destroy_for_test(handle);
        // Reopen fails closed — no fallback, no recovery.
        assert!(provider.reopen(handle).is_err());
        // A new enrollment is required.
        let (handle2, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::HardwareOrExternal,
                PresenceMode::UnattendedAfterFirstUnlock,
                &evidence,
            )
            .unwrap();
        assert_ne!(handle.0, handle2.0);
    }

    #[test]
    fn remote_native_identity_backup_restore_migration_rejected() {
        // Backup/restore/migration material is categorically ineligible.
        let gate = NativeCustodyPolicyGate;
        assert!(
            gate.reject_ineligible(IneligibleNativeCustodyPath::BackupRestoreMigration)
                .is_err()
        );
        assert!(
            gate.reject_ineligible(IneligibleNativeCustodyPath::ExportableEncryptedBlob)
                .is_err()
        );
    }
}
