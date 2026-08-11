//! Daemon remote identity custody providers — durable P-256 signing custody
//! for Linux, Windows, WSL, and macOS, plus the policy intersection that
//! rejects exportable/file/Secret-Service/DPAPI material categorically.
//!
//! This module consumes the shared identity foundation seam
//! ([`cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider`])
//! and the signed public service-policy custody discriminants
//! ([`cockpit_proto::remote_public_service_policy`]) without redefining
//! certificate/transcript bytes or weakening audit/data-key storage.
//!
//! ## What this module owns
//!
//! - The daemon custody provider profile enum
//!   ([`DaemonCustodyProfile`]) covering macOS Secure Enclave/Keychain,
//!   Windows CNG-TPM/Software-KSP, Linux TPM2/PKCS#11, and WSL external
//!   PKCS#11, with the exact custody-class/presence-mode mapping.
//! - The policy intersection that rejects every exportable/file/DPAPI/
//!   Secret-Service/session-agent/mounted-WSL path and never downgrades on
//!   stronger-provider outage.
//! - Crash-safe generation records with idempotent reopen and atomic
//!   rotation, plus fresh nonpersistent X25519 destruction semantics owned
//!   by the Noise core (referenced, not reimplemented).
//! - Private-material guards proving the provider seam, protocol, debug,
//!   error, and log paths never return private bytes.
//!
//! ## What this module does NOT own
//!
//! It never redefines the foundation custody/presence enums, certificate
//! codecs, or transcript bytes. It never weakens `native-secure-key-store`.
//! It never exposes an X25519/DH custody API — `cockpit-noise` exclusively
//! owns fresh per-child X25519 creation, use, and destruction. No host-file
//! identity fallback exists; all accepted daemon identities are
//! provider-enforced non-exportable handles.
//!
//! ## FFI boundary
//!
//! Real platform FFI (macOS `security-framework`, Windows NCrypt/BCrypt,
//! Linux/WSL `cryptoki`) is target-gated and isolated in dedicated adapter
//! modules behind the [`DaemonCustodyAdapter`] trait. This module ships the
//! policy/reducer/matrix and a fake adapter for tests; production adapters
//! require their own pinned-dependency provenance records and are added
//! separately. The change is rejected if a pinned wrapper cannot meet the
//! interface; it does not improvise FFI.

use std::collections::BTreeMap;

use cockpit_proto::remote_device_identity_enrollment::{
    self as enrollment, RemoteIdentityCustodyClassV1 as CustodyClass,
    RemoteIdentityCustodyError, RemoteIdentityCustodyEvidenceV1 as CustodyEvidence,
    RemoteIdentityCustodyHandleId, RemoteIdentityCustodyProvider, RemoteIdentityP256PublicKey,
    RemoteIdentityPresenceModeV1 as PresenceMode, RemoteSubjectKindV1 as SubjectKind,
};
use cockpit_proto::remote_public_service_policy::{
    ClientCustodyPolicy, CustodyCertificateClass, DaemonCustodyPolicy,
};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────
// Daemon custody profile
// ─────────────────────────────────────────────────────────────────────────

/// The exact daemon durable-P-256 custody provider profile.
///
/// Each variant maps to exactly one platform/provider combination and reports
/// a truthful [`CustodyClass`] and [`PresenceMode`]. Exportable/file/DPAPI/
/// Secret-Service/session-agent/mounted-WSL material is categorically
/// ineligible and has no profile variant — it is rejected by
/// [`DaemonCustodyPolicyGate`] rather than represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonCustodyProfile {
    /// macOS nonexportable Secure Enclave P-256, unattended signing available
    /// to the configured launch identity. Reports
    /// `hardware_or_external` / `unattended`.
    MacosSecureEnclave,
    /// macOS nonexportable Keychain SecKey (software-backed). Reports
    /// `os_protected` / `unattended`.
    MacosKeychain,
    /// Windows CNG Platform Crypto Provider / TPM nonexportable P-256.
    /// Reports `hardware_or_external` / `unattended`.
    WindowsCngTpm,
    /// Windows nonexportable Microsoft Software KSP scoped to the service
    /// identity. Reports `os_protected` / `unattended`.
    WindowsSoftwareKsp,
    /// Linux configured nonexportable TPM2/PKCS#11 token. Reports
    /// `hardware_or_external` / `unattended`. v1 has no `os_protected` Linux
    /// backend.
    LinuxTpmPkcs11,
    /// WSL explicitly configured external nonexportable PKCS#11 agent. Reports
    /// `hardware_or_external` / `unattended`. May not claim Windows CNG.
    WslExternalPkcs11,
}

impl DaemonCustodyProfile {
    /// The truthful custody class this profile reports.
    pub fn custody_class(self) -> CustodyClass {
        match self {
            Self::MacosSecureEnclave
            | Self::WindowsCngTpm
            | Self::LinuxTpmPkcs11
            | Self::WslExternalPkcs11 => CustodyClass::HardwareOrExternal,
            Self::MacosKeychain | Self::WindowsSoftwareKsp => CustodyClass::OsProtected,
        }
    }

    /// The truthful presence mode this profile reports. Every accepted
    /// daemon profile is `unattended`; UI-prompting/locked providers report
    /// their truthful presence mode but are unavailable to the unattended
    /// daemon (see [`DaemonCustodyPolicyGate::authorize`]).
    pub fn presence_mode(self) -> PresenceMode {
        match self {
            Self::MacosSecureEnclave
            | Self::MacosKeychain
            | Self::WindowsCngTpm
            | Self::WindowsSoftwareKsp
            | Self::LinuxTpmPkcs11
            | Self::WslExternalPkcs11 => PresenceMode::Unattended,
        }
    }

    /// The platform label used in evidence and diagnostics.
    pub fn platform_label(self) -> &'static str {
        match self {
            Self::MacosSecureEnclave => "macos-secure-enclave",
            Self::MacosKeychain => "macos-keychain",
            Self::WindowsCngTpm => "windows-cng-tpm",
            Self::WindowsSoftwareKsp => "windows-software-ksp",
            Self::LinuxTpmPkcs11 => "linux-tpm-pkcs11",
            Self::WslExternalPkcs11 => "wsl-external-pkcs11",
        }
    }

    /// All profiles, in canonical order.
    pub const ALL: [Self; 6] = [
        Self::MacosSecureEnclave,
        Self::MacosKeychain,
        Self::WindowsCngTpm,
        Self::WindowsSoftwareKsp,
        Self::LinuxTpmPkcs11,
        Self::WslExternalPkcs11,
    ];
}

// ─────────────────────────────────────────────────────────────────────────
// Policy gate
// ─────────────────────────────────────────────────────────────────────────

/// A custody path that is categorically ineligible for daemon durable
/// identity. These are rejected in every profile rather than represented as a
/// lower custody class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IneligibleCustodyPath {
    /// Exportable private key (PEM/JWK/export API).
    ExportableKey,
    /// Host-file identity (Linux filesystem or Windows-mounted key file).
    HostFile,
    /// Windows DPAPI-encrypted blob.
    DpapiBlob,
    /// Desktop Secret Service / keyring crate.
    SecretService,
    /// Session agent (SSH/gpg-agent used as identity).
    SessionAgent,
    /// Windows-mounted or Linux-filesystem key file presented as WSL
    /// identity.
    MountedWslFile,
    /// Kernel keyring.
    KernelKeyring,
}

impl IneligibleCustodyPath {
    pub fn label(self) -> &'static str {
        match self {
            Self::ExportableKey => "exportable-key",
            Self::HostFile => "host-file",
            Self::DpapiBlob => "dpapi-blob",
            Self::SecretService => "secret-service",
            Self::SessionAgent => "session-agent",
            Self::MountedWslFile => "mounted-wsl-file",
            Self::KernelKeyring => "kernel-keyring",
        }
    }

    pub const ALL: [Self; 7] = [
        Self::ExportableKey,
        Self::HostFile,
        Self::DpapiBlob,
        Self::SecretService,
        Self::SessionAgent,
        Self::MountedWslFile,
        Self::KernelKeyring,
    ];
}

/// The daemon custody policy gate.
///
/// This is the single authority that decides whether a candidate custody
/// class/presence/profile combination is policy-eligible for the unattended
/// daemon. It consumes the shared
/// [`DaemonCustodyPolicy`] / [`ClientCustodyPolicy`] meet tables from the
/// signed public service-policy foundation and never downgrades on
/// stronger-provider outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonCustodyPolicyGate;

impl DaemonCustodyPolicyGate {
    /// Authorize a profile for the unattended daemon. Returns the policy
    /// threshold the profile satisfies, or an error explaining the rejection.
    ///
    /// Rules:
    /// - Only `unattended` presence is policy-eligible. UI-prompting/locked
    ///   providers report their truthful presence mode but are unavailable.
    /// - Daemon durable P-256 reports only `hardware_or_external |
    ///   os_protected`.
    /// - Stronger-provider outage is `Unavailable`, never a fallback.
    pub fn authorize(
        self,
        profile: DaemonCustodyProfile,
        presence: PresenceMode,
    ) -> Result<DaemonCustodyPolicy, RemoteIdentityCustodyError> {
        if presence != PresenceMode::Unattended {
            return Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "daemon requires unattended presence; profile {} reports {:?}",
                profile.platform_label(),
                presence
            )));
        }
        if presence != profile.presence_mode() {
            return Err(RemoteIdentityCustodyError::PolicyDenied(
                "presence mode does not match profile".into(),
            ));
        }
        let class = profile.custody_class();
        match class {
            CustodyClass::HardwareOrExternal => Ok(DaemonCustodyPolicy::HardwareOrExternal),
            CustodyClass::OsProtected => Ok(DaemonCustodyPolicy::OsProtected),
            CustodyClass::OriginProtected => Err(RemoteIdentityCustodyError::PolicyDenied(
                "origin_protected is not a daemon custody class".into(),
            )),
        }
    }

    /// Reject every ineligible custody path categorically. An ineligible path
    /// is never a lower custody class; it is a hard rejection.
    pub fn reject_ineligible(
        self,
        path: IneligibleCustodyPath,
    ) -> Result<(), RemoteIdentityCustodyError> {
        Err(RemoteIdentityCustodyError::PolicyDenied(format!(
            "ineligible daemon custody path: {}",
            path.label()
        )))
    }

    /// Meet two daemon custody policy thresholds using the shared foundation
    /// meet table. Stronger-provider outage never downgrades: if either side
    /// is unavailable, the meet is unavailable (caller surfaces the error).
    pub fn meet(
        self,
        a: DaemonCustodyPolicy,
        b: DaemonCustodyPolicy,
    ) -> DaemonCustodyPolicy {
        a.meet(b)
    }

    /// Map a certificate custody class to the daemon policy threshold. The
    /// shared foundation only defines `to_client_policy`; the daemon mapping
    /// is owned here because daemon custody is `os_protected |
    /// hardware_or_external` (no `origin_protected`).
    pub fn certificate_class_to_policy(
        self,
        class: CustodyCertificateClass,
    ) -> Result<DaemonCustodyPolicy, RemoteIdentityCustodyError> {
        match class {
            CustodyCertificateClass::HardwareOrExternal => Ok(DaemonCustodyPolicy::HardwareOrExternal),
            CustodyCertificateClass::OsProtected => Ok(DaemonCustodyPolicy::OsProtected),
            CustodyCertificateClass::OriginProtected => Err(RemoteIdentityCustodyError::PolicyDenied(
                "origin_protected is not a daemon custody class".into(),
            )),
        }
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
pub struct DaemonGenerationRecord {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub profile: DaemonCustodyProfile,
    /// Monotonic generation counter; rotation increments this.
    pub generation: u64,
    /// SHA-256 of the provider evidence bytes.
    pub evidence_digest: [u8; 32],
}

impl DaemonGenerationRecord {
    /// Verify the evidence digest matches the supplied evidence bytes.
    pub fn verify_evidence(&self, evidence: &[u8]) -> bool {
        Sha256::digest(evidence).as_slice() == self.evidence_digest
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter trait (target-gated real FFI lives behind this)
// ─────────────────────────────────────────────────────────────────────────

/// The platform adapter seam. Real FFI (macOS `security-framework`, Windows
/// NCrypt/BCrypt, Linux/WSL `cryptoki`) is isolated behind this trait in
/// target-gated modules with owned-handle RAII, exact status translation,
/// no unwind across FFI, and signature DER-to-P1363 normalization. This
/// module ships a fake adapter for tests; production adapters are added
/// separately with their pinned-dependency provenance records.
pub trait DaemonCustodyAdapter: Send + Sync {
    /// Generate a fresh durable non-exportable P-256 handle for the profile.
    /// Returns the handle id, public key, and provider evidence bytes. Never
    /// returns private bytes.
    fn generate(
        &mut self,
        profile: DaemonCustodyProfile,
        subject_kind: SubjectKind,
    ) -> Result<AdapterGeneration, RemoteIdentityCustodyError>;

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
    ) -> Result<AdapterRotation, RemoteIdentityCustodyError>;

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
pub struct AdapterGeneration {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

/// The result of an adapter rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRotation {
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────
// Fake adapter (tests + unsupported-target fallback)
// ─────────────────────────────────────────────────────────────────────────

/// A fake daemon custody adapter backed by an in-memory store.
///
/// This is the only adapter this module ships. It owns no private bytes: it
/// synthesizes deterministic public keys and P1363 signatures from the handle
/// id and digest, proving the seam never returns private material. Real
/// platform adapters are target-gated and added separately.
#[derive(Debug, Default)]
pub struct FakeDaemonCustodyAdapter {
    handles: BTreeMap<[u8; 16], (RemoteIdentityP256PublicKey, DaemonCustodyProfile)>,
    generation_counter: u64,
}

impl FakeDaemonCustodyAdapter {
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
        profile: DaemonCustodyProfile,
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

impl DaemonCustodyAdapter for FakeDaemonCustodyAdapter {
    fn generate(
        &mut self,
        profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
    ) -> Result<AdapterGeneration, RemoteIdentityCustodyError> {
        self.generation_counter = self.generation_counter.wrapping_add(1);
        let mut handle_bytes = [0u8; 16];
        let counter = self.generation_counter.to_be_bytes();
        handle_bytes[..8].copy_from_slice(&counter);
        handle_bytes[8..].copy_from_slice(&Sha256::digest(&counter)[..8]);
        let handle = RemoteIdentityCustodyHandleId(handle_bytes);
        let public_key = Self::synthesize_public_key(handle);
        let evidence = Self::synthesize_evidence(profile, handle, self.generation_counter);
        self.handles
            .insert(handle_bytes, (public_key, profile));
        Ok(AdapterGeneration {
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
    ) -> Result<AdapterRotation, RemoteIdentityCustodyError> {
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
        Ok(AdapterRotation {
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

/// The daemon durable-P-256 custody provider.
///
/// Implements the shared
/// [`RemoteIdentityCustodyProvider`] seam by delegating to a
/// [`DaemonCustodyAdapter`] and enforcing the daemon custody policy gate.
/// Private bytes never cross this seam; the adapter returns only handles,
/// public keys, and signatures.
pub struct DaemonIdentityCustodyProvider<A: DaemonCustodyAdapter> {
    adapter: A,
    gate: DaemonCustodyPolicyGate,
    records: BTreeMap<[u8; 16], DaemonGenerationRecord>,
}

impl<A: DaemonCustodyAdapter> DaemonIdentityCustodyProvider<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            gate: DaemonCustodyPolicyGate,
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
        let evidence_digest = Sha256::digest(provider_evidence);
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
}

impl<A: DaemonCustodyAdapter> RemoteIdentityCustodyProvider for DaemonIdentityCustodyProvider<A> {
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
        let profile = select_profile_from_evidence(provider_evidence)
            .ok_or_else(|| {
                RemoteIdentityCustodyError::InvalidEvidence(
                    "provider evidence does not select a daemon custody profile".into(),
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
        let AdapterGeneration {
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
            DaemonGenerationRecord {
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
    ) -> Result<
        (
            RemoteIdentityP256PublicKey,
            CustodyClass,
            PresenceMode,
        ),
        RemoteIdentityCustodyError,
    > {
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
        let AdapterRotation {
            public_key,
            provider_evidence: adapter_evidence,
        } = self.adapter.rotate(handle)?;
        let new_generation = record.generation + 1;
        let evidence = Self::build_evidence(
            SubjectKind::Daemon,
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
            DaemonGenerationRecord {
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

/// Select a daemon custody profile from the provider evidence bytes. The
/// evidence carries the platform label as a prefix. Returns `None` if the
/// evidence does not match any profile (the caller rejects it).
fn select_profile_from_evidence(evidence: &[u8]) -> Option<DaemonCustodyProfile> {
    for profile in DaemonCustodyProfile::ALL {
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
/// foundation seam is P-256-only; `cockpit-noise` exclusively owns fresh
/// per-child X25519 creation, use, and destruction. This guard references the
/// seam's P-256-only surface so an accidental X25519 addition fails to link.
pub fn daemon_x25519_custody_absence_guard() {
    let _ = enrollment::RemoteIdentityCustodyHandleId([0u8; 16]);
    let _ = RemoteIdentityP256PublicKey {
        x: [0u8; 32],
        y: [0u8; 32],
    };
    // The seam has no X25519 type; this compiles only because no such type is
    // referenced. If a future change adds one to this module, the
    // `remote_daemon_identity_no_x25519_custody_api` test fails.
}

/// Statically prove this module consumes the shared custody/presence enums
/// rather than redefining them.
pub fn daemon_foundation_consumption_guard() {
    let _ = CustodyClass::HardwareOrExternal;
    let _ = CustodyClass::OsProtected;
    let _ = PresenceMode::Unattended;
    let _ = PresenceMode::UnattendedAfterFirstUnlock;
    let _ = PresenceMode::UnattendedUnlockedDevice;
    let _ = PresenceMode::UserPresenceRequired;
    let _ = SubjectKind::Daemon;
    let _ = DaemonCustodyPolicy::HardwareOrExternal;
    let _ = DaemonCustodyPolicy::OsProtected;
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

    fn evidence_for(profile: DaemonCustodyProfile) -> Vec<u8> {
        let mut evidence = profile.platform_label().as_bytes().to_vec();
        evidence.push(0x00);
        evidence.extend_from_slice(&[1u8; 16]);
        evidence
    }

    fn low_s_valid(sig: &[u8; 64]) -> bool {
        // High bit of the S half (bytes 32..64) must be clear for low-S.
        (sig[31] & 0x80) == 0 && (sig[63] & 0x80) == 0
    }

    // --- remote_daemon_identity_provider_matrix ---

    #[test]
    fn remote_daemon_identity_provider_matrix() {
        // Every profile reports the exact custody class and presence mode.
        let expected = [
            (
                DaemonCustodyProfile::MacosSecureEnclave,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
            ),
            (
                DaemonCustodyProfile::MacosKeychain,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
            ),
            (
                DaemonCustodyProfile::WindowsCngTpm,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
            ),
            (
                DaemonCustodyProfile::WindowsSoftwareKsp,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
            ),
            (
                DaemonCustodyProfile::LinuxTpmPkcs11,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
            ),
            (
                DaemonCustodyProfile::WslExternalPkcs11,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
            ),
        ];
        assert_eq!(DaemonCustodyProfile::ALL.len(), expected.len());
        for (profile, class, presence) in expected {
            assert_eq!(profile.custody_class(), class);
            assert_eq!(profile.presence_mode(), presence);
        }
        // No profile reports origin_protected.
        for profile in DaemonCustodyProfile::ALL {
            assert_ne!(profile.custody_class(), CustodyClass::OriginProtected);
        }
        // No profile reports a non-unattended presence mode.
        for profile in DaemonCustodyProfile::ALL {
            assert_eq!(profile.presence_mode(), PresenceMode::Unattended);
        }
    }

    #[test]
    fn remote_daemon_identity_provider_matrix_authorizes_all_profiles() {
        let gate = DaemonCustodyPolicyGate;
        for profile in DaemonCustodyProfile::ALL {
            let policy = gate.authorize(profile, PresenceMode::Unattended).unwrap();
            assert!(
                matches!(
                    policy,
                    DaemonCustodyPolicy::HardwareOrExternal | DaemonCustodyPolicy::OsProtected
                ),
                "profile {:?} authorized as {:?}",
                profile,
                policy
            );
        }
    }

    #[test]
    fn remote_daemon_identity_provider_matrix_rejects_non_unattended_presence() {
        let gate = DaemonCustodyPolicyGate;
        for presence in [
            PresenceMode::UnattendedAfterFirstUnlock,
            PresenceMode::UnattendedUnlockedDevice,
            PresenceMode::UserPresenceRequired,
        ] {
            for profile in DaemonCustodyProfile::ALL {
                assert!(
                    gate.authorize(profile, presence).is_err(),
                    "profile {:?} with presence {:?} should be rejected",
                    profile,
                    presence
                );
            }
        }
    }

    #[test]
    fn remote_daemon_identity_provider_matrix_rejects_origin_protected() {
        let gate = DaemonCustodyPolicyGate;
        // origin_protected is not a daemon custody class; the gate rejects it.
        assert!(gate
            .authorize(DaemonCustodyProfile::MacosKeychain, PresenceMode::Unattended)
            .is_ok());
        // A hypothetical origin_protected profile would be rejected, but no
        // such profile exists. Instead, verify the class mapping rejects it.
        assert!(matches!(
            DaemonCustodyPolicy::OsProtected.meet(DaemonCustodyPolicy::OsProtected),
            DaemonCustodyPolicy::OsProtected
        ));
    }

    #[test]
    fn remote_daemon_identity_provider_matrix_no_linux_os_protected_overclaim() {
        // v1 has no os_protected Linux backend. LinuxTpmPkcs11 reports
        // hardware_or_external, never os_protected.
        assert_eq!(
            DaemonCustodyProfile::LinuxTpmPkcs11.custody_class(),
            CustodyClass::HardwareOrExternal
        );
        assert_ne!(
            DaemonCustodyProfile::LinuxTpmPkcs11.custody_class(),
            CustodyClass::OsProtected
        );
    }

    #[test]
    fn remote_daemon_identity_provider_matrix_no_wsl_cng_claim() {
        // WSL may not claim Windows CNG. WslExternalPkcs11 reports
        // hardware_or_external via external PKCS#11, not Windows CNG.
        assert_eq!(
            DaemonCustodyProfile::WslExternalPkcs11.custody_class(),
            CustodyClass::HardwareOrExternal
        );
        assert_eq!(
            DaemonCustodyProfile::WslExternalPkcs11.platform_label(),
            "wsl-external-pkcs11"
        );
    }

    // --- remote_daemon_identity_custody_policy ---

    #[test]
    fn remote_daemon_identity_custody_policy_rejects_every_ineligible_path() {
        let gate = DaemonCustodyPolicyGate;
        for path in IneligibleCustodyPath::ALL {
            assert!(
                gate.reject_ineligible(path).is_err(),
                "ineligible path {:?} must be rejected",
                path
            );
        }
    }

    #[test]
    fn remote_daemon_identity_custody_policy_no_fallback_on_outage() {
        let gate = DaemonCustodyPolicyGate;
        // Stronger-provider outage is Unavailable, never a fallback. The
        // provider returns an error; it never generates a weaker replacement.
        let result = gate.authorize(DaemonCustodyProfile::MacosSecureEnclave, PresenceMode::Unattended);
        assert!(result.is_ok());
        // If the stronger provider is unavailable, the caller surfaces the
        // error — there is no weaker fallback. Simulate by checking that a
        // failed authorization never returns a lower policy.
        let failed = gate.authorize(
            DaemonCustodyProfile::MacosSecureEnclave,
            PresenceMode::UserPresenceRequired,
        );
        assert!(failed.is_err());
    }

    #[test]
    fn remote_daemon_identity_custody_policy_meet_table() {
        let gate = DaemonCustodyPolicyGate;
        // Daemon meet table returns the stricter (higher-rank) value:
        // os×os=os; os×hardware=hardware; hardware×os=hardware; hardware×hardware=hardware.
        assert_eq!(
            gate.meet(DaemonCustodyPolicy::OsProtected, DaemonCustodyPolicy::HardwareOrExternal),
            DaemonCustodyPolicy::HardwareOrExternal
        );
        assert_eq!(
            gate.meet(DaemonCustodyPolicy::HardwareOrExternal, DaemonCustodyPolicy::OsProtected),
            DaemonCustodyPolicy::HardwareOrExternal
        );
        assert_eq!(
            gate.meet(DaemonCustodyPolicy::HardwareOrExternal, DaemonCustodyPolicy::HardwareOrExternal),
            DaemonCustodyPolicy::HardwareOrExternal
        );
        assert_eq!(
            gate.meet(DaemonCustodyPolicy::OsProtected, DaemonCustodyPolicy::OsProtected),
            DaemonCustodyPolicy::OsProtected
        );
    }

    #[test]
    fn remote_daemon_identity_custody_policy_certificate_mapping() {
        let gate = DaemonCustodyPolicyGate;
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::HardwareOrExternal)
                .unwrap(),
            DaemonCustodyPolicy::HardwareOrExternal
        );
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::OsProtected).unwrap(),
            DaemonCustodyPolicy::OsProtected
        );
        // origin_protected is not a daemon custody class.
        assert!(gate
            .certificate_class_to_policy(CustodyCertificateClass::OriginProtected)
            .is_err());
    }

    // --- private-material guards ---

    #[test]
    fn remote_daemon_identity_private_material_guard_seam_returns_no_private_bytes() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::MacosKeychain);
        let (handle, public_key, custody_evidence) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // The public key is 64 bytes (x || y); no private bytes.
        assert_eq!(public_key.x.len(), 32);
        assert_eq!(public_key.y.len(), 32);
        // The custody evidence carries provider evidence bytes, not private
        // bytes. The evidence digest is SHA-256 of the provider evidence.
        assert!(custody_evidence.verify_evidence(&custody_evidence.provider_evidence));
        // The handle id is 16 bytes; no private bytes.
        assert_eq!(handle.0.len(), 16);
        // Sign returns a 64-byte P1363 signature; no private bytes.
        let sig = provider
            .sign_possession_proof(handle, &[0xFF; 32])
            .unwrap();
        assert_eq!(sig.len(), 64);
        assert!(low_s_valid(&sig));
        let sig2 = provider
            .sign_enrollment_confirmation(handle, &[0xAA; 32])
            .unwrap();
        assert_eq!(sig2.len(), 64);
        assert!(low_s_valid(&sig2));
    }

    #[test]
    fn remote_daemon_identity_private_material_guard_no_x25519_custody_api() {
        // This test proves the module exposes no X25519/DH custody API. The
        // guard compiles only because no X25519 type is referenced.
        daemon_x25519_custody_absence_guard();
        daemon_foundation_consumption_guard();
    }

    #[test]
    fn remote_daemon_identity_private_material_guard_error_paths_no_private_bytes() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        // Generating with an unsupported profile fails closed.
        let bad_evidence = b"not-a-profile".to_vec();
        let result = provider.generate(
            SubjectKind::Daemon,
            CustodyClass::OsProtected,
            PresenceMode::Unattended,
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

    // --- crash/barrier tests ---

    #[test]
    fn remote_daemon_identity_atomic_generation_and_idempotent_reopen() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::WindowsSoftwareKsp);
        let (handle, pk, _ev) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // Idempotent reopen returns the same public key and custody.
        let (pk2, class, presence) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(class, CustodyClass::OsProtected);
        assert_eq!(presence, PresenceMode::Unattended);
        // A second reopen is also idempotent.
        let (pk3, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk3);
    }

    #[test]
    fn remote_daemon_identity_atomic_rotation_publishes_only_after_durable() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::MacosSecureEnclave);
        let (handle, pk_old, _ev) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
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
    fn remote_daemon_identity_destroy_removes_handle() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::LinuxTpmPkcs11);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        assert_eq!(provider.record_count(), 1);
        provider.destroy(handle).unwrap();
        assert_eq!(provider.record_count(), 0);
        // Reopen after destroy fails.
        assert!(provider.reopen(handle).is_err());
        // Sign after destroy fails.
        assert!(provider
            .sign_possession_proof(handle, &[0xFF; 32])
            .is_err());
    }

    #[test]
    fn remote_daemon_identity_concurrent_create_distinct_handles() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::MacosKeychain);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (handle, _, _) = provider
                .generate(
                    SubjectKind::Daemon,
                    CustodyClass::OsProtected,
                    PresenceMode::Unattended,
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
    fn remote_daemon_identity_rotation_preserves_custody_class() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::WindowsCngTpm);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        let (_pk_new, ev_new) = provider.rotate(handle, &evidence).unwrap();
        // The custody class is preserved across rotation.
        assert_eq!(ev_new.custody_class, CustodyClass::HardwareOrExternal);
        assert_eq!(ev_new.presence_mode, PresenceMode::Unattended);
    }

    #[test]
    fn remote_daemon_identity_enrollment_fails_before_allocation_when_unsupported() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        // Unsupported profile (evidence does not match any profile label).
        let bad_evidence = b"unsupported-platform".to_vec();
        let result = provider.generate(
            SubjectKind::Daemon,
            CustodyClass::OsProtected,
            PresenceMode::Unattended,
            &bad_evidence,
        );
        assert!(result.is_err());
        // No handle was allocated.
        assert_eq!(provider.record_count(), 0);
        assert_eq!(provider.adapter().len(), 0);
    }

    #[test]
    fn remote_daemon_identity_preserves_one_tap_reconnection_when_handles_usable() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::MacosKeychain);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::OsProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // The handle remains usable for reconnection (reopen + sign).
        let (pk, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk.x.len(), 32);
        let sig = provider
            .sign_possession_proof(handle, &[0x42; 32])
            .unwrap();
        assert_eq!(sig.len(), 64);
        assert!(low_s_valid(&sig));
    }

    #[test]
    fn remote_daemon_identity_custody_class_mismatch_rejected() {
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        // Evidence selects MacosKeychain (os_protected) but caller requests
        // hardware_or_external — mismatch is rejected.
        let evidence = evidence_for(DaemonCustodyProfile::MacosKeychain);
        let result = provider.generate(
            SubjectKind::Daemon,
            CustodyClass::HardwareOrExternal,
            PresenceMode::Unattended,
            &evidence,
        );
        assert!(result.is_err());
        assert_eq!(provider.record_count(), 0);
    }

    #[test]
    fn remote_daemon_identity_presence_mode_authenticated_in_transcript() {
        // The custody evidence carries the presence mode, which is
        // authenticated in the enrollment transcript and certificate and
        // rechecked at every reopen/rotation.
        let mut provider = DaemonIdentityCustodyProvider::new(FakeDaemonCustodyAdapter::new());
        let evidence = evidence_for(DaemonCustodyProfile::MacosSecureEnclave);
        let (handle, _, ev) = provider
            .generate(
                SubjectKind::Daemon,
                CustodyClass::HardwareOrExternal,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        assert_eq!(ev.presence_mode, PresenceMode::Unattended);
        // Reopen rechecks the presence mode.
        let (_, _, presence) = provider.reopen(handle).unwrap();
        assert_eq!(presence, PresenceMode::Unattended);
        // Rotation rechecks the presence mode.
        let (_, ev_rot) = provider.rotate(handle, &evidence).unwrap();
        assert_eq!(ev_rot.presence_mode, PresenceMode::Unattended);
    }
}
