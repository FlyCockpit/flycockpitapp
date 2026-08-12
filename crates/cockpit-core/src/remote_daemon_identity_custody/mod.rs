//! Daemon remote identity custody — durable, non-exportable P-256 signing
//! custody for Linux, Windows, WSL, and macOS.
//!
//! This module consumes the shared identity foundation seam
//! ([`cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider`])
//! and the signed public service-policy custody discriminants
//! ([`cockpit_proto::remote_public_service_policy`]). It never redefines the
//! foundation custody/presence enums, certificate codecs, or transcript bytes,
//! and it exposes no X25519/DH custody API — `cockpit-noise` exclusively owns
//! fresh per-child X25519 creation, use, and destruction.
//!
//! ## Truthful, configuration-derived custody
//!
//! The custody class is **construction-time configuration**
//! ([`DaemonIdentityCustodyProvider::new`] takes a [`DaemonCustodyProfile`]).
//! Caller-supplied evidence bytes are never an input to classification — the
//! recorded `provider_evidence` is exclusively adapter *output* (attestation).
//! `generate` rejects a requested custody class or presence mode that does not
//! match the configured profile.
//!
//! ## Persistence
//!
//! Generation records and a monotonic generation high-water sequence live in
//! `cockpit-db` SQLite ([`store::SqliteCustodyStore`]). `destroy` never resets
//! or deletes the sequence, so a destroyed + regenerated identity always
//! receives a strictly greater generation. `observed_at` comes from an injected
//! [`DaemonCustodyClock`], never ambient system time in tests.
//!
//! ## Signatures
//!
//! The Rust seam is digest-based (`sign(handle, &[u8; 32])`); every daemon
//! platform API can sign a precomputed digest. Adapters normalize DER output to
//! low-S P1363 via [`der_signature_to_low_s_p1363`]. Acceptance of a signature
//! is proven only by round-tripping it through the production
//! `PossessionProof::encode`/`decode` codec — there is no hand-rolled low-S
//! predicate anywhere in this module.
//!
//! ## FFI boundary
//!
//! Real platform FFI is target-gated behind [`DaemonCustodyAdapter`]: macOS
//! [`macos`] (`security-framework`), Windows [`windows`] (NCrypt via
//! `windows-sys`), Linux/WSL [`pkcs11`] (`cryptoki`, loading only an explicitly
//! configured absolute module path). This module also ships a real-key test
//! fake ([`FakeDaemonCustodyAdapter`]) holding genuine `p256` signing keys.

use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyClassV1 as CustodyClass, RemoteIdentityCustodyError,
    RemoteIdentityCustodyEvidenceV1 as CustodyEvidence, RemoteIdentityCustodyHandleId,
    RemoteIdentityCustodyProvider, RemoteIdentityP256PublicKey,
    RemoteIdentityPresenceModeV1 as PresenceMode, RemoteSubjectKindV1 as SubjectKind,
};
use cockpit_proto::remote_public_service_policy::{CustodyCertificateClass, DaemonCustodyPolicy};
use sha2::{Digest, Sha256};

pub mod store;
pub use store::{NewCustodyRecord, SqliteCustodyStore};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(all(target_os = "linux", feature = "daemon-custody-pkcs11"))]
pub mod pkcs11;
#[cfg(target_os = "windows")]
pub mod windows;

// ─────────────────────────────────────────────────────────────────────────
// Daemon custody profile
// ─────────────────────────────────────────────────────────────────────────

/// The exact daemon durable-P-256 custody provider profile. Each variant maps
/// to exactly one platform/provider combination and reports a truthful
/// [`CustodyClass`] and [`PresenceMode`]. Exportable/file/DPAPI/Secret-Service/
/// session-agent/mounted-WSL material is categorically ineligible and has no
/// profile variant — it is rejected by [`DaemonCustodyPolicyGate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonCustodyProfile {
    /// macOS nonexportable Secure Enclave P-256. `hardware_or_external` / `unattended`.
    MacosSecureEnclave,
    /// macOS nonexportable Keychain SecKey (software-backed). `os_protected` / `unattended`.
    MacosKeychain,
    /// Windows CNG Platform Crypto Provider / TPM P-256. `hardware_or_external` / `unattended`.
    WindowsCngTpm,
    /// Windows nonexportable Microsoft Software KSP. `os_protected` / `unattended`.
    WindowsSoftwareKsp,
    /// Linux configured nonexportable TPM2/PKCS#11 token. `hardware_or_external` / `unattended`.
    LinuxTpmPkcs11,
    /// WSL explicitly configured external nonexportable PKCS#11 agent.
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

    /// The truthful presence mode this profile reports. Every accepted daemon
    /// profile is `unattended`.
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

    /// Parse a persisted platform label back into a profile.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.platform_label() == label)
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
    ExportableKey,
    HostFile,
    DpapiBlob,
    SecretService,
    SessionAgent,
    MountedWslFile,
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

/// The daemon custody policy gate — the single authority deciding whether a
/// candidate custody class/presence/profile combination is policy-eligible for
/// the unattended daemon. Never downgrades on stronger-provider outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonCustodyPolicyGate;

impl DaemonCustodyPolicyGate {
    /// Authorize a profile for the unattended daemon, returning the policy
    /// threshold the profile satisfies, or an error explaining the rejection.
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
        match profile.custody_class() {
            CustodyClass::HardwareOrExternal => Ok(DaemonCustodyPolicy::HardwareOrExternal),
            CustodyClass::OsProtected => Ok(DaemonCustodyPolicy::OsProtected),
            CustodyClass::OriginProtected => Err(RemoteIdentityCustodyError::PolicyDenied(
                "origin_protected is not a daemon custody class".into(),
            )),
        }
    }

    /// Reject every ineligible custody path categorically.
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
    /// meet table.
    pub fn meet(self, a: DaemonCustodyPolicy, b: DaemonCustodyPolicy) -> DaemonCustodyPolicy {
        a.meet(b)
    }

    /// Map a certificate custody class to the daemon policy threshold.
    pub fn certificate_class_to_policy(
        self,
        class: CustodyCertificateClass,
    ) -> Result<DaemonCustodyPolicy, RemoteIdentityCustodyError> {
        match class {
            CustodyCertificateClass::HardwareOrExternal => {
                Ok(DaemonCustodyPolicy::HardwareOrExternal)
            }
            CustodyCertificateClass::OsProtected => Ok(DaemonCustodyPolicy::OsProtected),
            CustodyCertificateClass::OriginProtected => {
                Err(RemoteIdentityCustodyError::PolicyDenied(
                    "origin_protected is not a daemon custody class".into(),
                ))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Injected clock
// ─────────────────────────────────────────────────────────────────────────

/// A clock seam for `observed_at`, following the workspace injected-time
/// convention. Never ambient system time in tests.
pub trait DaemonCustodyClock: Send + Sync {
    fn now_unix(&self) -> i64;
}

/// Production clock backed by the system wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;
impl DaemonCustodyClock for SystemClock {
    fn now_unix(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// Test clock returning a fixed timestamp.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub i64);
impl DaemonCustodyClock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Generation record
// ─────────────────────────────────────────────────────────────────────────

/// A durable generation record. Written atomically with the generation-sequence
/// bump inside one SQLite transaction; a generation is durable only once its
/// handle id, public key, custody discriminants, generation, and evidence
/// digest are all persisted together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonGenerationRecord {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub subject_kind: SubjectKind,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub profile: DaemonCustodyProfile,
    pub generation: u64,
    pub evidence_digest: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────
// DER → P1363 low-S normalization (shared by every platform adapter)
// ─────────────────────────────────────────────────────────────────────────

/// Parse a DER-encoded ECDSA/P-256 signature and return its low-S P1363
/// (`r || s`, 64 bytes) form. Normalization applies `s := n - s` when `s > n/2`
/// (both forms verify; low-S is canonical). A malformed DER encoding or an
/// out-of-range scalar is a typed `corrupted`-class error — never a
/// silently-mangled signature.
pub fn der_signature_to_low_s_p1363(der: &[u8]) -> Result<[u8; 64], RemoteIdentityCustodyError> {
    use p256::ecdsa::Signature;
    let signature = Signature::from_der(der).map_err(|_| {
        RemoteIdentityCustodyError::InvalidEvidence("malformed DER ECDSA signature".into())
    })?;
    let low_s = signature.normalize_s().unwrap_or(signature);
    let bytes = low_s.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a PKCS#11 `CKA_EC_POINT` (a DER `OCTET STRING` wrapping an uncompressed
/// SEC1 point `04 || X || Y`) into affine coordinates. Validates the tag AND the
/// length byte AND the total length, so a malformed encoding that declares the
/// wrong length (e.g. `04 00 04 || X || Y`) is rejected rather than parsed from
/// trailing bytes.
pub fn parse_pkcs11_ec_point(
    der_octet_string: &[u8],
) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
    let malformed =
        || RemoteIdentityCustodyError::InvalidEvidence("malformed PKCS#11 EC point".into());
    // Expect EXACTLY: 0x04 (OCTET STRING) 0x41 (length = 65) 0x04 (uncompressed
    // marker) X(32) Y(32) — 67 bytes total. The length byte MUST equal 65.
    if der_octet_string.len() != 67 || der_octet_string[0] != 0x04 || der_octet_string[1] != 0x41 {
        return Err(malformed());
    }
    let inner = &der_octet_string[2..];
    if inner[0] != 0x04 {
        return Err(malformed());
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&inner[1..33]);
    y.copy_from_slice(&inner[33..65]);
    Ok(RemoteIdentityP256PublicKey { x, y })
}

/// Normalize a raw P1363 (`r || s`) signature to low-S. Zero-r, zero-s, or an
/// out-of-range scalar is a typed error, never normalized.
pub fn normalize_p1363_low_s(signature: &[u8; 64]) -> Result<[u8; 64], RemoteIdentityCustodyError> {
    use p256::ecdsa::Signature;
    let parsed = Signature::from_slice(signature).map_err(|_| {
        RemoteIdentityCustodyError::InvalidEvidence("malformed P1363 ECDSA signature".into())
    })?;
    let low_s = parsed.normalize_s().unwrap_or(parsed);
    let bytes = low_s.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter trait (target-gated real FFI lives behind this)
// ─────────────────────────────────────────────────────────────────────────

/// The platform adapter seam. Real FFI is isolated behind this trait in
/// target-gated modules with owned-handle RAII, exact status translation, no
/// unwind across FFI, and signature DER-to-P1363 normalization.
///
/// Keys are aliased by `(handle, generation)`: the durable record's generation
/// is the single source of truth for which key is active, and each generation's
/// key is immutable. This makes rotation crash-consistent — the provider stages
/// the new generation's key ([`create`](Self::create)), commits the record
/// pointing at it, and only then retires ([`retire`](Self::retire)) the previous
/// generation's key. A crash at any point leaves the record and the key it
/// points at mutually consistent.
pub trait DaemonCustodyAdapter: Send + Sync {
    /// Create a fresh durable non-exportable P-256 key aliased by
    /// `(handle, generation)`. A prior generation's key is left untouched and
    /// stays usable until it is explicitly retired.
    fn create(
        &mut self,
        profile: DaemonCustodyProfile,
        subject_kind: SubjectKind,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError>;

    /// Reopen the key for `(handle, generation)`, returning its public key.
    /// Fails closed ([`RemoteIdentityCustodyError::NotFound`]) if the key is
    /// gone (device reset, keystore invalidation).
    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError>;

    /// Sign a 32-byte digest with the key for `(handle, generation)`, returning
    /// a low-S P1363 signature.
    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError>;

    /// Retire (destroy) exactly the key for `(handle, generation)`. Called only
    /// AFTER a rotation's new generation is durable, so an interrupted rotation
    /// never destroys a key the current record still points at.
    fn retire(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError>;

    /// Destroy every generation's key for the handle (used by `destroy`).
    fn destroy_all(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError>;
}

/// The public material an adapter returns when creating a key. Never carries
/// private bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterKeyMaterial {
    pub public_key: RemoteIdentityP256PublicKey,
    /// Adapter attestation output. Recorded into evidence; never caller bytes.
    pub provider_evidence: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────
// Real-key fake adapter (tests + unsupported-target fallback)
// ─────────────────────────────────────────────────────────────────────────

/// A fake daemon custody adapter holding **real** `p256::ecdsa::SigningKey`s.
///
/// It owns private keys only in process memory and never returns them across
/// the seam; it produces genuine low-S P1363 signatures that the production
/// codec accepts. Real platform adapters are target-gated and added separately.
#[derive(Default)]
pub struct FakeDaemonCustodyAdapter {
    /// Keys aliased by `(handle, generation)`, mirroring a real keystore where
    /// each generation is a distinct immutable key object.
    keys: std::collections::BTreeMap<
        ([u8; 16], u64),
        (p256::ecdsa::SigningKey, DaemonCustodyProfile),
    >,
}

impl std::fmt::Debug for FakeDaemonCustodyAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format private key material.
        f.debug_struct("FakeDaemonCustodyAdapter")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl FakeDaemonCustodyAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live keys (across all handles/generations).
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether a key exists for exactly `(handle, generation)` (tests).
    pub fn has_key(&self, handle: RemoteIdentityCustodyHandleId, generation: u64) -> bool {
        self.keys.contains_key(&(handle.0, generation))
    }

    fn fresh_signing_key() -> p256::ecdsa::SigningKey {
        use rand::Rng;
        loop {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&seed) {
                return key;
            }
        }
    }

    fn public_key_of(key: &p256::ecdsa::SigningKey) -> RemoteIdentityP256PublicKey {
        let point = key.verifying_key().to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().expect("uncompressed point has x"));
        y.copy_from_slice(point.y().expect("uncompressed point has y"));
        RemoteIdentityP256PublicKey { x, y }
    }

    fn attestation(
        profile: DaemonCustodyProfile,
        public_key: &RemoteIdentityP256PublicKey,
    ) -> Vec<u8> {
        // Adapter-output attestation: the platform label plus a fingerprint of
        // the created public key. Contains no caller-supplied bytes.
        let mut fingerprint = Sha256::new();
        fingerprint.update(public_key.x);
        fingerprint.update(public_key.y);
        let mut evidence = Vec::new();
        evidence.extend_from_slice(profile.platform_label().as_bytes());
        evidence.push(0x00);
        evidence.extend_from_slice(&fingerprint.finalize());
        evidence
    }
}

impl DaemonCustodyAdapter for FakeDaemonCustodyAdapter {
    fn create(
        &mut self,
        profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError> {
        let key = Self::fresh_signing_key();
        let public_key = Self::public_key_of(&key);
        let evidence = Self::attestation(profile, &public_key);
        self.keys.insert((handle.0, generation), (key, profile));
        Ok(AdapterKeyMaterial {
            public_key,
            provider_evidence: evidence,
        })
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        self.keys
            .get(&(handle.0, generation))
            .map(|(key, _)| Self::public_key_of(key))
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let (key, _) = self
            .keys
            .get(&(handle.0, generation))
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        let signature: p256::ecdsa::Signature = key
            .sign_prehash(digest)
            .map_err(|_| RemoteIdentityCustodyError::Unavailable("signing failed".into()))?;
        let low_s = signature.normalize_s().unwrap_or(signature);
        let bytes = low_s.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn retire(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        self.keys
            .remove(&(handle.0, generation))
            .map(|_| ())
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn destroy_all(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        let before = self.keys.len();
        self.keys.retain(|(h, _), _| *h != handle.0);
        if self.keys.len() < before {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::NotFound)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Provider (implements the shared RemoteIdentityCustodyProvider seam)
// ─────────────────────────────────────────────────────────────────────────

/// The daemon durable-P-256 custody provider.
///
/// Implements the shared [`RemoteIdentityCustodyProvider`] seam by delegating to
/// a [`DaemonCustodyAdapter`], enforcing the construction-time
/// [`DaemonCustodyProfile`] and the [`DaemonCustodyPolicyGate`], and persisting
/// monotonic generation records through [`SqliteCustodyStore`]. Private bytes
/// never cross this seam.
pub struct DaemonIdentityCustodyProvider<A: DaemonCustodyAdapter> {
    adapter: A,
    profile: DaemonCustodyProfile,
    gate: DaemonCustodyPolicyGate,
    store: SqliteCustodyStore,
    clock: Box<dyn DaemonCustodyClock>,
}

impl<A: DaemonCustodyAdapter> DaemonIdentityCustodyProvider<A> {
    /// Construct a provider over a configured profile, a persistent store, and
    /// an injected clock. The profile is the sole source of custody
    /// classification; caller-supplied evidence never selects or upgrades it.
    pub fn new(
        adapter: A,
        profile: DaemonCustodyProfile,
        store: SqliteCustodyStore,
        clock: Box<dyn DaemonCustodyClock>,
    ) -> Self {
        Self {
            adapter,
            profile,
            gate: DaemonCustodyPolicyGate,
            store,
            clock,
        }
    }

    /// The configured profile.
    pub fn profile(&self) -> DaemonCustodyProfile {
        self.profile
    }

    /// Access the underlying adapter (for tests).
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    /// The current persisted generation high-water mark.
    pub fn generation_high_water(&self) -> Result<u64, RemoteIdentityCustodyError> {
        self.store.current_high_water()
    }

    /// Access the store (tests need its rotation failpoint).
    pub fn store(&self) -> &SqliteCustodyStore {
        &self.store
    }

    fn random_handle() -> RemoteIdentityCustodyHandleId {
        use rand::Rng;
        let mut id = [0u8; 16];
        rand::rng().fill_bytes(&mut id);
        if id.iter().all(|b| *b == 0) {
            id[0] = 1;
        }
        RemoteIdentityCustodyHandleId(id)
    }

    fn build_evidence(
        &self,
        subject_kind: SubjectKind,
        subject_id: [u8; 16],
        generation: u64,
        provider_evidence: &[u8],
    ) -> Result<CustodyEvidence, RemoteIdentityCustodyError> {
        let evidence_digest: [u8; 32] = Sha256::digest(provider_evidence).into();
        let evidence = CustodyEvidence {
            subject_kind,
            subject_id,
            generation,
            custody_class: self.profile.custody_class(),
            presence_mode: self.profile.presence_mode(),
            provider_evidence: provider_evidence.to_vec(),
            evidence_digest,
            observed_at: self.clock.now_unix(),
        };
        // Round-trip through the foundation codec to prove the seam consumes it.
        evidence
            .encode()
            .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?;
        Ok(evidence)
    }
}

impl<A: DaemonCustodyAdapter> RemoteIdentityCustodyProvider for DaemonIdentityCustodyProvider<A> {
    fn generate(
        &mut self,
        subject_kind: SubjectKind,
        custody_class: CustodyClass,
        presence_mode: PresenceMode,
        _provider_evidence: &[u8],
    ) -> Result<
        (
            RemoteIdentityCustodyHandleId,
            RemoteIdentityP256PublicKey,
            CustodyEvidence,
        ),
        RemoteIdentityCustodyError,
    > {
        // Custody is construction-time configuration. The caller may only
        // REQUEST the configured profile's class/presence; the caller-supplied
        // `provider_evidence` is ignored entirely and never recorded, so forged
        // bytes can neither select nor upgrade a custody class.
        if custody_class != self.profile.custody_class() {
            return Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "requested custody class {:?} does not match configured profile {} ({:?})",
                custody_class,
                self.profile.platform_label(),
                self.profile.custody_class()
            )));
        }
        if presence_mode != self.profile.presence_mode() {
            return Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "requested presence {:?} does not match configured profile {} ({:?})",
                presence_mode,
                self.profile.platform_label(),
                self.profile.presence_mode()
            )));
        }
        self.gate.authorize(self.profile, presence_mode)?;

        let handle = Self::random_handle();
        // Reserve the next monotonic generation, then create the key aliased by
        // (handle, generation), then commit the record.
        let generation = self.store.reserve_generation()?;
        let material = self
            .adapter
            .create(self.profile, subject_kind, handle, generation)?;
        let evidence_digest: [u8; 32] = Sha256::digest(&material.provider_evidence).into();
        let now = self.clock.now_unix();
        if let Err(err) = self.store.insert_record(
            NewCustodyRecord {
                handle_id: handle.0,
                subject_kind,
                custody_class: self.profile.custody_class(),
                presence_mode: self.profile.presence_mode(),
                profile: self.profile,
                generation,
                public_key: material.public_key,
                evidence_digest,
            },
            now,
        ) {
            // Fail closed: the record never committed, so retire the orphan key.
            let _ = self.adapter.retire(handle, generation);
            return Err(err);
        }
        let evidence = self.build_evidence(
            subject_kind,
            handle.0,
            generation,
            &material.provider_evidence,
        )?;
        Ok((handle, material.public_key, evidence))
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(RemoteIdentityP256PublicKey, CustodyClass, PresenceMode), RemoteIdentityCustodyError>
    {
        let record = self
            .store
            .load_record(handle)?
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        // Fail closed: confirm the key for the record's generation still exists
        // and its public key matches. If the key was lost (device reset, keystore
        // invalidation), `reopen` propagates NotFound rather than reporting a
        // usable identity that would only fail at signing time.
        let pk = self.adapter.reopen(handle, record.generation)?;
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
        _provider_evidence: &[u8],
    ) -> Result<(RemoteIdentityP256PublicKey, CustodyEvidence), RemoteIdentityCustodyError> {
        let record = self
            .store
            .load_record(handle)?
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        self.gate.authorize(record.profile, record.presence_mode)?;

        let next = self.store.reserve_generation()?;
        // Stage the new generation's key. The previous generation's key
        // (record.generation) is left intact and remains the active signer until
        // the record is flipped below.
        let material = self
            .adapter
            .create(record.profile, record.subject_kind, handle, next)?;
        let evidence_digest: [u8; 32] = Sha256::digest(&material.provider_evidence).into();
        let now = self.clock.now_unix();
        // Publish: durably flip the record to the new generation. On failure the
        // old record + old key are untouched (fail-closed) and the staged new key
        // is retired.
        if let Err(err) =
            self.store
                .update_rotation(handle, next, material.public_key, evidence_digest, now)
        {
            let _ = self.adapter.retire(handle, next);
            return Err(err);
        }
        // Only AFTER the new generation is durably published do we retire the
        // previous generation's key. A retire failure merely leaks an
        // unreferenceable old key; the record already points at the valid new one.
        let _ = self.adapter.retire(handle, record.generation);
        let evidence = self.build_evidence(
            record.subject_kind,
            handle.0,
            next,
            &material.provider_evidence,
        )?;
        Ok((material.public_key, evidence))
    }

    fn destroy(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        if self.store.load_record(handle)?.is_none() {
            return Err(RemoteIdentityCustodyError::NotFound);
        }
        // Best-effort key destruction across every generation; an already-lost
        // key must not block record removal. The monotonic generation sequence
        // is never reset, so a later generate cannot reuse this generation.
        let _ = self.adapter.destroy_all(handle);
        self.store.delete_record(handle)?;
        Ok(())
    }

    fn sign_possession_proof(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        let record = self
            .store
            .load_record(handle)?
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        self.adapter.sign(handle, record.generation, signing_digest)
    }

    fn sign_enrollment_confirmation(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        let record = self
            .store
            .load_record(handle)?
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        self.adapter.sign(handle, record.generation, signing_digest)
    }
}

#[cfg(test)]
mod tests;
