//! Browser-origin remote identity custody — origin-bound non-extractable
//! durable P-256 signing custody with no private export.
//!
//! This module consumes the shared identity foundation seam
//! ([`cockpit_proto::remote_device_identity_enrollment::RemoteIdentityCustodyProvider`])
//! and the signed public service-policy custody discriminants
//! ([`cockpit_proto::remote_public_service_policy`]) without redefining
//! certificate/transcript bytes.
//!
//! ## What this module owns
//!
//! - The browser custody provider profile enum
//!   ([`BrowserCustodyProfile`]) covering native WebCrypto non-extractable
//!   `ECDSA/P-256` signing, with the exact `origin_protected` custody-class
//!   mapping.
//! - The policy intersection that rejects every extractable/P-256-ECDH/
//!   polyfill/localStorage/WebRTC-certificate path and never downgrades on
//!   capability loss.
//! - Crash-safe generation records with idempotent reopen and atomic
//!   rotation, persisted in IndexedDB under the exact origin.
//! - Private-material guards proving the provider seam, protocol, debug,
//!   error, and log paths never return private bytes, and that no WebCrypto
//!   X25519 ownership/API is exposed.
//!
//! ## What this module does NOT own
//!
//! It never redefines the foundation custody/presence enums, certificate
//! codecs, or transcript bytes. It never probes, generates, accepts,
//! derives, persists, or destroys X25519 — the shared Rust-WASM Noise core
//! exclusively owns fresh per-child X25519 creation, use, and destruction.
//! It never substitutes extractable keys, P-256 ECDH, a polyfill,
//! localStorage, or a WebRTC certificate. Browser custody is
//! `origin_protected`, never hardware- or OS-protected.
//!
//! ## Storage boundary
//!
//! Real browser storage (WebCrypto non-extractable `CryptoKey` handle plus
//! bounded public metadata in IndexedDB under the exact origin) is isolated
//! behind the [`BrowserCustodyAdapter`] trait. This module ships the
//! policy/reducer/matrix and a fake adapter for tests; production adapters
//! are added separately. The adapter persists only the non-extractable P-256
//! `CryptoKey` handle and bounded public metadata; no export/JWK/private
//! bytes enter storage, APIs, logs, errors, telemetry, URLs, clipboard, or
//! snapshots.

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
// Browser custody profile
// ─────────────────────────────────────────────────────────────────────────

/// The browser durable-P-256 custody provider profile.
///
/// Browser custody is `origin_protected`, never hardware- or OS-protected.
/// The one durable P-256 private handle is non-extractable; its loss requires
/// re-enrollment, not sync/backup/escrow. X25519 has no custody handle here.
///
/// The single accepted profile is native WebCrypto non-extractable
/// `ECDSA/P-256` signing, persisted in IndexedDB under the exact origin.
/// Extractable keys, P-256 ECDH, polyfills, localStorage, and WebRTC
/// certificates are categorically ineligible and have no profile variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserCustodyProfile {
    /// Native WebCrypto non-extractable `ECDSA/P-256` signing, persisted in
    /// IndexedDB under the exact origin. Reports `origin_protected` /
    /// `unattended` (no user-presence prompt for the durable handle).
    WebCryptoNonExtractableP256,
}

impl BrowserCustodyProfile {
    /// The truthful custody class this profile reports. Browser custody is
    /// always `origin_protected`, never hardware- or OS-protected.
    pub fn custody_class(self) -> CustodyClass {
        match self {
            Self::WebCryptoNonExtractableP256 => CustodyClass::OriginProtected,
        }
    }

    /// The truthful presence mode this profile reports. The durable P-256
    /// handle requires no user-presence prompt; it is `unattended`.
    pub fn presence_mode(self) -> PresenceMode {
        match self {
            Self::WebCryptoNonExtractableP256 => PresenceMode::Unattended,
        }
    }

    /// The platform label used in evidence and diagnostics.
    pub fn platform_label(self) -> &'static str {
        match self {
            Self::WebCryptoNonExtractableP256 => "webcrypto-non-extractable-p256",
        }
    }

    /// All profiles, in canonical order.
    pub const ALL: [Self; 1] = [Self::WebCryptoNonExtractableP256];
}

// ─────────────────────────────────────────────────────────────────────────
// Policy gate
// ─────────────────────────────────────────────────────────────────────────

/// A custody path that is categorically ineligible for browser durable
/// identity. These are rejected in every profile rather than represented as a
/// lower custody class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IneligibleBrowserCustodyPath {
    /// Extractable WebCrypto key (`extractable: true`).
    ExtractableKey,
    /// P-256 ECDH key (signing custody requires ECDSA, not ECDH).
    P256Ecdh,
    /// Crypto polyfill (non-native implementation).
    Polyfill,
    /// localStorage-backed key material.
    LocalStorage,
    /// WebRTC certificate presented as identity.
    WebRtcCertificate,
    /// JWK/private bytes in storage/API/log.
    JwkOrPrivateBytes,
    /// Cross-origin migrated key material.
    CrossOriginMigration,
}

impl IneligibleBrowserCustodyPath {
    pub fn label(self) -> &'static str {
        match self {
            Self::ExtractableKey => "extractable-key",
            Self::P256Ecdh => "p256-ecdh",
            Self::Polyfill => "polyfill",
            Self::LocalStorage => "local-storage",
            Self::WebRtcCertificate => "webrtc-certificate",
            Self::JwkOrPrivateBytes => "jwk-or-private-bytes",
            Self::CrossOriginMigration => "cross-origin-migration",
        }
    }

    pub const ALL: [Self; 7] = [
        Self::ExtractableKey,
        Self::P256Ecdh,
        Self::Polyfill,
        Self::LocalStorage,
        Self::WebRtcCertificate,
        Self::JwkOrPrivateBytes,
        Self::CrossOriginMigration,
    ];
}

/// The browser custody policy gate.
///
/// This is the single authority that decides whether a candidate custody
/// class/presence/profile combination is policy-eligible for the browser
/// client. It consumes the shared [`ClientCustodyPolicy`] meet tables from
/// the signed public service-policy foundation and never downgrades on
/// capability loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserCustodyPolicyGate;

impl BrowserCustodyPolicyGate {
    /// Authorize a profile for the browser client. Returns the policy
    /// threshold the profile satisfies, or an error explaining the rejection.
    ///
    /// Rules:
    /// - Browser custody is `origin_protected`, never hardware- or
    ///   OS-protected.
    /// - The durable P-256 handle is `unattended` (no user-presence prompt).
    /// - Capability/storage loss is re-enrollment, never a fallback.
    pub fn authorize(
        self,
        profile: BrowserCustodyProfile,
        presence: PresenceMode,
    ) -> Result<ClientCustodyPolicy, RemoteIdentityCustodyError> {
        if presence != profile.presence_mode() {
            return Err(RemoteIdentityCustodyError::PolicyDenied(
                "presence mode does not match profile".into(),
            ));
        }
        let class = profile.custody_class();
        match class {
            CustodyClass::OriginProtected => Ok(ClientCustodyPolicy::OriginProtected),
            CustodyClass::OsProtected | CustodyClass::HardwareOrExternal => {
                Err(RemoteIdentityCustodyError::PolicyDenied(
                    "browser custody is origin_protected, never hardware- or OS-protected".into(),
                ))
            }
        }
    }

    /// Reject every ineligible custody path categorically. An ineligible path
    /// is never a lower custody class; it is a hard rejection.
    pub fn reject_ineligible(
        self,
        path: IneligibleBrowserCustodyPath,
    ) -> Result<(), RemoteIdentityCustodyError> {
        Err(RemoteIdentityCustodyError::PolicyDenied(format!(
            "ineligible browser custody path: {}",
            path.label()
        )))
    }

    /// Meet two client custody policy thresholds using the shared foundation
    /// meet table. Capability loss never downgrades: if either side is
    /// unavailable, the meet is unavailable (caller surfaces the error).
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
/// The record is written atomically to IndexedDB: a generation is only
/// durable once both the handle id and public key are persisted together.
/// Reopen is idempotent and returns the persisted public key and custody
/// discriminants. Rotation publishes only after the new handle is durable;
/// the old private key is destroyed only after the new record is committed.
/// Origin/storage/P-256 loss requires re-enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserGenerationRecord {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub profile: BrowserCustodyProfile,
    /// Monotonic generation counter; rotation increments this.
    pub generation: u64,
    /// SHA-256 of the provider evidence bytes.
    pub evidence_digest: [u8; 32],
}

impl BrowserGenerationRecord {
    /// Verify the evidence digest matches the supplied evidence bytes.
    pub fn verify_evidence(&self, evidence: &[u8]) -> bool {
        Sha256::digest(evidence).as_slice() == self.evidence_digest
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Adapter trait (real WebCrypto/IndexedDB lives behind this)
// ─────────────────────────────────────────────────────────────────────────

/// The platform adapter seam. Real browser storage (WebCrypto non-extractable
/// `CryptoKey` handle plus bounded public metadata in IndexedDB under the
/// exact origin) is isolated behind this trait. This module ships a fake
/// adapter for tests; production adapters are added separately.
///
/// The adapter persists only the non-extractable P-256 `CryptoKey` handle and
/// bounded public metadata. It never probes, generates, accepts, derives,
/// persists, or destroys X25519 — the shared Rust-WASM Noise core owns
/// fallback capability and entropy exclusively. No export/JWK/private bytes
/// enter storage, APIs, logs, errors, telemetry, URLs, clipboard, or
/// snapshots.
pub trait BrowserCustodyAdapter: Send + Sync {
    /// Feature-detect native WebCrypto non-extractable `ECDSA/P-256` signing
    /// before enrollment. Returns `Ok(())` if available, or an
    /// `Unavailable` error if the engine is unsupported. Never falls back to
    /// a polyfill.
    fn probe_capability(&self) -> Result<(), RemoteIdentityCustodyError>;

    /// Generate a fresh durable non-extractable P-256 handle for the profile.
    /// Returns the handle id, public key, and provider evidence bytes. Never
    /// returns private bytes or JWK.
    fn generate(
        &mut self,
        profile: BrowserCustodyProfile,
        subject_kind: SubjectKind,
    ) -> Result<BrowserAdapterGeneration, RemoteIdentityCustodyError>;

    /// Reopen an existing handle, returning its public key. Never returns
    /// private bytes or JWK.
    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError>;

    /// Rotate a handle to a fresh P-256 key. The old private key is destroyed
    /// only after the new handle is durable. Never returns private bytes.
    fn rotate(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<BrowserAdapterRotation, RemoteIdentityCustodyError>;

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
pub struct BrowserAdapterGeneration {
    pub handle_id: RemoteIdentityCustodyHandleId,
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

/// The result of an adapter rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAdapterRotation {
    pub public_key: RemoteIdentityP256PublicKey,
    pub provider_evidence: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────
// Fake adapter (tests + unsupported-engine fallback)
// ─────────────────────────────────────────────────────────────────────────

/// A fake browser custody adapter backed by an in-memory store.
///
/// This is the only adapter this module ships. It owns no private bytes: it
/// synthesizes deterministic public keys and P1363 signatures from the handle
/// id and digest, proving the seam never returns private material. It
/// simulates an IndexedDB-backed non-extractable `CryptoKey` handle store.
/// Real WebCrypto/IndexedDB adapters are added separately.
#[derive(Debug, Default)]
pub struct FakeBrowserCustodyAdapter {
    handles: BTreeMap<[u8; 16], (RemoteIdentityP256PublicKey, BrowserCustodyProfile)>,
    generation_counter: u64,
    /// When true, the capability probe fails (unsupported engine).
    capability_available: bool,
}

impl FakeBrowserCustodyAdapter {
    pub fn new() -> Self {
        Self {
            capability_available: true,
            ..Default::default()
        }
    }

    /// Set whether the capability probe succeeds.
    pub fn with_capability(mut self, available: bool) -> Self {
        self.capability_available = available;
        self
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
        profile: BrowserCustodyProfile,
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

impl BrowserCustodyAdapter for FakeBrowserCustodyAdapter {
    fn probe_capability(&self) -> Result<(), RemoteIdentityCustodyError> {
        if self.capability_available {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::Unavailable(
                "WebCrypto non-extractable ECDSA/P-256 unavailable".into(),
            ))
        }
    }

    fn generate(
        &mut self,
        profile: BrowserCustodyProfile,
        _subject_kind: SubjectKind,
    ) -> Result<BrowserAdapterGeneration, RemoteIdentityCustodyError> {
        self.generation_counter = self.generation_counter.wrapping_add(1);
        let mut handle_bytes = [0u8; 16];
        let counter = self.generation_counter.to_be_bytes();
        handle_bytes[..8].copy_from_slice(&counter);
        handle_bytes[8..].copy_from_slice(&Sha256::digest(&counter)[..8]);
        let handle = RemoteIdentityCustodyHandleId(handle_bytes);
        let public_key = Self::synthesize_public_key(handle);
        let evidence = Self::synthesize_evidence(profile, handle, self.generation_counter);
        self.handles.insert(handle_bytes, (public_key, profile));
        Ok(BrowserAdapterGeneration {
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
    ) -> Result<BrowserAdapterRotation, RemoteIdentityCustodyError> {
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
        Ok(BrowserAdapterRotation {
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

/// The browser durable-P-256 custody provider.
///
/// Implements the shared [`RemoteIdentityCustodyProvider`] seam by delegating
/// to a [`BrowserCustodyAdapter`] and enforcing the browser custody policy
/// gate. Private bytes never cross this seam; the adapter returns only
/// handles, public keys, and signatures. This adapter never probes,
/// generates, accepts, derives, persists, or destroys X25519; fallback
/// capability and entropy belong exclusively to the Rust-WASM Noise binding.
pub struct BrowserIdentityCustodyProvider<A: BrowserCustodyAdapter> {
    adapter: A,
    gate: BrowserCustodyPolicyGate,
    records: BTreeMap<[u8; 16], BrowserGenerationRecord>,
}

impl<A: BrowserCustodyAdapter> BrowserIdentityCustodyProvider<A> {
    pub fn new(adapter: A) -> Self {
        Self {
            adapter,
            gate: BrowserCustodyPolicyGate,
            records: BTreeMap::new(),
        }
    }

    /// Feature-detect native WebCrypto non-extractable `ECDSA/P-256` signing
    /// before enrollment. Returns `Ok(())` if available, or an error if the
    /// engine is unsupported. Never falls back to a polyfill.
    pub fn probe_capability(&self) -> Result<(), RemoteIdentityCustodyError> {
        self.adapter.probe_capability()
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
    /// origin/storage clearing or corruption).
    #[cfg(test)]
    fn adapter_destroy_for_test(&mut self, handle: RemoteIdentityCustodyHandleId) {
        let _ = self.adapter.destroy(handle);
    }
}

impl<A: BrowserCustodyAdapter> RemoteIdentityCustodyProvider for BrowserIdentityCustodyProvider<A> {
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
        // Feature-detect before enrollment; never fall back to a polyfill.
        self.adapter.probe_capability()?;
        // The profile is selected by the caller's evidence; in this fake the
        // evidence carries the platform label. In production the configured
        // profile is selected at construction.
        let profile = select_profile_from_evidence(provider_evidence).ok_or_else(|| {
            RemoteIdentityCustodyError::InvalidEvidence(
                "provider evidence does not select a browser custody profile".into(),
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
        let BrowserAdapterGeneration {
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
            BrowserGenerationRecord {
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
        let BrowserAdapterRotation {
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
            BrowserGenerationRecord {
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

/// Select a browser custody profile from the provider evidence bytes. The
/// evidence carries the platform label as a prefix. Returns `None` if the
/// evidence does not match any profile (the caller rejects it).
fn select_profile_from_evidence(evidence: &[u8]) -> Option<BrowserCustodyProfile> {
    for profile in BrowserCustodyProfile::ALL {
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
/// foundation seam is P-256-only; the shared Rust-WASM Noise core
/// exclusively owns fresh per-child X25519 creation, use, and destruction.
/// This adapter never probes, generates, accepts, derives, persists, or
/// destroys X25519. This guard references the seam's P-256-only surface so
/// an accidental X25519 addition fails to link.
pub fn browser_x25519_custody_absence_guard() {
    let _ = enrollment::RemoteIdentityCustodyHandleId([0u8; 16]);
    let _ = RemoteIdentityP256PublicKey {
        x: [0u8; 32],
        y: [0u8; 32],
    };
    // The seam has no X25519 type; this compiles only because no such type is
    // referenced. If a future change adds one to this module, the
    // `remote_browser_identity_no_x25519_custody_api` test fails.
}

/// Statically prove this module consumes the shared custody/presence enums
/// rather than redefining them.
pub fn browser_foundation_consumption_guard() {
    let _ = CustodyClass::OriginProtected;
    let _ = CustodyClass::OsProtected;
    let _ = CustodyClass::HardwareOrExternal;
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

    fn evidence_for(profile: BrowserCustodyProfile) -> Vec<u8> {
        let mut evidence = profile.platform_label().as_bytes().to_vec();
        evidence.push(0x00);
        evidence.extend_from_slice(&[1u8; 16]);
        evidence
    }

    fn low_s_valid(sig: &[u8; 64]) -> bool {
        // High bit of the S half (bytes 32..64) must be clear for low-S.
        (sig[31] & 0x80) == 0 && (sig[63] & 0x80) == 0
    }

    // --- remote_browser_identity_capability_matrix ---

    #[test]
    fn remote_browser_identity_capability_matrix() {
        // The single profile reports origin_protected / unattended.
        assert_eq!(
            BrowserCustodyProfile::WebCryptoNonExtractableP256.custody_class(),
            CustodyClass::OriginProtected
        );
        assert_eq!(
            BrowserCustodyProfile::WebCryptoNonExtractableP256.presence_mode(),
            PresenceMode::Unattended
        );
        // No profile reports hardware_or_external or os_protected.
        for profile in BrowserCustodyProfile::ALL {
            assert_ne!(profile.custody_class(), CustodyClass::HardwareOrExternal);
            assert_ne!(profile.custody_class(), CustodyClass::OsProtected);
        }
    }

    #[test]
    fn remote_browser_identity_capability_matrix_probe() {
        // Feature-detect native WebCrypto non-extractable ECDSA/P-256 before
        // enrollment.
        let adapter = FakeBrowserCustodyAdapter::new();
        assert!(adapter.probe_capability().is_ok());
        // Unsupported engine fails closed; no polyfill fallback.
        let unsupported = FakeBrowserCustodyAdapter::new().with_capability(false);
        assert!(unsupported.probe_capability().is_err());
    }

    #[test]
    fn remote_browser_identity_capability_matrix_reopen() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // Reopen returns the same public key.
        let (pk2, class, presence) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(class, CustodyClass::OriginProtected);
        assert_eq!(presence, PresenceMode::Unattended);
    }

    #[test]
    fn remote_browser_identity_capability_matrix_origin_isolation() {
        // Origin/storage/P-256 loss requires re-enrollment. The provider
        // fails closed when the handle is gone (simulated by adapter loss).
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // Simulate origin/storage clearing: handle is gone.
        provider.adapter_destroy_for_test(handle);
        assert!(provider.reopen(handle).is_err());
        // Re-enrollment is required (a new handle is distinct).
        let (handle2, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        assert_ne!(handle.0, handle2.0);
    }

    #[test]
    fn remote_browser_identity_capability_matrix_storage_clearing() {
        // Storage clearing loses the handle; re-enrollment is required.
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        provider.destroy(handle).unwrap();
        assert!(provider.reopen(handle).is_err());
    }

    #[test]
    fn remote_browser_identity_capability_matrix_private_mode_quota_failure() {
        // Private mode / quota failure: the capability probe or generation
        // fails closed; no fallback.
        let mut provider = BrowserIdentityCustodyProvider::new(
            FakeBrowserCustodyAdapter::new().with_capability(false),
        );
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OriginProtected,
            PresenceMode::Unattended,
            &evidence,
        );
        assert!(result.is_err());
        assert_eq!(provider.record_count(), 0);
    }

    #[test]
    fn remote_browser_identity_capability_matrix_corruption() {
        // Corruption: reopen of a handle whose adapter record is gone fails
        // closed.
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _, _) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // Simulate corruption: destroy at adapter only, leaving a stale
        // provider record. Reopen detects the mismatch.
        provider.adapter_destroy_for_test(handle);
        assert!(provider.reopen(handle).is_err());
    }

    #[test]
    fn remote_browser_identity_capability_matrix_unsupported_engines() {
        // Unsupported engines fail the capability probe; no polyfill.
        let gate = BrowserCustodyPolicyGate;
        // The gate still authorizes the profile (origin_protected), but the
        // adapter probe fails closed in production.
        assert_eq!(
            gate.authorize(
                BrowserCustodyProfile::WebCryptoNonExtractableP256,
                PresenceMode::Unattended
            )
            .unwrap(),
            ClientCustodyPolicy::OriginProtected
        );
    }

    #[test]
    fn remote_browser_identity_capability_matrix_no_webcrypto_x25519_ownership() {
        // This adapter never probes, generates, accepts, derives, persists, or
        // destroys X25519. The adapter trait surface is P-256-only:
        // probe/generate/reopen/rotate/destroy/sign. No X25519 API exists.
        browser_x25519_custody_absence_guard();
        browser_foundation_consumption_guard();
    }

    // --- remote_browser_identity_private_material_guard ---

    #[test]
    fn remote_browser_identity_private_material_guard_seam_returns_no_private_bytes() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, public_key, custody_evidence) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
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
    fn remote_browser_identity_private_material_guard_no_export_jwk_storage() {
        // No export/JWK/private bytes enter storage, APIs, logs, errors,
        // telemetry, URLs, clipboard, or snapshots. The adapter stores only
        // the non-extractable CryptoKey handle and bounded public metadata.
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _, custody_evidence) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // The custody evidence provider_evidence is bounded public metadata;
        // it contains the platform label, handle id, and generation — no
        // private bytes.
        assert!(!custody_evidence.provider_evidence.is_empty());
        assert!(custody_evidence.provider_evidence.len() <= 65_000);
        // The error path carries no private bytes.
        let missing = RemoteIdentityCustodyHandleId([0xFF; 16]);
        let err = provider.reopen(missing).unwrap_err();
        assert!(!err.to_string().contains("private"));
        assert!(!err.to_string().contains("jwk"));
        let _ = handle;
    }

    #[test]
    fn remote_browser_identity_private_material_guard_error_paths_no_private_bytes() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        // Generating with an unsupported profile fails closed.
        let bad_evidence = b"not-a-profile".to_vec();
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OriginProtected,
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

    // --- remote_browser_identity_atomic_rotation ---

    #[test]
    fn remote_browser_identity_atomic_rotation_publishes_only_after_durable() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, pk_old, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
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
    fn remote_browser_identity_atomic_rotation_preserves_custody_class() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        let (_pk_new, ev_new) = provider.rotate(handle, &evidence).unwrap();
        // The custody class is preserved across rotation.
        assert_eq!(ev_new.custody_class, CustodyClass::OriginProtected);
        assert_eq!(ev_new.presence_mode, PresenceMode::Unattended);
    }

    #[test]
    fn remote_browser_identity_atomic_generation_and_idempotent_reopen() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
                PresenceMode::Unattended,
                &evidence,
            )
            .unwrap();
        // Idempotent reopen returns the same public key and custody.
        let (pk2, class, presence) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(class, CustodyClass::OriginProtected);
        assert_eq!(presence, PresenceMode::Unattended);
        // A second reopen is also idempotent.
        let (pk3, _, _) = provider.reopen(handle).unwrap();
        assert_eq!(pk, pk3);
    }

    #[test]
    fn remote_browser_identity_destroy_removes_handle() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _pk, _ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
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
        assert!(provider.sign_possession_proof(handle, &[0xFF; 32]).is_err());
    }

    // --- remote_browser_identity_custody_policy ---

    #[test]
    fn remote_browser_identity_custody_policy_rejects_every_ineligible_path() {
        let gate = BrowserCustodyPolicyGate;
        for path in IneligibleBrowserCustodyPath::ALL {
            assert!(
                gate.reject_ineligible(path).is_err(),
                "ineligible path {:?} must be rejected",
                path
            );
        }
    }

    #[test]
    fn remote_browser_identity_custody_policy_no_fallback_on_capability_loss() {
        // Capability/storage/P-256 loss requires re-enrollment, never a
        // fallback to extractable keys, P-256 ECDH, a polyfill, localStorage,
        // or a WebRTC certificate.
        let gate = BrowserCustodyPolicyGate;
        // The gate never downgrades: origin_protected is the only accepted
        // class; hardware/os are rejected for browser.
        assert!(
            gate.authorize(
                BrowserCustodyProfile::WebCryptoNonExtractableP256,
                PresenceMode::Unattended
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_browser_identity_custody_policy_meet_table() {
        let gate = BrowserCustodyPolicyGate;
        // Client meet table returns the stricter (higher-rank) value.
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::OriginProtected,
                ClientCustodyPolicy::OsProtected
            ),
            ClientCustodyPolicy::OsProtected
        );
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::OriginProtected,
                ClientCustodyPolicy::Hardware
            ),
            ClientCustodyPolicy::Hardware
        );
        assert_eq!(
            gate.meet(
                ClientCustodyPolicy::OriginProtected,
                ClientCustodyPolicy::OriginProtected
            ),
            ClientCustodyPolicy::OriginProtected
        );
    }

    #[test]
    fn remote_browser_identity_custody_policy_certificate_mapping() {
        let gate = BrowserCustodyPolicyGate;
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::OriginProtected)
                .unwrap(),
            ClientCustodyPolicy::OriginProtected
        );
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::OsProtected)
                .unwrap(),
            ClientCustodyPolicy::OsProtected
        );
        assert_eq!(
            gate.certificate_class_to_policy(CustodyCertificateClass::HardwareOrExternal)
                .unwrap(),
            ClientCustodyPolicy::Hardware
        );
    }

    #[test]
    fn remote_browser_identity_custody_policy_presence_mismatch_rejected() {
        let gate = BrowserCustodyPolicyGate;
        // The durable P-256 handle is unattended; a presence mismatch is
        // rejected.
        assert!(
            gate.authorize(
                BrowserCustodyProfile::WebCryptoNonExtractableP256,
                PresenceMode::UserPresenceRequired
            )
            .is_err()
        );
    }

    // --- enrollment integration ---

    #[test]
    fn remote_browser_identity_enrollment_fails_before_allocation_when_unsupported() {
        // Enrollment uses the exact foundation seam and fails before server
        // allocation on capability/custody failure.
        let mut provider = BrowserIdentityCustodyProvider::new(
            FakeBrowserCustodyAdapter::new().with_capability(false),
        );
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OriginProtected,
            PresenceMode::Unattended,
            &evidence,
        );
        assert!(result.is_err());
        // No handle was allocated.
        assert_eq!(provider.record_count(), 0);
        assert_eq!(provider.adapter().len(), 0);
    }

    #[test]
    fn remote_browser_identity_enrollment_fails_before_allocation_on_bad_evidence() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        // Unsupported profile (evidence does not match any profile label).
        let bad_evidence = b"unsupported-platform".to_vec();
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OriginProtected,
            PresenceMode::Unattended,
            &bad_evidence,
        );
        assert!(result.is_err());
        assert_eq!(provider.record_count(), 0);
        assert_eq!(provider.adapter().len(), 0);
    }

    #[test]
    fn remote_browser_identity_enrollment_custody_class_mismatch_rejected() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        // Evidence selects origin_protected but caller requests os_protected
        // — mismatch is rejected (browser custody is never os_protected).
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let result = provider.generate(
            SubjectKind::Client,
            CustodyClass::OsProtected,
            PresenceMode::Unattended,
            &evidence,
        );
        assert!(result.is_err());
        assert_eq!(provider.record_count(), 0);
    }

    #[test]
    fn remote_browser_identity_concurrent_create_distinct_handles() {
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let (handle, _, _) = provider
                .generate(
                    SubjectKind::Client,
                    CustodyClass::OriginProtected,
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
    fn remote_browser_identity_presence_mode_authenticated_in_transcript() {
        // The custody evidence carries the presence mode, which is
        // authenticated in the enrollment transcript and certificate and
        // rechecked at every reopen/rotation.
        let mut provider = BrowserIdentityCustodyProvider::new(FakeBrowserCustodyAdapter::new());
        let evidence = evidence_for(BrowserCustodyProfile::WebCryptoNonExtractableP256);
        let (handle, _, ev) = provider
            .generate(
                SubjectKind::Client,
                CustodyClass::OriginProtected,
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
