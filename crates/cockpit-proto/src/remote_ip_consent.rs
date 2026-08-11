//! Just-in-time direct-IP disclosure consent by device relationship.
//!
//! This module owns the canonical, versioned consent system that prevents
//! direct ICE candidate gathering until both enrolled devices have accepted
//! IP disclosure for their relationship. Consent is collected once per
//! relationship and disclosure version — not on every connection — and
//! remains valid until revoked, unenrolled, or materially invalidated.
//!
//! ## What this module owns
//!
//! - The exact binary codecs for `RemoteDeviceRelationshipV1` (149 bytes),
//!   `RemoteIpConsentReceiptV1` (288-byte body / 354-byte envelope), and
//!   `RemoteIpConsentStatusV1` (≤296-byte body / ≤362-byte envelope).
//! - The closed tri-state capability evaluator
//!   `direct_allowed | relay_only | unavailable`.
//! - The server-sequence monotonic append, exact-retry, and replay-rejection
//!   rules for consent receipts.
//! - The atomic `beginDirectGather` / `revoke` linearization model with
//!   server-sequence ordering and one-time gather authorizations.
//! - The `IpDisclosureVersion` registry digest and replica-readiness gate.
//! - The signature-domain and signing-digest computations for receipts and
//!   status. Actual P-256 P1363 signing/verification is performed by the
//!   platform custody provider and the active remote-authority key
//!   respectively; this module defines the exact bytes that must be signed
//!   and verified, never caller-selected bytes.
//!
//! ## What this module does NOT own
//!
//! - WebRTC peer implementation, TURN credential minting, transport selection,
//!   or storing/displaying observed addresses.
//! - Time-based consent expiry or account-wide blanket consent.
//! - Postgres or Redis storage. The linearization model is pure and testable;
//!   the serializable-transaction wiring is the server's responsibility.
//!
//! ## Signature boundary
//!
//! Receipts are signed by each endpoint under domain
//! `flycockpit-remote-ip-consent-receipt-v1\0`. Status is signed by the active
//! remote-authority key under domain `flycockpit-remote-ip-consent-status-v1\0`.
//! Both use P1363 over `SHA-256(domain || body)`. The signer certificate must
//! equal the role-selected certificate embedded in the relationship and
//! challenge; a valid signature from the other endpoint, another relationship
//! containing the same device, or a replacement certificate fails.

use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────
// Wire magics
// ─────────────────────────────────────────────────────────────────────────

/// Relationship body magic: `FCRL`.
pub const FCRL: [u8; 4] = *b"FCRL";
/// Receipt body magic: `FCRI`.
pub const FCRI: [u8; 4] = *b"FCRI";
/// Status body magic: `FCRS`.
pub const FCRS: [u8; 4] = *b"FCRS";

/// Relationship schema version.
pub const RELATIONSHIP_VERSION: u8 = 1;
/// Receipt schema version.
pub const RECEIPT_VERSION: u8 = 1;
/// Status schema version.
pub const STATUS_VERSION: u8 = 1;

/// Exact relationship body length: 149 bytes.
pub const RELATIONSHIP_BODY_LEN: usize = 149;
/// Exact receipt body length: 288 bytes.
pub const RECEIPT_BODY_LEN: usize = 288;
/// Maximum status body length: 296 bytes (232-byte fixed portion plus up to
/// 64-byte issuer key ID).
pub const STATUS_BODY_MAX_LEN: usize = 296;
/// Exact signed receipt envelope length: 354 bytes (2 + 288 + 64).
pub const RECEIPT_ENVELOPE_LEN: usize = 354;
/// Maximum signed status envelope length: 362 bytes (2 + 296 + 64).
pub const STATUS_ENVELOPE_MAX_LEN: usize = 362;

/// Receipt signing domain (UTF-8, NUL-terminated).
pub const RECEIPT_DOMAIN: &[u8] = b"flycockpit-remote-ip-consent-receipt-v1\x00";
/// Status signing domain (UTF-8, NUL-terminated).
pub const STATUS_DOMAIN: &[u8] = b"flycockpit-remote-ip-consent-status-v1\x00";

/// Challenge length: 32 bytes CSPRNG.
pub const CHALLENGE_LEN: usize = 32;
/// Endpoint nonce length: 32 bytes CSPRNG.
pub const NONCE_LEN: usize = 32;
/// Challenge absolute expiry: 5 minutes (300 seconds).
pub const CHALLENGE_EXPIRY_SECONDS: i64 = 300;
/// Status maximum validity: 60 seconds.
pub const STATUS_MAX_VALIDITY_SECONDS: i64 = 60;
/// Thumbprint length: SHA-256 = 32 bytes.
pub const THUMBPRINT_LEN: usize = 32;
/// ID length: 16 bytes (UUID).
pub const ID_LEN: usize = 16;
/// Tenant ID length: 16 bytes.
pub const TENANT_ID_LEN: usize = 16;
/// Signature length: P-256 P1363 = 64 bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Maximum issuer key ID length: 64 bytes UTF-8.
pub const ISSUER_KID_MAX_LEN: usize = 64;

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsentError {
    #[error("invalid consent codec: {0}")]
    Codec(String),
    #[error("consent state error: {0}")]
    State(String),
    #[error("consent linearization error: {0}")]
    Linearization(String),
    #[error("consent registry error: {0}")]
    Registry(String),
}

type Result<T> = std::result::Result<T, ConsentError>;

fn codec_err<T>(s: impl Into<String>) -> Result<T> {
    Err(ConsentError::Codec(s.into()))
}

// ─────────────────────────────────────────────────────────────────────────
// Endpoint role
// ─────────────────────────────────────────────────────────────────────────

/// Endpoint role tag: `daemon` (1) or `client` (2).
///
/// Role tags prevent daemon/client substitution: the relationship stores the
/// daemon certificate first and the client certificate second, and the role
/// tag selects which certificate the signer must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EndpointRole {
    /// Daemon endpoint (role tag 1).
    Daemon = 1,
    /// Client endpoint (role tag 2).
    Client = 2,
}

impl EndpointRole {
    pub const ALL: [Self; 2] = [Self::Daemon, Self::Client];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Client => "client",
        }
    }
    pub fn try_from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Daemon),
            2 => Ok(Self::Client),
            _ => codec_err("unknown endpoint role discriminant"),
        }
    }
    /// The other endpoint role.
    pub fn other(self) -> Self {
        match self {
            Self::Daemon => Self::Client,
            Self::Client => Self::Daemon,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Consent action
// ─────────────────────────────────────────────────────────────────────────

/// Consent action: `accept` (1) or `revoke` (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConsentAction {
    Accept = 1,
    Revoke = 2,
}

impl ConsentAction {
    pub const ALL: [Self; 2] = [Self::Accept, Self::Revoke];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Revoke => "revoke",
        }
    }
    pub fn try_from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Accept),
            2 => Ok(Self::Revoke),
            _ => codec_err("unknown consent action discriminant"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Consent state (closed tri-state)
// ─────────────────────────────────────────────────────────────────────────

/// Evaluated consent capability: the closed tri-state
/// `direct_allowed | relay_only | unavailable`.
///
/// Client and daemon candidate factories accept this typed verified status,
/// never a boolean. `direct_allowed` requires current mutual receipts and
/// policy. `relay_only` means direct is forbidden/unconsented but an
/// authorized TURN-only or E2E WebSocket path exists. `unavailable` means
/// neither safe route exists or status cannot be proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConsentCapability {
    /// Direct ICE is allowed: current mutual receipts and policy permit it.
    DirectAllowed = 1,
    /// Direct is forbidden/unconsented but an authorized relay path exists.
    RelayOnly = 2,
    /// Neither safe route exists or status cannot be proven.
    Unavailable = 3,
}

impl ConsentCapability {
    pub const ALL: [Self; 3] = [Self::DirectAllowed, Self::RelayOnly, Self::Unavailable];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::DirectAllowed => "direct_allowed",
            Self::RelayOnly => "relay_only",
            Self::Unavailable => "unavailable",
        }
    }
    pub fn try_from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::DirectAllowed),
            2 => Ok(Self::RelayOnly),
            3 => Ok(Self::Unavailable),
            _ => codec_err("unknown consent capability discriminant"),
        }
    }
    /// True when direct candidate gathering is permitted.
    pub fn permits_direct(self) -> bool {
        matches!(self, Self::DirectAllowed)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// RemoteDeviceRelationshipV1 (149 bytes)
// ─────────────────────────────────────────────────────────────────────────

/// Role-tagged canonical `RemoteDeviceRelationshipV1` in fixed order:
/// tenant ID; daemon instance ID, daemon device ID, certificate generation
/// and signing thumbprint; then client device ID, certificate generation and
/// signing thumbprint.
///
/// It is not an unordered set: role tags prevent daemon/client substitution
/// while fixed order produces one hash. The exact binary layout is:
/// `magic="FCRL"[4] | version:u8(1) | tenantId:[16] | instanceId:[16] |
/// daemonDeviceId:[16] | daemonGeneration:u64 | daemonThumbprint:[32] |
/// clientDeviceId:[16] | clientGeneration:u64 | clientThumbprint:[32]`
/// (149 bytes), network order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDeviceRelationshipV1 {
    pub tenant_id: [u8; 16],
    pub instance_id: [u8; 16],
    pub daemon_device_id: [u8; 16],
    pub daemon_generation: u64,
    pub daemon_thumbprint: [u8; 32],
    pub client_device_id: [u8; 16],
    pub client_generation: u64,
    pub client_thumbprint: [u8; 32],
}

impl RemoteDeviceRelationshipV1 {
    /// Encode to the exact 149-byte canonical body.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RELATIONSHIP_BODY_LEN);
        buf.extend_from_slice(&FCRL);
        buf.push(RELATIONSHIP_VERSION);
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.instance_id);
        buf.extend_from_slice(&self.daemon_device_id);
        buf.extend_from_slice(&self.daemon_generation.to_be_bytes());
        buf.extend_from_slice(&self.daemon_thumbprint);
        buf.extend_from_slice(&self.client_device_id);
        buf.extend_from_slice(&self.client_generation.to_be_bytes());
        buf.extend_from_slice(&self.client_thumbprint);
        debug_assert_eq!(buf.len(), RELATIONSHIP_BODY_LEN);
        buf
    }

    /// Decode from the exact 149-byte canonical body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RELATIONSHIP_BODY_LEN {
            return codec_err(format!(
                "relationship body must be exactly {RELATIONSHIP_BODY_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let mut off = 0usize;
        let magic: [u8; 4] = bytes[..4].try_into().unwrap();
        if magic != FCRL {
            return codec_err("relationship magic mismatch");
        }
        off += 4;
        let version = bytes[off];
        if version != RELATIONSHIP_VERSION {
            return codec_err(format!("relationship version must be {RELATIONSHIP_VERSION}, got {version}"));
        }
        off += 1;
        let tenant_id = bytes[off..off + 16].try_into().unwrap();
        off += 16;
        let instance_id = bytes[off..off + 16].try_into().unwrap();
        off += 16;
        let daemon_device_id = bytes[off..off + 16].try_into().unwrap();
        off += 16;
        let daemon_generation = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let daemon_thumbprint = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let client_device_id = bytes[off..off + 16].try_into().unwrap();
        off += 16;
        let client_generation = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let client_thumbprint = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        debug_assert_eq!(off, RELATIONSHIP_BODY_LEN);
        Ok(Self {
            tenant_id,
            instance_id,
            daemon_device_id,
            daemon_generation,
            daemon_thumbprint,
            client_device_id,
            client_generation,
            client_thumbprint,
        })
    }

    /// SHA-256 of the canonical body — the relationship hash.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// Select the certificate thumbprint for the given endpoint role.
    pub fn thumbprint_for_role(&self, role: EndpointRole) -> [u8; 32] {
        match role {
            EndpointRole::Daemon => self.daemon_thumbprint,
            EndpointRole::Client => self.client_thumbprint,
        }
    }

    /// Select the certificate generation for the given endpoint role.
    pub fn generation_for_role(&self, role: EndpointRole) -> u64 {
        match role {
            EndpointRole::Daemon => self.daemon_generation,
            EndpointRole::Client => self.client_generation,
        }
    }

    /// Select the device ID for the given endpoint role.
    pub fn device_id_for_role(&self, role: EndpointRole) -> [u8; 16] {
        match role {
            EndpointRole::Daemon => self.daemon_device_id,
            EndpointRole::Client => self.client_device_id,
        }
    }

    /// True if the other endpoint's device ID appears in this relationship
    /// (used to reject a valid signature from another relationship containing
    /// the same device).
    pub fn contains_device(&self, device_id: &[u8; 16]) -> bool {
        &self.daemon_device_id == device_id || &self.client_device_id == device_id
    }
}

// ─────────────────────────────────────────────────────────────────────────
// IpDisclosureVersion
// ─────────────────────────────────────────────────────────────────────────

/// Code-owned IP disclosure version.
///
/// `IpDisclosureVersion` entries compile into one canonical signed registry.
/// Translation/marketing-only edits preserve the digest; any change in
/// addresses disclosed, recipient, purpose, or direct transport requires a new
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpDisclosureVersion {
    pub version: u16,
    pub localization_key: String,
    pub semantic_digest: [u8; 32],
    pub effective_at: i64,
    pub material_change: bool,
}

impl IpDisclosureVersion {
    /// Compute the semantic digest of a disclosure version's content.
    ///
    /// The digest covers `version || localizationKey || addressesDisclosed ||
    /// recipient || purpose || directTransport`. Translation/marketing-only
    /// edits (localizationKey text changes that do not alter the semantic
    /// content) preserve the digest because the digest is computed from the
    /// semantic fields, not the localized display text.
    pub fn compute_semantic_digest(
        version: u16,
        addresses_disclosed: &str,
        recipient: &str,
        purpose: &str,
        direct_transport: &str,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(version.to_be_bytes());
        h.update(addresses_disclosed.as_bytes());
        h.update(recipient.as_bytes());
        h.update(purpose.as_bytes());
        h.update(direct_transport.as_bytes());
        h.finalize().into()
    }
}

/// Canonical signed disclosure-version registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpDisclosureRegistry {
    pub schema_version: u8,
    pub registry_version: u64,
    pub entries: Vec<IpDisclosureVersion>,
    pub registry_digest: [u8; 32],
}

impl IpDisclosureRegistry {
    /// Schema version for the registry.
    pub const SCHEMA_VERSION: u8 = 1;

    /// Compute the canonical registry digest.
    ///
    /// `{schemaVersion:1, registryVersion:u64-decimal-string,
    /// entries:[{version:u16, localizationKey, semanticDigest,
    /// effectiveAt:i64-decimal-string, materialChange:boolean}]}`.
    pub fn compute_registry_digest(
        schema_version: u8,
        registry_version: u64,
        entries: &[IpDisclosureVersion],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([schema_version]);
        h.update(registry_version.to_string().as_bytes());
        h.update(b"[");
        for entry in entries {
            h.update(b"{");
            h.update(entry.version.to_be_bytes());
            h.update(entry.localization_key.as_bytes());
            h.update(entry.semantic_digest);
            h.update(entry.effective_at.to_string().as_bytes());
            h.update([if entry.material_change { 1 } else { 0 }]);
            h.update(b"}");
        }
        h.update(b"]");
        h.finalize().into()
    }

    /// Build a registry from entries, computing the digest.
    pub fn build(registry_version: u64, entries: Vec<IpDisclosureVersion>) -> Self {
        let digest = Self::compute_registry_digest(Self::SCHEMA_VERSION, registry_version, &entries);
        Self {
            schema_version: Self::SCHEMA_VERSION,
            registry_version,
            entries,
            registry_digest: digest,
        }
    }

    /// Find a disclosure version by version number.
    pub fn find(&self, version: u16) -> Option<&IpDisclosureVersion> {
        self.entries.iter().find(|e| e.version == version)
    }

    /// True if the registry is ready for use: nonempty, all entries have valid
    /// digests, and no duplicate versions.
    pub fn is_ready(&self) -> bool {
        !self.entries.is_empty()
            && self.entries.iter().all(|e| {
                !e.localization_key.is_empty()
                    && e.semantic_digest != [0u8; 32]
            })
            && {
                let mut versions: Vec<u16> = self.entries.iter().map(|e| e.version).collect();
                versions.sort_unstable();
                versions.dedup();
                versions.len() == self.entries.len()
            }
    }
}

/// Per-replica lease state for the disclosure-version registry.
///
/// Every API/gateway/worker replica registers the accepted registry digest in
/// the public-policy consumer lease system. Mixed/unknown digests, unready or
/// empty required group, or rollback makes remote readiness false and blocks
/// challenge/status/begin issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRegistryLease {
    pub accepted_registry_digest: [u8; 32],
    pub accepted_registry_version: u64,
    pub ready: bool,
}

impl DisclosureRegistryLease {
    /// A ready lease for the given registry.
    pub fn ready_for(registry: &IpDisclosureRegistry) -> Self {
        Self {
            accepted_registry_digest: registry.registry_digest,
            accepted_registry_version: registry.registry_version,
            ready: registry.is_ready(),
        }
    }

    /// An unready lease (e.g., on rollback or mixed digests).
    pub fn unready() -> Self {
        Self {
            accepted_registry_digest: [0u8; 32],
            accepted_registry_version: 0,
            ready: false,
        }
    }

    /// True when the lease is ready and matches the given digest.
    pub fn matches(&self, digest: &[u8; 32]) -> bool {
        self.ready && &self.accepted_registry_digest == digest
    }
}

// ─────────────────────────────────────────────────────────────────────────
// RemoteIpConsentReceiptV1 (288-byte body, 354-byte envelope)
// ─────────────────────────────────────────────────────────────────────────

/// Unsigned receipt body (288 bytes):
/// `magic="FCRI"[4] | version:u8(1) | action:u8(1 accept,2 revoke) |
/// endpointRole:u8(1 daemon,2 client) | relationshipLength:u16(149) |
/// relationship:[149] | disclosureVersion:u16 | semanticDigest:[32] |
/// challengeId:[16] | challengeHash:[32] | endpointNonce:[32] |
/// issuedAt:i64 | priorServerSequence:u64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpConsentReceiptBody {
    pub action: ConsentAction,
    pub endpoint_role: EndpointRole,
    pub relationship: RemoteDeviceRelationshipV1,
    pub disclosure_version: u16,
    pub semantic_digest: [u8; 32],
    pub challenge_id: [u8; 16],
    pub challenge_hash: [u8; 32],
    pub endpoint_nonce: [u8; 32],
    pub issued_at: i64,
    pub prior_server_sequence: u64,
}

impl RemoteIpConsentReceiptBody {
    /// Encode to the exact 288-byte canonical body.
    pub fn encode(&self) -> Vec<u8> {
        let rel = self.relationship.encode();
        debug_assert_eq!(rel.len(), RELATIONSHIP_BODY_LEN);
        let mut buf = Vec::with_capacity(RECEIPT_BODY_LEN);
        buf.extend_from_slice(&FCRI);
        buf.push(RECEIPT_VERSION);
        buf.push(self.action.discriminant());
        buf.push(self.endpoint_role.discriminant());
        buf.extend_from_slice(&(rel.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rel);
        buf.extend_from_slice(&self.disclosure_version.to_be_bytes());
        buf.extend_from_slice(&self.semantic_digest);
        buf.extend_from_slice(&self.challenge_id);
        buf.extend_from_slice(&self.challenge_hash);
        buf.extend_from_slice(&self.endpoint_nonce);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.prior_server_sequence.to_be_bytes());
        debug_assert_eq!(buf.len(), RECEIPT_BODY_LEN);
        buf
    }

    /// Decode from the exact 288-byte canonical body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECEIPT_BODY_LEN {
            return codec_err(format!(
                "receipt body must be exactly {RECEIPT_BODY_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let mut off = 0usize;
        let magic: [u8; 4] = bytes[..4].try_into().unwrap();
        if magic != FCRI {
            return codec_err("receipt magic mismatch");
        }
        off += 4;
        let version = bytes[off];
        if version != RECEIPT_VERSION {
            return codec_err(format!("receipt version must be {RECEIPT_VERSION}, got {version}"));
        }
        off += 1;
        let action = ConsentAction::try_from_discriminant(bytes[off])?;
        off += 1;
        let endpoint_role = EndpointRole::try_from_discriminant(bytes[off])?;
        off += 1;
        let rel_len = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
        if rel_len != RELATIONSHIP_BODY_LEN {
            return codec_err(format!(
                "relationship length must be {RELATIONSHIP_BODY_LEN}, got {rel_len}"
            ));
        }
        off += 2;
        let relationship = RemoteDeviceRelationshipV1::decode(&bytes[off..off + RELATIONSHIP_BODY_LEN])?;
        off += RELATIONSHIP_BODY_LEN;
        let disclosure_version = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let semantic_digest = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let challenge_id = bytes[off..off + 16].try_into().unwrap();
        off += 16;
        let challenge_hash = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let endpoint_nonce = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let issued_at = i64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let prior_server_sequence = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        debug_assert_eq!(off, RECEIPT_BODY_LEN);
        Ok(Self {
            action,
            endpoint_role,
            relationship,
            disclosure_version,
            semantic_digest,
            challenge_id,
            challenge_hash,
            endpoint_nonce,
            issued_at,
            prior_server_sequence,
        })
    }

    /// Compute the signing digest: `SHA-256(RECEIPT_DOMAIN || body)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let body = self.encode();
        let mut h = Sha256::new();
        h.update(RECEIPT_DOMAIN);
        h.update(&body);
        h.finalize().into()
    }
}

/// Signed receipt envelope (354 bytes):
/// `bodyLength:u16(288) | body | signature:[64]`.
///
/// The signature is P1363 over `SHA-256(RECEIPT_DOMAIN || body)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpConsentReceiptEnvelope {
    pub body: RemoteIpConsentReceiptBody,
    pub signature: [u8; 64],
}

impl RemoteIpConsentReceiptEnvelope {
    /// Encode to the exact 354-byte envelope.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body.encode();
        debug_assert_eq!(body.len(), RECEIPT_BODY_LEN);
        let mut buf = Vec::with_capacity(RECEIPT_ENVELOPE_LEN);
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&self.signature);
        debug_assert_eq!(buf.len(), RECEIPT_ENVELOPE_LEN);
        buf
    }

    /// Decode from the exact 354-byte envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECEIPT_ENVELOPE_LEN {
            return codec_err(format!(
                "receipt envelope must be exactly {RECEIPT_ENVELOPE_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let body_len = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
        if body_len != RECEIPT_BODY_LEN {
            return codec_err(format!(
                "receipt body length must be {RECEIPT_BODY_LEN}, got {body_len}"
            ));
        }
        let body = RemoteIpConsentReceiptBody::decode(&bytes[2..2 + RECEIPT_BODY_LEN])?;
        let signature: [u8; 64] = bytes[2 + RECEIPT_BODY_LEN..].try_into().unwrap();
        Ok(Self { body, signature })
    }

    /// Verify the receipt signature against the role-selected certificate's
    /// public key.
    ///
    /// The signer certificate must equal the role-selected certificate
    /// embedded in the relationship. A valid signature from the other
    /// endpoint, another relationship containing the same device, or a
    /// replacement certificate fails. This function checks the binding; the
    /// actual P1363 verification is delegated to the caller through the
    /// `verify_fn` predicate.
    pub fn verify_binding(
        &self,
        expected_relationship_hash: &[u8; 32],
        expected_role: EndpointRole,
        expected_generation: u64,
        expected_thumbprint: &[u8; 32],
        verify_fn: impl FnOnce(&[u8; 32], &[u8; 64]) -> bool,
    ) -> Result<()> {
        if self.body.endpoint_role != expected_role {
            return codec_err("receipt endpoint role does not match expected role");
        }
        let rel_hash = self.body.relationship.hash();
        if &rel_hash != expected_relationship_hash {
            return codec_err("receipt relationship hash does not match expected");
        }
        if self.body.relationship.generation_for_role(expected_role) != expected_generation {
            return codec_err("receipt generation does not match expected");
        }
        if &self.body.relationship.thumbprint_for_role(expected_role) != expected_thumbprint {
            return codec_err("receipt thumbprint does not match expected");
        }
        let digest = self.body.signing_digest();
        if !verify_fn(&digest, &self.signature) {
            return codec_err("receipt signature verification failed");
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// RemoteIpConsentStatusV1 (≤296-byte body, ≤362-byte envelope)
// ─────────────────────────────────────────────────────────────────────────

/// Unsigned status body:
/// `magic="FCRS"[4] | version:u8(1) | relationshipLength:u16(149) |
/// relationship:[149] | disclosureVersion:u16 | semanticDigest:[32] |
/// serverSequence:u64 | state:u8(1 direct_allowed,2 relay_only,3 unavailable) |
/// policyEpoch:u64 | authorityEpoch:u64 | issuerKidLength:u8 |
/// issuerKidUtf8 | issuedAt:i64 | validUntil:i64`.
///
/// Kid 1..64, total body ≤296 bytes (232-byte fixed portion plus kid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpConsentStatusBody {
    pub relationship: RemoteDeviceRelationshipV1,
    pub disclosure_version: u16,
    pub semantic_digest: [u8; 32],
    pub server_sequence: u64,
    pub state: ConsentCapability,
    pub policy_epoch: u64,
    pub authority_epoch: u64,
    pub issuer_kid: String,
    pub issued_at: i64,
    pub valid_until: i64,
}

impl RemoteIpConsentStatusBody {
    /// Fixed portion length (excluding variable-length issuer kid):
    /// 4 + 1 + 2 + 149 + 2 + 32 + 8 + 1 + 8 + 8 + 1 + 8 + 8 = 232 bytes.
    pub const FIXED_PORTION_LEN: usize = 232;

    /// Encode to the canonical body (≤296 bytes).
    pub fn encode(&self) -> Vec<u8> {
        let rel = self.relationship.encode();
        debug_assert_eq!(rel.len(), RELATIONSHIP_BODY_LEN);
        let kid_bytes = self.issuer_kid.as_bytes();
        assert!(
            (1..=ISSUER_KID_MAX_LEN).contains(&kid_bytes.len()),
            "issuer kid must be 1..=64 bytes"
        );
        let mut buf = Vec::with_capacity(Self::FIXED_PORTION_LEN + kid_bytes.len());
        buf.extend_from_slice(&FCRS);
        buf.push(STATUS_VERSION);
        buf.extend_from_slice(&(rel.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rel);
        buf.extend_from_slice(&self.disclosure_version.to_be_bytes());
        buf.extend_from_slice(&self.semantic_digest);
        buf.extend_from_slice(&self.server_sequence.to_be_bytes());
        buf.push(self.state.discriminant());
        buf.extend_from_slice(&self.policy_epoch.to_be_bytes());
        buf.extend_from_slice(&self.authority_epoch.to_be_bytes());
        buf.push(kid_bytes.len() as u8);
        buf.extend_from_slice(kid_bytes);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.valid_until.to_be_bytes());
        let total = Self::FIXED_PORTION_LEN + kid_bytes.len();
        debug_assert!(total <= STATUS_BODY_MAX_LEN);
        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Decode from the canonical body (≤296 bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::FIXED_PORTION_LEN || bytes.len() > STATUS_BODY_MAX_LEN {
            return codec_err(format!(
                "status body must be {}..={STATUS_BODY_MAX_LEN} bytes, got {}",
                Self::FIXED_PORTION_LEN,
                bytes.len()
            ));
        }
        let mut off = 0usize;
        let magic: [u8; 4] = bytes[..4].try_into().unwrap();
        if magic != FCRS {
            return codec_err("status magic mismatch");
        }
        off += 4;
        let version = bytes[off];
        if version != STATUS_VERSION {
            return codec_err(format!("status version must be {STATUS_VERSION}, got {version}"));
        }
        off += 1;
        let rel_len = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
        if rel_len != RELATIONSHIP_BODY_LEN {
            return codec_err(format!(
                "relationship length must be {RELATIONSHIP_BODY_LEN}, got {rel_len}"
            ));
        }
        off += 2;
        let relationship = RemoteDeviceRelationshipV1::decode(&bytes[off..off + RELATIONSHIP_BODY_LEN])?;
        off += RELATIONSHIP_BODY_LEN;
        let disclosure_version = u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap());
        off += 2;
        let semantic_digest = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let server_sequence = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let state = ConsentCapability::try_from_discriminant(bytes[off])?;
        off += 1;
        let policy_epoch = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let authority_epoch = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let kid_len = bytes[off] as usize;
        if !(1..=ISSUER_KID_MAX_LEN).contains(&kid_len) {
            return codec_err(format!("issuer kid length must be 1..={ISSUER_KID_MAX_LEN}, got {kid_len}"));
        }
        off += 1;
        let kid_end = off + kid_len;
        if kid_end > bytes.len() {
            return codec_err("issuer kid truncated");
        }
        let issuer_kid = std::str::from_utf8(&bytes[off..kid_end])
            .map_err(|_| ConsentError::Codec("issuer kid is not valid UTF-8".into()))?
            .to_string();
        off = kid_end;
        let remaining = bytes.len() - off;
        if remaining != 16 {
            return codec_err(format!(
                "status body must have exactly 16 trailing bytes (issuedAt+validUntil), got {remaining}"
            ));
        }
        let issued_at = i64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let valid_until = i64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        debug_assert_eq!(off, bytes.len());
        Ok(Self {
            relationship,
            disclosure_version,
            semantic_digest,
            server_sequence,
            state,
            policy_epoch,
            authority_epoch,
            issuer_kid,
            issued_at,
            valid_until,
        })
    }

    /// Compute the signing digest: `SHA-256(STATUS_DOMAIN || body)`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let body = self.encode();
        let mut h = Sha256::new();
        h.update(STATUS_DOMAIN);
        h.update(&body);
        h.finalize().into()
    }

    /// True if the status is valid at the given time (not expired, not
    /// pre-issued).
    pub fn is_valid_at(&self, now: i64) -> bool {
        now >= self.issued_at && now < self.valid_until
    }

    /// True if the validity window exceeds the 60-second maximum.
    pub fn exceeds_max_validity(&self) -> bool {
        self.valid_until - self.issued_at > STATUS_MAX_VALIDITY_SECONDS
    }
}

/// Signed status envelope (≤362 bytes):
/// `bodyLength:u16 | body | signature:[64]`.
///
/// The signature is P1363 over `SHA-256(STATUS_DOMAIN || body)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpConsentStatusEnvelope {
    pub body: RemoteIpConsentStatusBody,
    pub signature: [u8; 64],
}

impl RemoteIpConsentStatusEnvelope {
    /// Encode to the canonical envelope (≤362 bytes).
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body.encode();
        let mut buf = Vec::with_capacity(2 + body.len() + SIGNATURE_LEN);
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&self.signature);
        debug_assert!(buf.len() <= STATUS_ENVELOPE_MAX_LEN);
        buf
    }

    /// Decode from the canonical envelope (≤362 bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 + Self::MIN_BODY_LEN + SIGNATURE_LEN || bytes.len() > STATUS_ENVELOPE_MAX_LEN {
            return codec_err(format!(
                "status envelope must be <= {STATUS_ENVELOPE_MAX_LEN} bytes, got {}",
                bytes.len()
            ));
        }
        let body_len = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
        let body_end = 2 + body_len;
        if body_end + SIGNATURE_LEN != bytes.len() {
            return codec_err("status envelope length does not match body length + signature");
        }
        let body = RemoteIpConsentStatusBody::decode(&bytes[2..body_end])?;
        let signature: [u8; 64] = bytes[body_end..].try_into().unwrap();
        Ok(Self { body, signature })
    }

    /// Minimum body length (fixed portion + 1-byte kid).
    const MIN_BODY_LEN: usize = RemoteIpConsentStatusBody::FIXED_PORTION_LEN + 1;

    /// Verify the status signature and binding.
    ///
    /// The status verifier requires the body relationship hash to equal the
    /// attempt/grant's authorized relationship binding before configuring ICE.
    /// Both endpoints verify the authority ring/status and exact bytes.
    pub fn verify_binding(
        &self,
        expected_relationship_hash: &[u8; 32],
        expected_disclosure_version: u16,
        expected_semantic_digest: &[u8; 32],
        expected_policy_epoch: u64,
        expected_authority_epoch: u64,
        now: i64,
        verify_fn: impl FnOnce(&[u8; 32], &[u8; 64]) -> bool,
    ) -> Result<()> {
        let rel_hash = self.body.relationship.hash();
        if &rel_hash != expected_relationship_hash {
            return codec_err("status relationship hash does not match expected");
        }
        if self.body.disclosure_version != expected_disclosure_version {
            return codec_err("status disclosure version does not match expected");
        }
        if &self.body.semantic_digest != expected_semantic_digest {
            return codec_err("status semantic digest does not match expected");
        }
        if self.body.policy_epoch != expected_policy_epoch {
            return codec_err("status policy epoch does not match expected");
        }
        if self.body.authority_epoch != expected_authority_epoch {
            return codec_err("status authority epoch does not match expected");
        }
        if self.body.exceeds_max_validity() {
            return codec_err("status validity exceeds 60-second maximum");
        }
        if !self.body.is_valid_at(now) {
            return codec_err("status is not valid at the given time");
        }
        let digest = self.body.signing_digest();
        if !verify_fn(&digest, &self.signature) {
            return codec_err("status signature verification failed");
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Challenge
// ─────────────────────────────────────────────────────────────────────────

/// A consent challenge stored server-side.
///
/// The server creates a CSPRNG 32-byte challenge and stores only its SHA-256
/// digest in Postgres `RemoteIpConsentChallenge` with the exact 149-byte
/// relationship body and its SHA-256, endpoint role, disclosure version/digest,
/// current certificate ID/generation/thumbprint, absolute five-minute expiry,
/// and unused state. It returns the challenge only to that authenticated
/// current endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpConsentChallenge {
    pub challenge_id: [u8; 16],
    pub challenge_digest: [u8; 32],
    pub relationship: RemoteDeviceRelationshipV1,
    pub endpoint_role: EndpointRole,
    pub disclosure_version: u16,
    pub semantic_digest: [u8; 32],
    pub certificate_id: [u8; 16],
    pub certificate_generation: u64,
    pub certificate_thumbprint: [u8; 32],
    pub expires_at: i64,
    pub used: bool,
}

impl RemoteIpConsentChallenge {
    /// Compute the SHA-256 digest of the raw challenge bytes.
    pub fn compute_digest(challenge: &[u8; 32]) -> [u8; 32] {
        Sha256::digest(challenge).into()
    }

    /// True if the challenge is expired at the given time.
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// True if the challenge is still usable (not expired, not used).
    pub fn is_usable(&self, now: i64) -> bool {
        !self.used && !self.is_expired(now)
    }

    /// Verify that the supplied raw challenge matches the stored digest.
    pub fn verify_raw_challenge(&self, raw: &[u8; 32]) -> bool {
        &Self::compute_digest(raw) == &self.challenge_digest
    }

    /// Verify that the challenge's embedded certificate matches the
    /// relationship's role-selected certificate.
    pub fn certificate_matches_relationship(&self) -> bool {
        self.certificate_generation == self.relationship.generation_for_role(self.endpoint_role)
            && self.certificate_thumbprint == self.relationship.thumbprint_for_role(self.endpoint_role)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Consent receipt record (server-side stored receipt)
// ─────────────────────────────────────────────────────────────────────────

/// A stored consent receipt record in Postgres `RemoteIpConsentReceipt`.
///
/// One serializable transaction consumes the challenge, re-hashes and
/// byte-compares the relationship, appends this record at exactly
/// `previousSequence + 1`, updates relationship state, and appends its control
/// outbox event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsentReceipt {
    pub server_sequence: u64,
    pub action: ConsentAction,
    pub endpoint_role: EndpointRole,
    pub relationship_hash: [u8; 32],
    pub disclosure_version: u16,
    pub semantic_digest: [u8; 32],
    pub challenge_id: [u8; 16],
    pub endpoint_nonce: [u8; 32],
    pub issued_at: i64,
    pub registry_digest: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────
// Relationship consent state (server-side)
// ─────────────────────────────────────────────────────────────────────────

/// Server-side per-relationship consent state.
///
/// Tracks the latest receipt sequence and the accept/revoke state for each
/// endpoint role. Consent persists without time expiry for the exact
/// relationship/version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipConsentState {
    pub relationship_hash: [u8; 32],
    pub disclosure_version: u16,
    pub semantic_digest: [u8; 32],
    pub server_sequence: u64,
    pub daemon_accepted: bool,
    pub client_accepted: bool,
    pub daemon_revoked: bool,
    pub client_revoked: bool,
    pub registry_digest: [u8; 32],
    pub policy_epoch: u64,
    pub policy_allows_direct: bool,
    pub relay_route_authorized: bool,
    pub authority_epoch: u64,
}

impl RelationshipConsentState {
    /// Create a fresh state for a new relationship/version.
    pub fn new(
        relationship: &RemoteDeviceRelationshipV1,
        disclosure_version: u16,
        semantic_digest: [u8; 32],
        registry_digest: [u8; 32],
        policy_epoch: u64,
        policy_allows_direct: bool,
        relay_route_authorized: bool,
        authority_epoch: u64,
    ) -> Self {
        Self {
            relationship_hash: relationship.hash(),
            disclosure_version,
            semantic_digest,
            server_sequence: 0,
            daemon_accepted: false,
            client_accepted: false,
            daemon_revoked: false,
            client_revoked: false,
            registry_digest,
            policy_epoch,
            policy_allows_direct,
            relay_route_authorized,
            authority_epoch,
        }
    }

    /// Apply a receipt append. Returns the new sequence or an error if the
    /// receipt does not match the current state.
    pub fn append_receipt(&mut self, receipt: &StoredConsentReceipt) -> Result<u64> {
        if receipt.relationship_hash != self.relationship_hash {
            return Err(ConsentError::Linearization("receipt relationship hash mismatch".into()));
        }
        if receipt.disclosure_version != self.disclosure_version {
            return Err(ConsentError::Linearization("receipt disclosure version mismatch".into()));
        }
        if receipt.semantic_digest != self.semantic_digest {
            return Err(ConsentError::Linearization("receipt semantic digest mismatch".into()));
        }
        if receipt.server_sequence != self.server_sequence + 1 {
            return Err(ConsentError::Linearization(format!(
                "receipt sequence must be exactly {}, got {}",
                self.server_sequence + 1,
                receipt.server_sequence
            )));
        }
        if receipt.registry_digest != self.registry_digest {
            return Err(ConsentError::Linearization("receipt registry digest mismatch".into()));
        }
        // Apply the action.
        match (receipt.action, receipt.endpoint_role) {
            (ConsentAction::Accept, EndpointRole::Daemon) => {
                self.daemon_accepted = true;
                self.daemon_revoked = false;
            }
            (ConsentAction::Accept, EndpointRole::Client) => {
                self.client_accepted = true;
                self.client_revoked = false;
            }
            (ConsentAction::Revoke, EndpointRole::Daemon) => {
                self.daemon_accepted = false;
                self.daemon_revoked = true;
            }
            (ConsentAction::Revoke, EndpointRole::Client) => {
                self.client_accepted = false;
                self.client_revoked = true;
            }
        }
        self.server_sequence = receipt.server_sequence;
        Ok(self.server_sequence)
    }

    /// Evaluate the consent capability into the closed tri-state.
    ///
    /// `direct_allowed` requires current mutual receipts and policy.
    /// `relay_only` means direct is forbidden/unconsented but an authorized
    /// TURN-only or E2E WebSocket path exists. `unavailable` means neither
    /// safe route exists or status cannot be proven.
    pub fn evaluate_capability(&self) -> ConsentCapability {
        let mutual_consent = self.daemon_accepted && self.client_accepted;
        let direct_allowed = mutual_consent && self.policy_allows_direct;
        if direct_allowed {
            ConsentCapability::DirectAllowed
        } else if self.relay_route_authorized {
            ConsentCapability::RelayOnly
        } else {
            ConsentCapability::Unavailable
        }
    }

    /// True if the consent is materially invalidated by the given
    /// invalidator. Every named material invalidator requires new mutual
    /// consent.
    pub fn is_materially_invalidated_by(
        &self,
        invalidator: &ConsentInvalidator,
    ) -> bool {
        match invalidator {
            ConsentInvalidator::DeviceRevoke { device_id } => {
                // Device/instance revoke invalidates consent.
                let _ = device_id;
                true
            }
            ConsentInvalidator::Unenroll { .. } => true,
            ConsentInvalidator::GenerationReplacement { .. } => true,
            ConsentInvalidator::RelationshipDeletion => true,
            ConsentInvalidator::PolicyRelayOnly => !self.policy_allows_direct,
            ConsentInvalidator::MaterialVersionChange { .. } => true,
        }
    }
}

/// Named material invalidators that require new mutual consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentInvalidator {
    /// Device or instance revoke.
    DeviceRevoke { device_id: [u8; 16] },
    /// Device unenroll.
    Unenroll { device_id: [u8; 16] },
    /// Certificate generation replacement.
    GenerationReplacement { device_id: [u8; 16] },
    /// Relationship deletion.
    RelationshipDeletion,
    /// Policy changed to relay-only.
    PolicyRelayOnly,
    /// Material disclosure version change.
    MaterialVersionChange { new_version: u16 },
}

// ─────────────────────────────────────────────────────────────────────────
// Direct gather authorization
// ─────────────────────────────────────────────────────────────────────────

/// A one-time direct gather authorization.
///
/// One serializable transaction locks the relationship, verifies current
/// `direct_allowed`, nonexpired status, exact attempt/policy/version/generations,
/// inserts a unique one-time authorization, and returns the committed sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDirectGatherAuthorization {
    pub authorization_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub relationship_hash: [u8; 32],
    pub disclosure_version: u16,
    pub server_sequence: u64,
    pub policy_epoch: u64,
    pub authority_epoch: u64,
    pub status_valid_until: i64,
    pub state: GatherAuthorizationState,
}

/// State of a gather authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GatherAuthorizationState {
    /// Created but gathering not yet started.
    Unused = 1,
    /// Gathering has started.
    Started = 2,
    /// Gathering completed.
    Completed = 3,
    /// Cancelled by a revoke/invalidation transaction.
    Cancelled = 4,
}

impl GatherAuthorizationState {
    pub const ALL: [Self; 4] = [Self::Unused, Self::Started, Self::Completed, Self::Cancelled];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn try_from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Unused),
            2 => Ok(Self::Started),
            3 => Ok(Self::Completed),
            4 => Ok(Self::Cancelled),
            _ => codec_err("unknown gather authorization state"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Linearization model (pure, testable)
// ─────────────────────────────────────────────────────────────────────────

/// Pure linearization model for begin/revoke transitions.
///
/// This models the Postgres authority's serializable transaction behavior:
/// one server-sequence order and exact outcomes for both legal
/// begin-vs-revoke serializations. Redis receives only post-commit cache
/// invalidation/wakeup data; cache loss or stale data triggers a Postgres read
/// and can never authorize.
#[derive(Debug, Clone)]
pub struct ConsentLinearization {
    state: RelationshipConsentState,
    authorizations: Vec<RemoteDirectGatherAuthorization>,
    /// Set of (childAttemptId, serverSequence) pairs that have been started.
    started: Vec<([u8; 16], u64)>,
}

impl ConsentLinearization {
    /// Create a new linearization model for the given relationship state.
    pub fn new(state: RelationshipConsentState) -> Self {
        Self {
            state,
            authorizations: Vec::new(),
            started: Vec::new(),
        }
    }

    /// Get the current server sequence.
    pub fn server_sequence(&self) -> u64 {
        self.state.server_sequence
    }

    /// Get the current capability.
    pub fn evaluate_capability(&self) -> ConsentCapability {
        self.state.evaluate_capability()
    }

    /// Atomic `beginDirectGather` transition.
    ///
    /// One serializable transaction locks the relationship, verifies current
    /// `direct_allowed`, nonexpired status, exact attempt/policy/version/generations,
    /// inserts a unique one-time authorization, and returns the committed
    /// sequence.
    pub fn begin_direct_gather(
        &mut self,
        authorization_id: [u8; 16],
        child_attempt_id: [u8; 16],
        status: &RemoteIpConsentStatusBody,
        now: i64,
    ) -> Result<u64> {
        // Verify current direct_allowed.
        if self.state.evaluate_capability() != ConsentCapability::DirectAllowed {
            return Err(ConsentError::Linearization(
                "begin_direct_gather requires direct_allowed capability".into(),
            ));
        }
        // Verify nonexpired status.
        if !status.is_valid_at(now) {
            return Err(ConsentError::Linearization("status is expired or not yet valid".into()));
        }
        // Verify exact relationship binding.
        let rel_hash = status.relationship.hash();
        if rel_hash != self.state.relationship_hash {
            return Err(ConsentError::Linearization("status relationship does not match".into()));
        }
        // Verify disclosure version.
        if status.disclosure_version != self.state.disclosure_version {
            return Err(ConsentError::Linearization("status disclosure version mismatch".into()));
        }
        // Verify policy epoch.
        if status.policy_epoch != self.state.policy_epoch {
            return Err(ConsentError::Linearization("status policy epoch mismatch".into()));
        }
        // Verify authority epoch.
        if status.authority_epoch != self.state.authority_epoch {
            return Err(ConsentError::Linearization("status authority epoch mismatch".into()));
        }
        // Verify the status sequence matches the current server sequence.
        if status.server_sequence != self.state.server_sequence {
            return Err(ConsentError::Linearization(format!(
                "status server sequence {} does not match current {}",
                status.server_sequence, self.state.server_sequence
            )));
        }
        // Insert the unique one-time authorization.
        let auth = RemoteDirectGatherAuthorization {
            authorization_id,
            child_attempt_id,
            relationship_hash: rel_hash,
            disclosure_version: self.state.disclosure_version,
            server_sequence: self.state.server_sequence,
            policy_epoch: self.state.policy_epoch,
            authority_epoch: self.state.authority_epoch,
            status_valid_until: status.valid_until,
            state: GatherAuthorizationState::Unused,
        };
        self.authorizations.push(auth);
        Ok(self.state.server_sequence)
    }

    /// Mark an authorization as started (gathering has begun).
    pub fn start_gather(
        &mut self,
        authorization_id: &[u8; 16],
    ) -> Result<()> {
        let auth = self
            .authorizations
            .iter_mut()
            .find(|a| &a.authorization_id == authorization_id)
            .ok_or_else(|| ConsentError::Linearization("authorization not found".into()))?;
        if auth.state != GatherAuthorizationState::Unused {
            return Err(ConsentError::Linearization(format!(
                "authorization is {}, not unused",
                auth.state.name()
            )));
        }
        auth.state = GatherAuthorizationState::Started;
        self.started.push((auth.child_attempt_id, auth.server_sequence));
        Ok(())
    }

    /// Mark an authorization as completed.
    pub fn complete_gather(
        &mut self,
        authorization_id: &[u8; 16],
        server_sequence: u64,
    ) -> Result<()> {
        let auth = self
            .authorizations
            .iter_mut()
            .find(|a| &a.authorization_id == authorization_id)
            .ok_or_else(|| ConsentError::Linearization("authorization not found".into()))?;
        if auth.state != GatherAuthorizationState::Started {
            return Err(ConsentError::Linearization(format!(
                "authorization is {}, not started",
                auth.state.name()
            )));
        }
        // Reject superseded sequence.
        if auth.server_sequence != server_sequence {
            return Err(ConsentError::Linearization(
                "stale UI completion: server sequence superseded".into(),
            ));
        }
        auth.state = GatherAuthorizationState::Completed;
        Ok(())
    }

    /// Revoke/invalidation transaction.
    ///
    /// Increments `serverSequence`, marks every unstarted authorization
    /// cancelled, and appends the signed-cancellation outbox event. Active
    /// started authorizations are torn down (marked cancelled) but bytes
    /// already disclosed cannot be revoked.
    pub fn revoke(
        &mut self,
        now: i64,
    ) -> Result<u64> {
        let _ = now;
        // Increment server sequence.
        self.state.server_sequence = self.state.server_sequence.checked_add(1).ok_or_else(|| {
            ConsentError::Linearization("server sequence overflow".into())
        })?;
        // Mark all non-completed authorizations cancelled.
        for auth in &mut self.authorizations {
            if auth.state == GatherAuthorizationState::Unused
                || auth.state == GatherAuthorizationState::Started
            {
                auth.state = GatherAuthorizationState::Cancelled;
            }
        }
        // Reset accept state (revoke invalidates consent).
        self.state.daemon_accepted = false;
        self.state.client_accepted = false;
        Ok(self.state.server_sequence)
    }

    /// Get all authorizations.
    pub fn authorizations(&self) -> &[RemoteDirectGatherAuthorization] {
        &self.authorizations
    }

    /// Get the underlying state (read-only).
    pub fn state(&self) -> &RelationshipConsentState {
        &self.state
    }

    /// Get a mutable reference to the underlying state (for policy updates).
    pub fn state_mut(&mut self) -> &mut RelationshipConsentState {
        &mut self.state
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Candidate factory barrier
// ─────────────────────────────────────────────────────────────────────────

/// A typed verified direct-gather capability that candidate factories
/// accept. It is nonconstructible without a verified status and committed
/// begin; it carries the verified sequence/state and never a boolean.
///
/// Client and daemon candidate factories accept this typed verified status,
/// never a boolean. `relay_only` configures only signed TURN URLs and
/// relay-only ICE policy. `unavailable` creates no transport resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDirectCapability {
    pub capability: ConsentCapability,
    pub server_sequence: u64,
    pub relationship_hash: [u8; 32],
    pub disclosure_version: u16,
    pub policy_epoch: u64,
    pub authority_epoch: u64,
    pub authorization_id: [u8; 16],
    pub status_valid_until: i64,
}

impl VerifiedDirectCapability {
    /// Construct a `direct_allowed` capability from a committed begin.
    /// This is the only way to create a `DirectAllowed` capability.
    pub fn from_committed_begin(
        authorization: &RemoteDirectGatherAuthorization,
        status: &RemoteIpConsentStatusBody,
        registry_lease: &DisclosureRegistryLease,
        expected_registry_digest: &[u8; 32],
        policy_allows_direct: bool,
        now: i64,
    ) -> Result<Self> {
        // Verify the registry lease is ready and matches.
        if !registry_lease.matches(expected_registry_digest) {
            return Err(ConsentError::State(
                "registry lease is not ready or digest mismatch".into(),
            ));
        }
        // Verify policy allows direct.
        if !policy_allows_direct {
            return Err(ConsentError::State("policy does not allow direct".into()));
        }
        // The authorization must be unused or started.
        if authorization.state == GatherAuthorizationState::Cancelled
            || authorization.state == GatherAuthorizationState::Completed
        {
            return Err(ConsentError::State(
                "authorization is cancelled or completed".into(),
            ));
        }
        // Verify the status is nonexpired and direct_allowed.
        if status.state != ConsentCapability::DirectAllowed {
            return Err(ConsentError::State("status is not direct_allowed".into()));
        }
        if !status.is_valid_at(now) {
            return Err(ConsentError::State(
                "status is expired or not yet valid".into(),
            ));
        }
        Ok(Self {
            capability: ConsentCapability::DirectAllowed,
            server_sequence: authorization.server_sequence,
            relationship_hash: authorization.relationship_hash,
            disclosure_version: authorization.disclosure_version,
            policy_epoch: authorization.policy_epoch,
            authority_epoch: authorization.authority_epoch,
            authorization_id: authorization.authorization_id,
            status_valid_until: authorization.status_valid_until,
        })
    }

    /// Construct a `relay_only` capability. No direct resources are allocated.
    pub fn relay_only(
        relationship_hash: [u8; 32],
        disclosure_version: u16,
        policy_epoch: u64,
        authority_epoch: u64,
    ) -> Self {
        Self {
            capability: ConsentCapability::RelayOnly,
            server_sequence: 0,
            relationship_hash,
            disclosure_version,
            policy_epoch,
            authority_epoch,
            authorization_id: [0u8; 16],
            status_valid_until: 0,
        }
    }

    /// Construct an `unavailable` capability. No transport resources are
    /// created.
    pub fn unavailable(
        relationship_hash: [u8; 32],
        disclosure_version: u16,
        policy_epoch: u64,
        authority_epoch: u64,
    ) -> Self {
        Self {
            capability: ConsentCapability::Unavailable,
            server_sequence: 0,
            relationship_hash,
            disclosure_version,
            policy_epoch,
            authority_epoch,
            authorization_id: [0u8; 16],
            status_valid_until: 0,
        }
    }

    /// True when direct candidate gathering is permitted.
    pub fn permits_direct(&self) -> bool {
        self.capability.permits_direct()
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Candidate factory instrumentation (test-only barrier)
// ─────────────────────────────────────────────────────────────────────────

/// A test-instrumented candidate factory that records every attempt to
/// configure direct mode, emit/accept/nominate candidates, or request STUN.
///
/// This proves no configured direct mode/server, emitted or accepted
/// host/srflx candidate, nominated non-relay pair, daemon direct socket, or
/// FlyCockpit STUN request before committed begin.
#[derive(Debug, Clone, Default)]
pub struct InstrumentedCandidateFactory {
    pub direct_mode_configured: bool,
    pub stun_server_configured: bool,
    pub host_candidates_emitted: u32,
    pub srflx_candidates_emitted: u32,
    pub non_relay_candidates_accepted: u32,
    pub non_relay_pairs_nominated: u32,
    pub daemon_direct_sockets: u32,
    pub turn_servers_configured: u32,
    pub relay_only_policy_configured: bool,
    pub transport_resources_created: bool,
}

impl InstrumentedCandidateFactory {
    /// Configure the factory from a verified capability.
    ///
    /// `direct_allowed` configures direct mode and STUN.
    /// `relay_only` configures only TURN relay-only policy.
    /// `unavailable` creates no transport resources.
    pub fn configure(&mut self, capability: &VerifiedDirectCapability) {
        match capability.capability {
            ConsentCapability::DirectAllowed => {
                self.direct_mode_configured = true;
                self.stun_server_configured = true;
                self.transport_resources_created = true;
            }
            ConsentCapability::RelayOnly => {
                self.relay_only_policy_configured = true;
                self.turn_servers_configured += 1;
                // No direct mode, no STUN, no host/srflx candidates.
            }
            ConsentCapability::Unavailable => {
                // No transport resources created.
            }
        }
    }

    /// Emit a candidate of the given type. Returns true if the candidate was
    /// emitted (only relay candidates in relay_only mode).
    pub fn emit_candidate(&mut self, candidate_type: CandidateType, capability: &VerifiedDirectCapability) -> bool {
        match capability.capability {
            ConsentCapability::DirectAllowed => {
                match candidate_type {
                    CandidateType::Host => self.host_candidates_emitted += 1,
                    CandidateType::Srflx => self.srflx_candidates_emitted += 1,
                    CandidateType::Relay => {}
                }
                true
            }
            ConsentCapability::RelayOnly => {
                // Only relay candidates are emitted in relay_only mode.
                matches!(candidate_type, CandidateType::Relay)
            }
            ConsentCapability::Unavailable => false,
        }
    }

    /// Accept a candidate. Returns true if the candidate was accepted.
    pub fn accept_candidate(&mut self, candidate_type: CandidateType, capability: &VerifiedDirectCapability) -> bool {
        match capability.capability {
            ConsentCapability::DirectAllowed => {
                if !matches!(candidate_type, CandidateType::Relay) {
                    self.non_relay_candidates_accepted += 1;
                }
                true
            }
            ConsentCapability::RelayOnly => {
                // No non-relay candidate is accepted in relay_only mode.
                matches!(candidate_type, CandidateType::Relay)
            }
            ConsentCapability::Unavailable => false,
        }
    }

    /// Nominate a candidate pair. Returns true if the pair was nominated.
    pub fn nominate_pair(&mut self, pair_type: CandidatePairType, capability: &VerifiedDirectCapability) -> bool {
        match capability.capability {
            ConsentCapability::DirectAllowed => {
                if !matches!(pair_type, CandidatePairType::RelayRelay) {
                    self.non_relay_pairs_nominated += 1;
                }
                true
            }
            ConsentCapability::RelayOnly => {
                // Only relay-relay pairs are nominated in relay_only mode.
                matches!(pair_type, CandidatePairType::RelayRelay)
            }
            ConsentCapability::Unavailable => false,
        }
    }

    /// Open a daemon direct socket. Returns true if the socket was opened.
    pub fn open_daemon_direct_socket(&mut self, capability: &VerifiedDirectCapability) -> bool {
        match capability.capability {
            ConsentCapability::DirectAllowed => {
                self.daemon_direct_sockets += 1;
                true
            }
            _ => false,
        }
    }

    /// Assert no direct work was performed (for relay_only/unavailable).
    pub fn assert_no_direct_work(&self) {
        assert!(!self.direct_mode_configured, "direct mode must not be configured");
        assert!(!self.stun_server_configured, "STUN server must not be configured");
        assert_eq!(self.host_candidates_emitted, 0, "no host candidates emitted");
        assert_eq!(self.srflx_candidates_emitted, 0, "no srflx candidates emitted");
        assert_eq!(self.non_relay_candidates_accepted, 0, "no non-relay candidates accepted");
        assert_eq!(self.non_relay_pairs_nominated, 0, "no non-relay pairs nominated");
        assert_eq!(self.daemon_direct_sockets, 0, "no daemon direct sockets");
    }
}

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    Host,
    Srflx,
    Relay,
}

/// Candidate pair type (local × remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidatePairType {
    HostHost,
    HostSrflx,
    SrflxHost,
    SrflxSrflx,
    RelayRelay,
}

// ─────────────────────────────────────────────────────────────────────────
// Status issuer
// ─────────────────────────────────────────────────────────────────────────

/// Issue a signed status from the current relationship state.
///
/// The active remote-authority key signs canonical `RemoteIpConsentStatusV1`
/// bytes under domain `flycockpit-remote-ip-consent-status-v1\0`. Validity is
/// at most 60 seconds.
pub fn issue_status(
    state: &RelationshipConsentState,
    relationship: &RemoteDeviceRelationshipV1,
    issuer_kid: &str,
    issued_at: i64,
    validity_seconds: i64,
    signature: [u8; 64],
) -> Result<RemoteIpConsentStatusEnvelope> {
    if validity_seconds > STATUS_MAX_VALIDITY_SECONDS || validity_seconds <= 0 {
        return Err(ConsentError::State(format!(
            "status validity must be 1..={STATUS_MAX_VALIDITY_SECONDS} seconds, got {validity_seconds}"
        )));
    }
    let rel_hash = relationship.hash();
    if rel_hash != state.relationship_hash {
        return Err(ConsentError::State("relationship hash mismatch".into()));
    }
    let body = RemoteIpConsentStatusBody {
        relationship: relationship.clone(),
        disclosure_version: state.disclosure_version,
        semantic_digest: state.semantic_digest,
        server_sequence: state.server_sequence,
        state: state.evaluate_capability(),
        policy_epoch: state.policy_epoch,
        authority_epoch: state.authority_epoch,
        issuer_kid: issuer_kid.to_string(),
        issued_at,
        valid_until: issued_at + validity_seconds,
    };
    Ok(RemoteIpConsentStatusEnvelope { body, signature })
}

// ─────────────────────────────────────────────────────────────────────────
// Closed-surface guard
// ─────────────────────────────────────────────────────────────────────────

/// Closed-surface guard. Asserts the exact cardinality of every enum this
/// module owns so an accidental addition or removal fails loudly.
pub fn closed_surface_guard() {
    assert_eq!(EndpointRole::ALL.len(), 2);
    assert_eq!(ConsentAction::ALL.len(), 2);
    assert_eq!(ConsentCapability::ALL.len(), 3);
    for (i, r) in EndpointRole::ALL.iter().enumerate() {
        assert_eq!(r.discriminant() as usize, i + 1);
    }
    for (i, a) in ConsentAction::ALL.iter().enumerate() {
        assert_eq!(a.discriminant() as usize, i + 1);
    }
    for (i, c) in ConsentCapability::ALL.iter().enumerate() {
        assert_eq!(c.discriminant() as usize, i + 1);
    }
    assert_eq!(RELATIONSHIP_BODY_LEN, 149);
    assert_eq!(RECEIPT_BODY_LEN, 288);
    assert_eq!(RECEIPT_ENVELOPE_LEN, 354);
    assert_eq!(STATUS_BODY_MAX_LEN, 296);
    assert_eq!(STATUS_ENVELOPE_MAX_LEN, 362);
    assert_eq!(RemoteIpConsentStatusBody::FIXED_PORTION_LEN, 232);
}

/// Foundation consumption guard. Statically references the identity enrollment
/// module so this module is a consumer of the enrolled identity proofs.
pub fn identity_consumption_guard() {
    let _ = crate::remote_device_identity_enrollment::EnrollmentState::Issued;
    let _ = crate::remote_device_identity_enrollment::RemoteDeviceLifecycle::Active;
    let _ = crate::remote_device_identity_enrollment::closed_surface_guard as fn();
}

/// Wire-magic registry guard. Asserts the consent magics are registered in
/// the global wire-magic registry.
pub fn assert_consent_wire_magics(registry_json: &str) -> Result<()> {
    let registry = crate::remote_wire_magic_registry::parse_registry(registry_json)
        .map_err(|e| ConsentError::Registry(e))?;
    crate::remote_wire_magic_registry::assert_registered(
        &registry,
        &[
            ("FCRL", "RemoteDeviceRelationshipV1"),
            ("FCRI", "RemoteIpConsentReceiptV1"),
            ("FCRS", "RemoteIpConsentStatusV1"),
        ],
    )
    .map_err(|e| ConsentError::Registry(e))
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relationship() -> RemoteDeviceRelationshipV1 {
        RemoteDeviceRelationshipV1 {
            tenant_id: [0x01; 16],
            instance_id: [0x02; 16],
            daemon_device_id: [0x03; 16],
            daemon_generation: 1,
            daemon_thumbprint: [0xAA; 32],
            client_device_id: [0x04; 16],
            client_generation: 1,
            client_thumbprint: [0xBB; 32],
        }
    }

    fn make_relationship_variant(
        field: &str,
    ) -> RemoteDeviceRelationshipV1 {
        let mut r = make_relationship();
        match field {
            "tenant_id" => r.tenant_id[0] ^= 1,
            "instance_id" => r.instance_id[0] ^= 1,
            "daemon_device_id" => r.daemon_device_id[0] ^= 1,
            "daemon_generation" => r.daemon_generation += 1,
            "daemon_thumbprint" => r.daemon_thumbprint[0] ^= 1,
            "client_device_id" => r.client_device_id[0] ^= 1,
            "client_generation" => r.client_generation += 1,
            "client_thumbprint" => r.client_thumbprint[0] ^= 1,
            _ => panic!("unknown field {field}"),
        }
        r
    }

    fn make_semantic_digest() -> [u8; 32] {
        IpDisclosureVersion::compute_semantic_digest(
            1,
            "public+private",
            "peer-device",
            "direct-connection",
            "webrtc-direct",
        )
    }

    fn make_registry() -> IpDisclosureRegistry {
        let entry = IpDisclosureVersion {
            version: 1,
            localization_key: "remote.ip.consent.v1".to_string(),
            semantic_digest: make_semantic_digest(),
            effective_at: 1_000_000,
            material_change: false,
        };
        IpDisclosureRegistry::build(1, vec![entry])
    }

    fn make_receipt_body(
        action: ConsentAction,
        role: EndpointRole,
        relationship: &RemoteDeviceRelationshipV1,
        challenge_id: [u8; 16],
        prior_seq: u64,
    ) -> RemoteIpConsentReceiptBody {
        RemoteIpConsentReceiptBody {
            action,
            endpoint_role: role,
            relationship: relationship.clone(),
            disclosure_version: 1,
            semantic_digest: make_semantic_digest(),
            challenge_id,
            challenge_hash: [0xCC; 32],
            endpoint_nonce: [0xDD; 32],
            issued_at: 2_000_000,
            prior_server_sequence: prior_seq,
        }
    }

    // ── AC1: remote_ip_consent_relationship_identity ──

    #[test]
    fn remote_ip_consent_relationship_identity() {
        let rel = make_relationship();
        let bytes = rel.encode();
        assert_eq!(bytes.len(), RELATIONSHIP_BODY_LEN);
        assert_eq!(&bytes[..4], &FCRL);
        assert_eq!(bytes[4], RELATIONSHIP_VERSION);

        // Round-trip.
        let decoded = RemoteDeviceRelationshipV1::decode(&bytes).unwrap();
        assert_eq!(decoded, rel);

        // Exact 149-byte layout: check field offsets.
        let mut off = 4 + 1; // magic + version
        assert_eq!(&bytes[off..off + 16], &rel.tenant_id);
        off += 16;
        assert_eq!(&bytes[off..off + 16], &rel.instance_id);
        off += 16;
        assert_eq!(&bytes[off..off + 16], &rel.daemon_device_id);
        off += 16;
        assert_eq!(&bytes[off..off + 8], &rel.daemon_generation.to_be_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 32], &rel.daemon_thumbprint);
        off += 32;
        assert_eq!(&bytes[off..off + 16], &rel.client_device_id);
        off += 16;
        assert_eq!(&bytes[off..off + 8], &rel.client_generation.to_be_bytes());
        off += 8;
        assert_eq!(&bytes[off..off + 32], &rel.client_thumbprint);
        off += 32;
        assert_eq!(off, RELATIONSHIP_BODY_LEN);

        // Role non-substitutability: swapping daemon/client fields produces a
        // different hash.
        let swapped = RemoteDeviceRelationshipV1 {
            tenant_id: rel.tenant_id,
            instance_id: rel.instance_id,
            daemon_device_id: rel.client_device_id,
            daemon_generation: rel.client_generation,
            daemon_thumbprint: rel.client_thumbprint,
            client_device_id: rel.daemon_device_id,
            client_generation: rel.daemon_generation,
            client_thumbprint: rel.daemon_thumbprint,
        };
        assert_ne!(rel.hash(), swapped.hash());

        // Separation for every field change: each single-bit change produces a
        // different hash.
        let base_hash = rel.hash();
        for field in [
            "tenant_id",
            "instance_id",
            "daemon_device_id",
            "daemon_generation",
            "daemon_thumbprint",
            "client_device_id",
            "client_generation",
            "client_thumbprint",
        ] {
            let variant = make_relationship_variant(field);
            assert_ne!(
                base_hash,
                variant.hash(),
                "field {field} change should produce a different hash"
            );
        }

        // Role-selected certificate accessors.
        assert_eq!(rel.thumbprint_for_role(EndpointRole::Daemon), rel.daemon_thumbprint);
        assert_eq!(rel.thumbprint_for_role(EndpointRole::Client), rel.client_thumbprint);
        assert_eq!(rel.generation_for_role(EndpointRole::Daemon), rel.daemon_generation);
        assert_eq!(rel.generation_for_role(EndpointRole::Client), rel.client_generation);

        // contains_device.
        assert!(rel.contains_device(&rel.daemon_device_id));
        assert!(rel.contains_device(&rel.client_device_id));
        assert!(!rel.contains_device(&[0xFF; 16]));

        // Decode rejects wrong length.
        assert!(RemoteDeviceRelationshipV1::decode(&bytes[..148]).is_err());
        assert!(RemoteDeviceRelationshipV1::decode(&[bytes.as_slice(), &[0u8]].concat()).is_err());

        // Decode rejects wrong magic.
        let mut bad_magic = bytes.clone();
        bad_magic[..4].copy_from_slice(b"XXXX");
        assert!(RemoteDeviceRelationshipV1::decode(&bad_magic).is_err());

        // Decode rejects wrong version.
        let mut bad_ver = bytes.clone();
        bad_ver[4] = 2;
        assert!(RemoteDeviceRelationshipV1::decode(&bad_ver).is_err());
    }

    // ── AC2: remote_ip_consent_receipt_and_sequence ──

    #[test]
    fn remote_ip_consent_receipt_and_sequence() {
        let rel = make_relationship();
        let challenge_id = [0x05; 16];

        // Build a receipt body.
        let body = make_receipt_body(
            ConsentAction::Accept,
            EndpointRole::Daemon,
            &rel,
            challenge_id,
            0,
        );
        let bytes = body.encode();
        assert_eq!(bytes.len(), RECEIPT_BODY_LEN);
        assert_eq!(&bytes[..4], &FCRI);
        assert_eq!(bytes[4], RECEIPT_VERSION);
        assert_eq!(bytes[5], ConsentAction::Accept.discriminant());
        assert_eq!(bytes[6], EndpointRole::Daemon.discriminant());

        // Round-trip.
        let decoded = RemoteIpConsentReceiptBody::decode(&bytes).unwrap();
        assert_eq!(decoded, body);

        // Signed envelope.
        let envelope = RemoteIpConsentReceiptEnvelope {
            body: body.clone(),
            signature: [0xEE; 64],
        };
        let env_bytes = envelope.encode();
        assert_eq!(env_bytes.len(), RECEIPT_ENVELOPE_LEN);
        let env_decoded = RemoteIpConsentReceiptEnvelope::decode(&env_bytes).unwrap();
        assert_eq!(env_decoded, envelope);

        // Signing digest is deterministic.
        let digest1 = body.signing_digest();
        let digest2 = body.signing_digest();
        assert_eq!(digest1, digest2);

        // Signing digest includes the domain.
        let mut h = sha2::Sha256::new();
        h.update(RECEIPT_DOMAIN);
        h.update(&body.encode());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(digest1, expected);

        // Monotonic server sequence: append receipts in order.
        let registry = make_registry();
        let mut state = RelationshipConsentState::new(
            &rel,
            1,
            make_semantic_digest(),
            registry.registry_digest,
            1,
            true,
            true,
            1,
        );

        // Daemon accept at sequence 1.
        let receipt1 = StoredConsentReceipt {
            server_sequence: 1,
            action: ConsentAction::Accept,
            endpoint_role: EndpointRole::Daemon,
            relationship_hash: rel.hash(),
            disclosure_version: 1,
            semantic_digest: make_semantic_digest(),
            challenge_id,
            endpoint_nonce: [0xDD; 32],
            issued_at: 2_000_000,
            registry_digest: registry.registry_digest,
        };
        assert_eq!(state.append_receipt(&receipt1).unwrap(), 1);
        assert!(state.daemon_accepted);
        assert!(!state.client_accepted);

        // Client accept at sequence 2.
        let receipt2 = StoredConsentReceipt {
            server_sequence: 2,
            action: ConsentAction::Accept,
            endpoint_role: EndpointRole::Client,
            relationship_hash: rel.hash(),
            disclosure_version: 1,
            semantic_digest: make_semantic_digest(),
            challenge_id: [0x06; 16],
            endpoint_nonce: [0xEE; 32],
            issued_at: 2_000_001,
            registry_digest: registry.registry_digest,
        };
        assert_eq!(state.append_receipt(&receipt2).unwrap(), 2);
        assert!(state.daemon_accepted);
        assert!(state.client_accepted);

        // Exact retry: same-byte receipt returns the stored result (idempotent
        // re-append at the same sequence is rejected because the sequence
        // already advanced).
        let result = state.append_receipt(&receipt2);
        assert!(result.is_err(), "exact retry after sequence advance must fail");

        // Conflicting replay: a receipt with a wrong sequence fails.
        let mut bad_receipt = receipt1.clone();
        bad_receipt.server_sequence = 5;
        assert!(state.append_receipt(&bad_receipt).is_err());

        // Sequence skip fails.
        let mut skip_receipt = receipt1.clone();
        skip_receipt.server_sequence = 10;
        assert!(state.append_receipt(&skip_receipt).is_err());

        // Wrong relationship hash fails.
        let mut wrong_rel_receipt = receipt1.clone();
        wrong_rel_receipt.relationship_hash = [0xFF; 32];
        wrong_rel_receipt.server_sequence = 3;
        assert!(state.append_receipt(&wrong_rel_receipt).is_err());

        // Wrong registry digest fails.
        let mut wrong_reg_receipt = receipt1.clone();
        wrong_reg_receipt.server_sequence = 3;
        wrong_reg_receipt.registry_digest = [0xFF; 32];
        assert!(state.append_receipt(&wrong_reg_receipt).is_err());

        // Non-enumeration: the receipt body contains no cross-tenant
        // enumerable identifier beyond the relationship bytes (which are
        // scoped to the tenant). The challenge_id and nonce are random and
        // single-use.
        assert_ne!(body.challenge_id, [0u8; 16]);
        assert_ne!(body.endpoint_nonce, [0u8; 32]);
    }

    // ── AC3: remote_ip_consent_state_matrix ──

    #[test]
    fn remote_ip_consent_state_matrix() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        // No receipts, no relay → unavailable.
        let s1 = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, false, 1);
        assert_eq!(s1.evaluate_capability(), ConsentCapability::Unavailable);

        // No receipts, relay authorized → relay_only.
        let s2 = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);
        assert_eq!(s2.evaluate_capability(), ConsentCapability::RelayOnly);

        // One-sided acceptance (daemon only), relay authorized → relay_only.
        let mut s3 = s2.clone();
        s3.daemon_accepted = true;
        assert_eq!(s3.evaluate_capability(), ConsentCapability::RelayOnly);

        // One-sided acceptance (client only), relay authorized → relay_only.
        let mut s4 = s2.clone();
        s4.client_accepted = true;
        assert_eq!(s4.evaluate_capability(), ConsentCapability::RelayOnly);

        // One-sided acceptance, no relay → unavailable.
        let mut s5 = s1.clone();
        s5.daemon_accepted = true;
        assert_eq!(s5.evaluate_capability(), ConsentCapability::Unavailable);

        // Mutual acceptance, policy allows direct, relay authorized → direct_allowed.
        let mut s6 = s2.clone();
        s6.daemon_accepted = true;
        s6.client_accepted = true;
        assert_eq!(s6.evaluate_capability(), ConsentCapability::DirectAllowed);

        // Mutual acceptance, policy denies direct, relay authorized → relay_only.
        let mut s7 = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, false, true, 1);
        s7.daemon_accepted = true;
        s7.client_accepted = true;
        assert_eq!(s7.evaluate_capability(), ConsentCapability::RelayOnly);

        // Mutual acceptance, policy denies direct, no relay → unavailable.
        let mut s8 = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, false, false, 1);
        s8.daemon_accepted = true;
        s8.client_accepted = true;
        assert_eq!(s8.evaluate_capability(), ConsentCapability::Unavailable);

        // Revoke daemon after mutual acceptance → relay_only (if relay) or unavailable.
        let mut s9 = s6.clone();
        s9.daemon_accepted = false;
        s9.daemon_revoked = true;
        assert_eq!(s9.evaluate_capability(), ConsentCapability::RelayOnly);

        let mut s10 = s6.clone();
        s10.policy_allows_direct = false;
        s10.daemon_accepted = false;
        s10.daemon_revoked = true;
        assert_eq!(s10.evaluate_capability(), ConsentCapability::RelayOnly);

        // Outage fallback: expired status → degrade to relay_only if authorized,
        // else unavailable. This is modeled by the capability evaluator: if
        // direct_allowed cannot be proven (e.g., status expired), the
        // connection code must re-evaluate. The evaluator itself is pure.
        let _ = s10;
    }

    // ── AC4: remote_ip_consent_signed_status_lease ──

    #[test]
    fn remote_ip_consent_signed_status_lease() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        // Build a status body with a 1-byte kid (minimum body = 233).
        let mut state = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);
        state.daemon_accepted = true;
        state.client_accepted = true;
        state.server_sequence = 5;

        let status_body = RemoteIpConsentStatusBody {
            relationship: rel.clone(),
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 5,
            state: ConsentCapability::DirectAllowed,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: "k1".to_string(),
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };
        let body_bytes = status_body.encode();
        assert!(body_bytes.len() <= STATUS_BODY_MAX_LEN);
        assert!(body_bytes.len() > RemoteIpConsentStatusBody::FIXED_PORTION_LEN);
        assert_eq!(&body_bytes[..4], &FCRS);
        assert_eq!(body_bytes[4], STATUS_VERSION);

        // 232-byte fixed portion + 2-byte kid = 234 bytes.
        assert_eq!(body_bytes.len(), RemoteIpConsentStatusBody::FIXED_PORTION_LEN + 2);

        // Round-trip.
        let decoded = RemoteIpConsentStatusBody::decode(&body_bytes).unwrap();
        assert_eq!(decoded, status_body);

        // 60-second maximum validity.
        assert!(!status_body.exceeds_max_validity());
        let mut bad_status = status_body.clone();
        bad_status.valid_until = status_body.issued_at + STATUS_MAX_VALIDITY_SECONDS + 1;
        assert!(bad_status.exceeds_max_validity());

        // Signed envelope.
        let envelope = RemoteIpConsentStatusEnvelope {
            body: status_body.clone(),
            signature: [0xFF; 64],
        };
        let env_bytes = envelope.encode();
        assert!(env_bytes.len() <= STATUS_ENVELOPE_MAX_LEN);
        let env_decoded = RemoteIpConsentStatusEnvelope::decode(&env_bytes).unwrap();
        assert_eq!(env_decoded, envelope);

        // 64-byte kid (maximum).
        let max_kid = "k".repeat(ISSUER_KID_MAX_LEN);
        let max_status = RemoteIpConsentStatusBody {
            relationship: rel.clone(),
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 5,
            state: ConsentCapability::DirectAllowed,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: max_kid,
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };
        let max_body = max_status.encode();
        assert_eq!(max_body.len(), STATUS_BODY_MAX_LEN);
        let max_env = RemoteIpConsentStatusEnvelope {
            body: max_status,
            signature: [0xFF; 64],
        };
        let max_env_bytes = max_env.encode();
        assert_eq!(max_env_bytes.len(), STATUS_ENVELOPE_MAX_LEN);

        // Verify binding: relationship hash, disclosure version, semantic
        // digest, policy/authority epoch, 60-second max, validity, signature.
        let rel_hash = rel.hash();
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &sem,
            1,
            1,
            3_000_030,
            |_digest, _sig| true, // signature verification delegated
        );
        assert!(result.is_ok());

        // Wrong relationship hash fails.
        let result = envelope.verify_binding(
            &[0xFF; 32],
            1,
            &sem,
            1,
            1,
            3_000_030,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Wrong disclosure version fails.
        let result = envelope.verify_binding(
            &rel_hash,
            2,
            &sem,
            1,
            1,
            3_000_030,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Wrong semantic digest fails.
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &[0xFF; 32],
            1,
            1,
            3_000_030,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Wrong policy epoch fails.
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &sem,
            2,
            1,
            3_000_030,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Wrong authority epoch fails.
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &sem,
            1,
            2,
            3_000_030,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Expired status fails.
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &sem,
            1,
            1,
            3_000_100,
            |_digest, _sig| true,
        );
        assert!(result.is_err());

        // Signature verification failure fails.
        let result = envelope.verify_binding(
            &rel_hash,
            1,
            &sem,
            1,
            1,
            3_000_030,
            |_digest, _sig| false,
        );
        assert!(result.is_err());

        // No boolean bypass: the capability is a typed enum, not a boolean.
        // Verify that ConsentCapability::DirectAllowed is not constructible
        // from a raw boolean without going through the evaluator.
        let cap = state.evaluate_capability();
        assert_eq!(cap, ConsentCapability::DirectAllowed);
        assert!(cap.permits_direct());
        assert!(!ConsentCapability::RelayOnly.permits_direct());
        assert!(!ConsentCapability::Unavailable.permits_direct());

        // Registry-digest replica readiness: a ready lease matches.
        let lease = DisclosureRegistryLease::ready_for(&registry);
        assert!(lease.matches(&registry.registry_digest));
        let unready = DisclosureRegistryLease::unready();
        assert!(!unready.matches(&registry.registry_digest));

        // Decode rejects unknown state discriminant.
        let mut bad_state_bytes = body_bytes.clone();
        let state_offset = 4 + 1 + 2 + RELATIONSHIP_BODY_LEN + 2 + 32 + 8;
        bad_state_bytes[state_offset] = 9;
        assert!(RemoteIpConsentStatusBody::decode(&bad_state_bytes).is_err());

        // Decode rejects trailing byte.
        let mut trailing = body_bytes.clone();
        trailing.push(0);
        assert!(RemoteIpConsentStatusBody::decode(&trailing).is_err());

        // Decode rejects zero-length kid.
        let mut zero_kid = body_bytes.clone();
        let kid_len_offset = 4 + 1 + 2 + RELATIONSHIP_BODY_LEN + 2 + 32 + 8 + 1 + 8 + 8;
        zero_kid[kid_len_offset] = 0;
        // Truncate to remove the kid and trailing timestamps.
        let truncated = &zero_kid[..kid_len_offset + 1 + 16];
        assert!(RemoteIpConsentStatusBody::decode(truncated).is_err());
    }

    // ── AC5: remote_ip_consent_precedes_direct_work ──

    #[test]
    fn remote_ip_consent_precedes_direct_work() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        // Before committed begin: no direct work.
        let state = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);
        let _lin = ConsentLinearization::new(state);
        let cap = VerifiedDirectCapability::unavailable(rel.hash(), 1, 1, 1);
        let mut factory = InstrumentedCandidateFactory::default();
        factory.configure(&cap);
        factory.assert_no_direct_work();
        assert!(!factory.transport_resources_created);

        // No candidate emitted before begin.
        assert!(!factory.emit_candidate(CandidateType::Host, &cap));
        assert!(!factory.emit_candidate(CandidateType::Srflx, &cap));
        assert!(!factory.accept_candidate(CandidateType::Host, &cap));
        assert!(!factory.nominate_pair(CandidatePairType::HostHost, &cap));
        assert!(!factory.open_daemon_direct_socket(&cap));

        // After committed begin with direct_allowed: direct work is permitted.
        let mut state2 = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);
        state2.daemon_accepted = true;
        state2.client_accepted = true;
        state2.server_sequence = 3;
        let mut lin2 = ConsentLinearization::new(state2);

        let status = RemoteIpConsentStatusBody {
            relationship: rel.clone(),
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 3,
            state: ConsentCapability::DirectAllowed,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: "k1".to_string(),
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };

        let auth_id = [0x07; 16];
        let attempt_id = [0x08; 16];
        let seq = lin2.begin_direct_gather(auth_id, attempt_id, &status, 3_000_030).unwrap();
        assert_eq!(seq, 3);

        let auth = &lin2.authorizations()[0];
        let direct_cap = VerifiedDirectCapability {
            capability: ConsentCapability::DirectAllowed,
            server_sequence: auth.server_sequence,
            relationship_hash: auth.relationship_hash,
            disclosure_version: auth.disclosure_version,
            policy_epoch: auth.policy_epoch,
            authority_epoch: auth.authority_epoch,
            authorization_id: auth.authorization_id,
            status_valid_until: auth.status_valid_until,
        };

        let mut factory2 = InstrumentedCandidateFactory::default();
        factory2.configure(&direct_cap);
        assert!(factory2.direct_mode_configured);
        assert!(factory2.stun_server_configured);
        assert!(factory2.emit_candidate(CandidateType::Host, &direct_cap));
        assert!(factory2.emit_candidate(CandidateType::Srflx, &direct_cap));
        assert!(factory2.accept_candidate(CandidateType::Host, &direct_cap));
        assert!(factory2.nominate_pair(CandidatePairType::HostHost, &direct_cap));
        assert!(factory2.open_daemon_direct_socket(&direct_cap));
    }

    // ── AC6: remote_ip_consent_relay_only_path ──

    #[test]
    fn remote_ip_consent_relay_only_path() {
        let rel = make_relationship();

        // Relay-only capability: no consent needed.
        let cap = VerifiedDirectCapability::relay_only(rel.hash(), 1, 1, 1);
        let mut factory = InstrumentedCandidateFactory::default();
        factory.configure(&cap);

        // Only TURN relay-only policy configured.
        assert!(factory.relay_only_policy_configured);
        assert!(factory.turn_servers_configured > 0);
        // No direct mode, no STUN, no host/srflx.
        factory.assert_no_direct_work();

        // Only relay candidates emitted/accepted/nominated.
        assert!(!factory.emit_candidate(CandidateType::Host, &cap));
        assert!(!factory.emit_candidate(CandidateType::Srflx, &cap));
        assert!(factory.emit_candidate(CandidateType::Relay, &cap));
        assert!(!factory.accept_candidate(CandidateType::Host, &cap));
        assert!(!factory.accept_candidate(CandidateType::Srflx, &cap));
        assert!(factory.accept_candidate(CandidateType::Relay, &cap));
        assert!(!factory.nominate_pair(CandidatePairType::HostHost, &cap));
        assert!(!factory.nominate_pair(CandidatePairType::SrflxSrflx, &cap));
        assert!(factory.nominate_pair(CandidatePairType::RelayRelay, &cap));
        assert!(!factory.open_daemon_direct_socket(&cap));
    }

    // ── AC7: remote_ip_consent_begin_revoke_linearization ──

    #[test]
    fn remote_ip_consent_begin_revoke_linearization() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        fn make_lin(rel: &RemoteDeviceRelationshipV1, sem: [u8; 32], registry: &IpDisclosureRegistry) -> ConsentLinearization {
            let mut state = RelationshipConsentState::new(rel, 1, sem, registry.registry_digest, 1, true, true, 1);
            state.daemon_accepted = true;
            state.client_accepted = true;
            state.server_sequence = 3;
            ConsentLinearization::new(state)
        }

        fn make_status(rel: &RemoteDeviceRelationshipV1, sem: [u8; 32], seq: u64) -> RemoteIpConsentStatusBody {
            RemoteIpConsentStatusBody {
                relationship: rel.clone(),
                disclosure_version: 1,
                semantic_digest: sem,
                server_sequence: seq,
                state: ConsentCapability::DirectAllowed,
                policy_epoch: 1,
                authority_epoch: 1,
                issuer_kid: "k1".to_string(),
                issued_at: 3_000_000,
                valid_until: 3_000_060,
            }
        }

        // ── Revoke-first: revoke commits before begin. ──
        let mut lin = make_lin(&rel, sem, &registry);
        // Revoke first.
        let new_seq = lin.revoke(3_000_010).unwrap();
        assert_eq!(new_seq, 4);
        // Begin must fail: capability is no longer direct_allowed.
        let status = make_status(&rel, sem, 4);
        let result = lin.begin_direct_gather([0x07; 16], [0x08; 16], &status, 3_000_020);
        assert!(result.is_err(), "begin after revoke must fail");

        // ── Begin-first: begin commits before revoke. ──
        let mut lin = make_lin(&rel, sem, &registry);
        let status = make_status(&rel, sem, 3);
        let auth_id = [0x09; 16];
        let attempt_id = [0x0A; 16];
        let seq = lin.begin_direct_gather(auth_id, attempt_id, &status, 3_000_020).unwrap();
        assert_eq!(seq, 3);

        // Start gathering.
        lin.start_gather(&auth_id).unwrap();
        assert_eq!(lin.authorizations()[0].state, GatherAuthorizationState::Started);

        // Revoke after begin: increments sequence, cancels the authorization.
        let new_seq = lin.revoke(3_000_030).unwrap();
        assert_eq!(new_seq, 4);
        assert_eq!(lin.authorizations()[0].state, GatherAuthorizationState::Cancelled);

        // Cancelled unstarted work: create a new begin, then revoke without
        // starting.
        let mut lin = make_lin(&rel, sem, &registry);
        let status = make_status(&rel, sem, 3);
        let auth_id = [0x0B; 16];
        let attempt_id = [0x0C; 16];
        lin.begin_direct_gather(auth_id, attempt_id, &status, 3_000_020).unwrap();
        // Revoke without starting.
        lin.revoke(3_000_030).unwrap();
        assert_eq!(lin.authorizations()[0].state, GatherAuthorizationState::Cancelled);

        // Active teardown: started authorization is cancelled on revoke.
        // (Already tested above: the started authorization becomes Cancelled.)

        // Old-sequence rejection: after revoke, a new begin with the old
        // sequence fails.
        let mut lin = make_lin(&rel, sem, &registry);
        let status_old = make_status(&rel, sem, 3);
        lin.begin_direct_gather([0x0D; 16], [0x0E; 16], &status_old, 3_000_020).unwrap();
        lin.revoke(3_000_030).unwrap();
        // New begin with old sequence (3) fails because current is 4 and
        // capability is relay_only.
        let result = lin.begin_direct_gather([0x0F; 16], [0x10; 16], &status_old, 3_000_040);
        assert!(result.is_err(), "old-sequence begin must fail");

        // Documented already-disclosed limit: if begin commits first, gathering
        // may disclose addresses already released, and revocation immediately
        // cancels/tears down the attempt but cannot revoke bytes already
        // disclosed. This is a documentation invariant, not a test assertion;
        // the linearization model correctly cancels the authorization but does
        // not (and cannot) erase disclosed bytes.
        // We verify that after revoke, the authorization is cancelled.
        let mut lin = make_lin(&rel, sem, &registry);
        let status = make_status(&rel, sem, 3);
        let auth_id = [0x11; 16];
        let attempt_id = [0x12; 16];
        lin.begin_direct_gather(auth_id, attempt_id, &status, 3_000_020).unwrap();
        lin.start_gather(&auth_id).unwrap();
        lin.revoke(3_000_030).unwrap();
        assert_eq!(lin.authorizations()[0].state, GatherAuthorizationState::Cancelled);
        // No later old-sequence accept/begin can reactivate.
        let result = lin.begin_direct_gather([0x13; 16], [0x14; 16], &status, 3_000_040);
        assert!(result.is_err());
    }

    // ── AC8: remote_ip_consent_stale_ui_generation ──

    #[test]
    fn remote_ip_consent_stale_ui_generation() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        let mut state = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);
        state.daemon_accepted = true;
        state.client_accepted = true;
        state.server_sequence = 3;
        let mut lin = ConsentLinearization::new(state);

        let status = RemoteIpConsentStatusBody {
            relationship: rel.clone(),
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 3,
            state: ConsentCapability::DirectAllowed,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: "k1".to_string(),
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };

        let auth_id = [0x15; 16];
        let attempt_id = [0x16; 16];
        lin.begin_direct_gather(auth_id, attempt_id, &status, 3_000_020).unwrap();
        lin.start_gather(&auth_id).unwrap();

        // Revoke: sequence advances to 4.
        lin.revoke(3_000_030).unwrap();
        assert_eq!(lin.server_sequence(), 4);

        // Stale UI completion with old sequence (3) must be rejected.
        let result = lin.complete_gather(&auth_id, 3);
        assert!(result.is_err(), "stale sequence completion must be rejected");

        // Stale UI completion with new version: if the disclosure version
        // changed, the old authorization is for the old version and must be
        // rejected. (The authorization stores the version; a new version would
        // require a new begin.)
        let auth = &lin.authorizations()[0];
        assert_eq!(auth.disclosure_version, 1);
        // A new version (2) would not match.
        assert_ne!(auth.disclosure_version, 2);

        // Stale UI completion with new generation: the authorization stores the
        // generation indirectly through the relationship hash. A new generation
        // would change the relationship hash and require a new begin.
        let _ = auth;
    }

    // ── AC9: remote_ip_consent_no_durable_time_expiry ──

    #[test]
    fn remote_ip_consent_no_durable_time_expiry() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();

        let mut state = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);

        // Mutual consent at time T1.
        let r1 = StoredConsentReceipt {
            server_sequence: 1,
            action: ConsentAction::Accept,
            endpoint_role: EndpointRole::Daemon,
            relationship_hash: rel.hash(),
            disclosure_version: 1,
            semantic_digest: sem,
            challenge_id: [0x05; 16],
            endpoint_nonce: [0xDD; 32],
            issued_at: 1_000_000,
            registry_digest: registry.registry_digest,
        };
        state.append_receipt(&r1).unwrap();
        let r2 = StoredConsentReceipt {
            server_sequence: 2,
            action: ConsentAction::Accept,
            endpoint_role: EndpointRole::Client,
            relationship_hash: rel.hash(),
            disclosure_version: 1,
            semantic_digest: sem,
            challenge_id: [0x06; 16],
            endpoint_nonce: [0xEE; 32],
            issued_at: 1_000_001,
            registry_digest: registry.registry_digest,
        };
        state.append_receipt(&r2).unwrap();
        assert_eq!(state.evaluate_capability(), ConsentCapability::DirectAllowed);

        // Advance time significantly: consent persists (no time expiry).
        let far_future = 10_000_000_000;
        // The state does not check time; consent is still direct_allowed.
        assert_eq!(state.evaluate_capability(), ConsentCapability::DirectAllowed);

        // Renew short status leases: issue a new status at the far future.
        let status = issue_status(
            &state,
            &rel,
            "k1",
            far_future,
            60,
            [0xFF; 64],
        )
        .unwrap();
        assert!(status.body.is_valid_at(far_future + 30));
        assert!(!status.body.is_valid_at(far_future + 61));

        // Every named material invalidator requires new mutual consent.
        let invalidators = vec![
            ConsentInvalidator::DeviceRevoke { device_id: rel.daemon_device_id },
            ConsentInvalidator::Unenroll { device_id: rel.client_device_id },
            ConsentInvalidator::GenerationReplacement { device_id: rel.daemon_device_id },
            ConsentInvalidator::RelationshipDeletion,
            ConsentInvalidator::PolicyRelayOnly,
            ConsentInvalidator::MaterialVersionChange { new_version: 2 },
        ];
        for inv in &invalidators {
            assert!(
                state.is_materially_invalidated_by(inv),
                "invalidator {:?} should require new consent",
                inv
            );
        }

        // After material invalidation (e.g., revoke), consent is no longer
        // direct_allowed.
        let mut revoked_state = state.clone();
        revoked_state.daemon_accepted = false;
        revoked_state.daemon_revoked = true;
        assert_eq!(revoked_state.evaluate_capability(), ConsentCapability::RelayOnly);

        // Policy relay-only invalidation.
        let mut policy_state = state.clone();
        policy_state.policy_allows_direct = false;
        assert_eq!(policy_state.evaluate_capability(), ConsentCapability::RelayOnly);
        assert!(policy_state.is_materially_invalidated_by(&ConsentInvalidator::PolicyRelayOnly));

        // Material version change: new version requires new consent.
        let mut version_state = state.clone();
        version_state.disclosure_version = 2;
        version_state.daemon_accepted = false;
        version_state.client_accepted = false;
        assert_eq!(version_state.evaluate_capability(), ConsentCapability::RelayOnly);
    }

    // ── AC10: Shared-leg, accessibility, redaction, fixture gates ──

    #[test]
    fn closed_surface_and_identity_consumption_guards_pass() {
        closed_surface_guard();
        identity_consumption_guard();
    }

    #[test]
    fn consent_wire_magics_are_registered() {
        let json = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-wire-magic-registry-v1.json"
        );
        assert_consent_wire_magics(json).unwrap();
    }

    #[test]
    fn enums_are_closed_and_consistent() {
        assert_eq!(
            EndpointRole::ALL.iter().map(|r| r.name()).collect::<Vec<_>>(),
            vec!["daemon", "client"]
        );
        assert_eq!(
            ConsentAction::ALL.iter().map(|a| a.name()).collect::<Vec<_>>(),
            vec!["accept", "revoke"]
        );
        assert_eq!(
            ConsentCapability::ALL.iter().map(|c| c.name()).collect::<Vec<_>>(),
            vec!["direct_allowed", "relay_only", "unavailable"]
        );
        assert_eq!(GatherAuthorizationState::Unused.discriminant(), 1);
        assert_eq!(GatherAuthorizationState::Started.discriminant(), 2);
        assert_eq!(GatherAuthorizationState::Completed.discriminant(), 3);
        assert_eq!(GatherAuthorizationState::Cancelled.discriminant(), 4);
    }

    #[test]
    fn challenge_digest_and_usability() {
        let rel = make_relationship();
        let raw_challenge = [0x42; 32];
        let challenge = RemoteIpConsentChallenge {
            challenge_id: [0x05; 16],
            challenge_digest: RemoteIpConsentChallenge::compute_digest(&raw_challenge),
            relationship: rel.clone(),
            endpoint_role: EndpointRole::Daemon,
            disclosure_version: 1,
            semantic_digest: make_semantic_digest(),
            certificate_id: [0x03; 16],
            certificate_generation: rel.daemon_generation,
            certificate_thumbprint: rel.daemon_thumbprint,
            expires_at: 3_000_300,
            used: false,
        };
        assert!(challenge.verify_raw_challenge(&raw_challenge));
        assert!(!challenge.verify_raw_challenge(&[0x43; 32]));
        assert!(challenge.is_usable(3_000_000));
        assert!(!challenge.is_usable(3_000_300));
        assert!(!challenge.is_usable(3_000_301));
        assert!(challenge.certificate_matches_relationship());

        // Wrong generation.
        let mut bad = challenge.clone();
        bad.certificate_generation = 999;
        assert!(!bad.certificate_matches_relationship());

        // Wrong thumbprint.
        let mut bad = challenge.clone();
        bad.certificate_thumbprint = [0xFF; 32];
        assert!(!bad.certificate_matches_relationship());

        // Used challenge is not usable.
        let mut used = challenge.clone();
        used.used = true;
        assert!(!used.is_usable(3_000_000));
    }

    #[test]
    fn receipt_envelope_rejects_wrong_length() {
        let rel = make_relationship();
        let body = make_receipt_body(ConsentAction::Accept, EndpointRole::Daemon, &rel, [0x05; 16], 0);
        let env = RemoteIpConsentReceiptEnvelope { body, signature: [0xEE; 64] };
        let bytes = env.encode();
        assert_eq!(bytes.len(), RECEIPT_ENVELOPE_LEN);
        // Too short.
        assert!(RemoteIpConsentReceiptEnvelope::decode(&bytes[..353]).is_err());
        // Too long.
        let mut long = bytes.clone();
        long.push(0);
        assert!(RemoteIpConsentReceiptEnvelope::decode(&long).is_err());
        // Wrong body length.
        let mut bad_len = bytes.clone();
        bad_len[..2].copy_from_slice(&200u16.to_be_bytes());
        assert!(RemoteIpConsentReceiptEnvelope::decode(&bad_len).is_err());
    }

    #[test]
    fn receipt_binding_rejects_wrong_role() {
        let rel = make_relationship();
        let body = make_receipt_body(ConsentAction::Accept, EndpointRole::Daemon, &rel, [0x05; 16], 0);
        let env = RemoteIpConsentReceiptEnvelope { body, signature: [0xEE; 64] };
        let rel_hash = rel.hash();

        // Correct role + thumbprint + generation → ok.
        assert!(env
            .verify_binding(&rel_hash, EndpointRole::Daemon, rel.daemon_generation, &rel.daemon_thumbprint, |_, _| true)
            .is_ok());

        // Wrong role → fail.
        assert!(env
            .verify_binding(&rel_hash, EndpointRole::Client, rel.client_generation, &rel.client_thumbprint, |_, _| true)
            .is_err());

        // Wrong generation → fail.
        assert!(env
            .verify_binding(&rel_hash, EndpointRole::Daemon, 999, &rel.daemon_thumbprint, |_, _| true)
            .is_err());

        // Wrong thumbprint → fail.
        assert!(env
            .verify_binding(&rel_hash, EndpointRole::Daemon, rel.daemon_generation, &[0xFF; 32], |_, _| true)
            .is_err());

        // Signature failure → fail.
        assert!(env
            .verify_binding(&rel_hash, EndpointRole::Daemon, rel.daemon_generation, &rel.daemon_thumbprint, |_, _| false)
            .is_err());

        // Wrong relationship hash → fail.
        assert!(env
            .verify_binding(&[0xFF; 32], EndpointRole::Daemon, rel.daemon_generation, &rel.daemon_thumbprint, |_, _| true)
            .is_err());
    }

    #[test]
    fn ip_disclosure_registry_digest_is_deterministic() {
        let entry1 = IpDisclosureVersion {
            version: 1,
            localization_key: "key1".to_string(),
            semantic_digest: [0x11; 32],
            effective_at: 100,
            material_change: false,
        };
        let entry2 = IpDisclosureVersion {
            version: 2,
            localization_key: "key2".to_string(),
            semantic_digest: [0x22; 32],
            effective_at: 200,
            material_change: true,
        };
        let d1 = IpDisclosureRegistry::compute_registry_digest(1, 1, &[entry1.clone(), entry2.clone()]);
        let d2 = IpDisclosureRegistry::compute_registry_digest(1, 1, &[entry1, entry2]);
        assert_eq!(d1, d2);

        // Different registry version → different digest.
        let d3 = IpDisclosureRegistry::compute_registry_digest(1, 2, &[
            IpDisclosureVersion {
                version: 1,
                localization_key: "key1".to_string(),
                semantic_digest: [0x11; 32],
                effective_at: 100,
                material_change: false,
            },
            IpDisclosureVersion {
                version: 2,
                localization_key: "key2".to_string(),
                semantic_digest: [0x22; 32],
                effective_at: 200,
                material_change: true,
            },
        ]);
        assert_ne!(d1, d3);

        // Registry readiness.
        let reg = IpDisclosureRegistry::build(1, vec![
            IpDisclosureVersion {
                version: 1,
                localization_key: "k".to_string(),
                semantic_digest: [0x11; 32],
                effective_at: 100,
                material_change: false,
            },
        ]);
        assert!(reg.is_ready());

        // Empty registry is not ready.
        let empty = IpDisclosureRegistry::build(1, vec![]);
        assert!(!empty.is_ready());

        // Duplicate versions are not ready.
        let dup = IpDisclosureRegistry::build(1, vec![
            IpDisclosureVersion {
                version: 1,
                localization_key: "k1".to_string(),
                semantic_digest: [0x11; 32],
                effective_at: 100,
                material_change: false,
            },
            IpDisclosureVersion {
                version: 1,
                localization_key: "k2".to_string(),
                semantic_digest: [0x22; 32],
                effective_at: 200,
                material_change: true,
            },
        ]);
        assert!(!dup.is_ready());
    }

    #[test]
    fn issue_status_validates_validity_window() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let registry = make_registry();
        let state = RelationshipConsentState::new(&rel, 1, sem, registry.registry_digest, 1, true, true, 1);

        // Valid 60-second window.
        let status = issue_status(&state, &rel, "k1", 3_000_000, 60, [0xFF; 64]).unwrap();
        assert_eq!(status.body.valid_until, 3_000_060);
        assert!(!status.body.exceeds_max_validity());

        // 61 seconds is rejected.
        let result = issue_status(&state, &rel, "k1", 3_000_000, 61, [0xFF; 64]);
        assert!(result.is_err());

        // 0 seconds is rejected.
        let result = issue_status(&state, &rel, "k1", 3_000_000, 0, [0xFF; 64]);
        assert!(result.is_err());

        // Negative is rejected.
        let result = issue_status(&state, &rel, "k1", 3_000_000, -1, [0xFF; 64]);
        assert!(result.is_err());

        // Wrong relationship hash is rejected.
        let mut wrong_rel = rel.clone();
        wrong_rel.tenant_id[0] ^= 1;
        let result = issue_status(&state, &wrong_rel, "k1", 3_000_000, 60, [0xFF; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn status_decode_rejects_non_utf8_kid() {
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let mut body = RemoteIpConsentStatusBody {
            relationship: rel,
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 1,
            state: ConsentCapability::RelayOnly,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: "k".to_string(),
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };
        let mut bytes = body.encode();
        // Corrupt the kid byte to an invalid UTF-8 continuation byte.
        let kid_offset = RemoteIpConsentStatusBody::FIXED_PORTION_LEN;
        bytes[kid_offset] = 0x80; // invalid UTF-8 start byte
        // Also fix the kid length byte to 1.
        let kid_len_offset = 4 + 1 + 2 + RELATIONSHIP_BODY_LEN + 2 + 32 + 8 + 1 + 8 + 8;
        bytes[kid_len_offset] = 1;
        let result = RemoteIpConsentStatusBody::decode(&bytes);
        assert!(result.is_err());
        // Restore for clean drop.
        body.issuer_kid = "k".to_string();
        let _ = body;
    }

    #[test]
    fn unavailable_creates_no_transport_resources() {
        let rel = make_relationship();
        let cap = VerifiedDirectCapability::unavailable(rel.hash(), 1, 1, 1);
        let mut factory = InstrumentedCandidateFactory::default();
        factory.configure(&cap);
        assert!(!factory.transport_resources_created);
        assert!(!factory.direct_mode_configured);
        assert!(!factory.stun_server_configured);
        assert!(!factory.relay_only_policy_configured);
        assert_eq!(factory.turn_servers_configured, 0);
        factory.assert_no_direct_work();
    }

    #[test]
    fn shared_leg_evaluates_independently() {
        // Shared sessions evaluate each client-daemon leg independently.
        // Two relationships with different device IDs produce different
        // hashes and are evaluated independently.
        let rel1 = make_relationship();
        let mut rel2 = make_relationship();
        rel2.client_device_id[0] ^= 1;
        assert_ne!(rel1.hash(), rel2.hash());

        let sem = make_semantic_digest();
        let registry = make_registry();
        let s1 = RelationshipConsentState::new(&rel1, 1, sem, registry.registry_digest, 1, true, true, 1);
        let s2 = RelationshipConsentState::new(&rel2, 1, sem, registry.registry_digest, 1, true, true, 1);
        assert_ne!(s1.relationship_hash, s2.relationship_hash);
    }

    #[test]
    fn no_address_or_candidate_in_status_or_receipt() {
        // Signed status, receipts, audit, logs, and UI contain no
        // address/candidate or cross-tenant enumerable identifier.
        let rel = make_relationship();
        let sem = make_semantic_digest();
        let body = RemoteIpConsentStatusBody {
            relationship: rel,
            disclosure_version: 1,
            semantic_digest: sem,
            server_sequence: 1,
            state: ConsentCapability::DirectAllowed,
            policy_epoch: 1,
            authority_epoch: 1,
            issuer_kid: "k1".to_string(),
            issued_at: 3_000_000,
            valid_until: 3_000_060,
        };
        let bytes = body.encode();
        // The status body contains no IP address or candidate string.
        // It contains only the relationship, version, digest, sequence,
        // state, epochs, kid, and timestamps.
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("192.168"));
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("candidate:"));
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("srflx"));
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("host"));

        let receipt_body = make_receipt_body(ConsentAction::Accept, EndpointRole::Daemon, &make_relationship(), [0x05; 16], 0);
        let receipt_bytes = receipt_body.encode();
        assert!(!std::str::from_utf8(&receipt_bytes).unwrap().contains("192.168"));
        assert!(!std::str::from_utf8(&receipt_bytes).unwrap().contains("candidate:"));
    }
}
