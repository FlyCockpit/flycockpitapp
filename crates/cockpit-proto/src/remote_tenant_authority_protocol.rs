//! Transport-neutral canonical tenant-authority request, evidence, result,
//! status, and error protocol package.
//!
//! This module is the sole neutral owner of the closed tenant-authority
//! protocol surface: eleven operations, FCTA request envelope, FCTO result
//! envelope, twenty evidence types, the closed result/reason matrix, the
//! signing-domain enum, and the wire-magic registry guard.
//!
//! It consumes identity codecs from [`crate::remote_identity_protocol`],
//! public-service policy codecs from [`crate::remote_public_service_policy`],
//! and the wire-magic registry from [`crate::remote_wire_magic_registry`].
//! It never redefines, re-encodes, or independently hashes those bytes.
//!
//! No function exported by this module signs caller-selected bytes.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::remote_identity_protocol::{
    self as identity, FCCE, FCCF, FCEN, FCIP, FCPP, SubjectKind,
};
use crate::remote_public_service_policy::{
    self as policy, RemoteAuthorizedTupleSetV1, RemotePermissionCeilingDigestV1,
    RemotePermissionCeilingV1, permission_ceiling_digest, validate_transport_bits,
};
use crate::remote_wire_magic_registry::{self as magic, assert_registered, parse_registry};

// Wire magics
pub const FCTA: [u8; 4] = *b"FCTA";
pub const FCTO: [u8; 4] = *b"FCTO";
pub const FCTV: [u8; 4] = *b"FCTV";
pub const FCIR: [u8; 4] = *b"FCIR";
pub const FCAR: [u8; 4] = *b"FCAR";
pub const FCQR: [u8; 4] = *b"FCQR";
pub const FCRH: [u8; 4] = *b"FCRH";
pub const FCMI: [u8; 4] = *b"FCMI";
pub const FCTR: [u8; 4] = *b"FCTR";
pub const FCRS: [u8; 4] = *b"FCRS";

// Envelope version — the single supported FCTA envelope format version. Do not
// reuse this for FCTO/evidence-type version bytes; those carry their own.
pub const FCTA_ENVELOPE_VERSION: u8 = 1;

// Envelope size constants
pub const MAX_BODY_BYTES: usize = 261_760;
pub const MAX_REQUEST_BYTES: usize = 262_144;
pub const MAX_RESULT_BYTES: usize = 16_384;
pub const MAX_STATEMENT_JWS_BYTES: usize = 16_000;
pub const MAX_ARTIFACT_BYTES: usize = 16_000;
pub const MAX_FCTV_BYTES: usize = 16_384;
pub const MAX_FCTV_JWS_BYTES: usize = 16_000;
pub const MAX_FCTV_RESULT_BYTES: usize = 16_057;
pub const FCTA_VALIDITY_SECONDS: i64 = 60;
pub const FUTURE_ISSUED_TOLERANCE_SECONDS: i64 = 60;
pub const NETWORK_DEADLINE_SECONDS: i64 = 10;
pub const IDEMPOTENCY_RETENTION_HOURS: i64 = 24;
pub const STATEMENT_LIFETIME_ATTEMPT: i64 = 300;
pub const STATEMENT_LIFETIME_HIGH_ASSURANCE: i64 = 900;
pub const STATEMENT_LIFETIME_DENIAL_STATUS: i64 = 60;
pub const VERIFIER_CACHE_SECONDS: i64 = 30;
pub const VERIFIER_SKEW_SECONDS: i64 = 60;
pub const RETENTION_FLOOR_SECONDS: i64 = 990;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantAuthorityProtocolError {
    #[error("invalid tenant authority protocol: {0}")]
    Invalid(String),
    #[error("invalid FCTA envelope: {0}")]
    Envelope(String),
    #[error("invalid FCTO result: {0}")]
    Result(String),
    #[error("invalid evidence: {0}")]
    Evidence(String),
    #[error("invalid wire magic: {0}")]
    Magic(String),
}

type Result<T> = std::result::Result<T, TenantAuthorityProtocolError>;
fn invalid<T>(s: impl Into<String>) -> Result<T> {
    Err(TenantAuthorityProtocolError::Invalid(s.into()))
}
fn envelope_err<T>(s: impl Into<String>) -> Result<T> {
    Err(TenantAuthorityProtocolError::Envelope(s.into()))
}
fn result_err<T>(s: impl Into<String>) -> Result<T> {
    Err(TenantAuthorityProtocolError::Result(s.into()))
}
fn evidence_err<T>(s: impl Into<String>) -> Result<T> {
    Err(TenantAuthorityProtocolError::Evidence(s.into()))
}
fn magic_err<T>(s: impl Into<String>) -> Result<T> {
    Err(TenantAuthorityProtocolError::Magic(s.into()))
}

// Operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TenantAuthorityOperation {
    AuthorityActivation = 1,
    DeviceEnrollment = 2,
    PolicyRevision = 3,
    AttemptGrant = 4,
    AuthorityRotation = 5,
    CredentialRegistryRevision = 6,
    RecoveryLifecycle = 7,
    RecoveryExecution = 8,
    TenantAuthorityStatus = 9,
    TenantIdentityRevocationStatus = 10,
    IdentityRevocation = 11,
}

impl TenantAuthorityOperation {
    pub const ALL: [Self; 11] = [
        Self::AuthorityActivation,
        Self::DeviceEnrollment,
        Self::PolicyRevision,
        Self::AttemptGrant,
        Self::AuthorityRotation,
        Self::CredentialRegistryRevision,
        Self::RecoveryLifecycle,
        Self::RecoveryExecution,
        Self::TenantAuthorityStatus,
        Self::TenantIdentityRevocationStatus,
        Self::IdentityRevocation,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::AuthorityActivation),
            2 => Ok(Self::DeviceEnrollment),
            3 => Ok(Self::PolicyRevision),
            4 => Ok(Self::AttemptGrant),
            5 => Ok(Self::AuthorityRotation),
            6 => Ok(Self::CredentialRegistryRevision),
            7 => Ok(Self::RecoveryLifecycle),
            8 => Ok(Self::RecoveryExecution),
            9 => Ok(Self::TenantAuthorityStatus),
            10 => Ok(Self::TenantIdentityRevocationStatus),
            11 => Ok(Self::IdentityRevocation),
            _ => invalid(format!("unknown operation discriminant {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthorityActivation => "authority_activation",
            Self::DeviceEnrollment => "device_enrollment",
            Self::PolicyRevision => "policy_revision",
            Self::AttemptGrant => "attempt_grant",
            Self::AuthorityRotation => "authority_rotation",
            Self::CredentialRegistryRevision => "credential_registry_revision",
            Self::RecoveryLifecycle => "recovery_lifecycle",
            Self::RecoveryExecution => "recovery_execution",
            Self::TenantAuthorityStatus => "tenant_authority_status",
            Self::TenantIdentityRevocationStatus => "tenant_identity_revocation_status",
            Self::IdentityRevocation => "identity_revocation",
        }
    }
    pub fn has_closed_action(self) -> bool {
        matches!(
            self,
            Self::DeviceEnrollment
                | Self::CredentialRegistryRevision
                | Self::RecoveryLifecycle
                | Self::IdentityRevocation
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeviceEnrollmentAction {
    Enroll = 1,
    Renew = 2,
    Rotate = 3,
}
impl DeviceEnrollmentAction {
    pub const ALL: [Self; 3] = [Self::Enroll, Self::Renew, Self::Rotate];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Enroll),
            2 => Ok(Self::Renew),
            3 => Ok(Self::Rotate),
            _ => invalid(format!("unknown device-enrollment action {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Renew => "renew",
            Self::Rotate => "rotate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CredentialRegistryAction {
    AddCredential = 1,
    RevokeCredential = 2,
    AssignSecurityRole = 3,
    RemoveSecurityRole = 4,
}
impl CredentialRegistryAction {
    pub const ALL: [Self; 4] = [
        Self::AddCredential,
        Self::RevokeCredential,
        Self::AssignSecurityRole,
        Self::RemoveSecurityRole,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::AddCredential),
            2 => Ok(Self::RevokeCredential),
            3 => Ok(Self::AssignSecurityRole),
            4 => Ok(Self::RemoveSecurityRole),
            _ => invalid(format!("unknown credential-registry action {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::AddCredential => "add_credential",
            Self::RevokeCredential => "revoke_credential",
            Self::AssignSecurityRole => "assign_security_role",
            Self::RemoveSecurityRole => "remove_security_role",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecoveryLifecycleAction {
    Propose = 1,
    Reconfirm = 2,
    Cancel = 3,
    Expire = 4,
}
impl RecoveryLifecycleAction {
    pub const ALL: [Self; 4] = [Self::Propose, Self::Reconfirm, Self::Cancel, Self::Expire];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Propose),
            2 => Ok(Self::Reconfirm),
            3 => Ok(Self::Cancel),
            4 => Ok(Self::Expire),
            _ => invalid(format!("unknown recovery-lifecycle action {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Reconfirm => "reconfirm",
            Self::Cancel => "cancel",
            Self::Expire => "expire",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IdentityRevocationAction {
    SelfClient = 1,
    SecurityAdmin = 2,
}
impl IdentityRevocationAction {
    pub const ALL: [Self; 2] = [Self::SelfClient, Self::SecurityAdmin];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::SelfClient),
            2 => Ok(Self::SecurityAdmin),
            _ => invalid(format!("unknown identity-revocation action {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::SelfClient => "self_client",
            Self::SecurityAdmin => "security_admin",
        }
    }
}

// Evidence types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceCategory {
    CompactJws,
    CanonicalJson,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EvidenceType {
    AuthorityRing = 1,
    AuthorityStatus = 2,
    MtlsIdentity = 3,
    CredentialRegistry = 4,
    AdminApproval = 5,
    IdentityCertificate = 6,
    PossessionProof = 7,
    CustodyEvidence = 8,
    PublicServicePolicy = 9,
    TenantPolicy = 10,
    RevocationStatus = 11,
    AttemptRequest = 12,
    QuotaRequest = 13,
    RecoveryHistory = 14,
    IdentityProposal = 15,
    EnrollmentTranscript = 16,
    EnrollmentConfirmation = 17,
    IdentityRevocationRequest = 18,
    ControlPlaneAuthorityRing = 19,
    ControlPlaneAuthorityStatus = 20,
}

impl EvidenceType {
    pub const ALL: [Self; 20] = [
        Self::AuthorityRing,
        Self::AuthorityStatus,
        Self::MtlsIdentity,
        Self::CredentialRegistry,
        Self::AdminApproval,
        Self::IdentityCertificate,
        Self::PossessionProof,
        Self::CustodyEvidence,
        Self::PublicServicePolicy,
        Self::TenantPolicy,
        Self::RevocationStatus,
        Self::AttemptRequest,
        Self::QuotaRequest,
        Self::RecoveryHistory,
        Self::IdentityProposal,
        Self::EnrollmentTranscript,
        Self::EnrollmentConfirmation,
        Self::IdentityRevocationRequest,
        Self::ControlPlaneAuthorityRing,
        Self::ControlPlaneAuthorityStatus,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::AuthorityRing),
            2 => Ok(Self::AuthorityStatus),
            3 => Ok(Self::MtlsIdentity),
            4 => Ok(Self::CredentialRegistry),
            5 => Ok(Self::AdminApproval),
            6 => Ok(Self::IdentityCertificate),
            7 => Ok(Self::PossessionProof),
            8 => Ok(Self::CustodyEvidence),
            9 => Ok(Self::PublicServicePolicy),
            10 => Ok(Self::TenantPolicy),
            11 => Ok(Self::RevocationStatus),
            12 => Ok(Self::AttemptRequest),
            13 => Ok(Self::QuotaRequest),
            14 => Ok(Self::RecoveryHistory),
            15 => Ok(Self::IdentityProposal),
            16 => Ok(Self::EnrollmentTranscript),
            17 => Ok(Self::EnrollmentConfirmation),
            18 => Ok(Self::IdentityRevocationRequest),
            19 => Ok(Self::ControlPlaneAuthorityRing),
            20 => Ok(Self::ControlPlaneAuthorityStatus),
            _ => evidence_err(format!("unknown evidence type discriminant {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthorityRing => "authority_ring",
            Self::AuthorityStatus => "authority_status",
            Self::MtlsIdentity => "mtls_identity",
            Self::CredentialRegistry => "credential_registry",
            Self::AdminApproval => "admin_approval",
            Self::IdentityCertificate => "identity_certificate",
            Self::PossessionProof => "possession_proof",
            Self::CustodyEvidence => "custody_evidence",
            Self::PublicServicePolicy => "public_service_policy",
            Self::TenantPolicy => "tenant_policy",
            Self::RevocationStatus => "revocation_status",
            Self::AttemptRequest => "attempt_request",
            Self::QuotaRequest => "quota_request",
            Self::RecoveryHistory => "recovery_history",
            Self::IdentityProposal => "identity_proposal",
            Self::EnrollmentTranscript => "enrollment_transcript",
            Self::EnrollmentConfirmation => "enrollment_confirmation",
            Self::IdentityRevocationRequest => "identity_revocation_request",
            Self::ControlPlaneAuthorityRing => "control_plane_authority_ring",
            Self::ControlPlaneAuthorityStatus => "control_plane_authority_status",
        }
    }
    pub fn category(self) -> EvidenceCategory {
        match self {
            Self::AuthorityRing
            | Self::AuthorityStatus
            | Self::IdentityCertificate
            | Self::PublicServicePolicy
            | Self::TenantPolicy
            | Self::ControlPlaneAuthorityStatus => EvidenceCategory::CompactJws,
            Self::ControlPlaneAuthorityRing => EvidenceCategory::CanonicalJson,
            _ => EvidenceCategory::Binary,
        }
    }
    pub fn cap(self) -> usize {
        match self {
            Self::AuthorityRing => 32_768,
            Self::AuthorityStatus => 16_384,
            Self::MtlsIdentity => 8_192,
            Self::CredentialRegistry => 131_072,
            Self::AdminApproval => 16_384,
            Self::IdentityCertificate => 4_096,
            Self::PossessionProof => 4_096,
            Self::CustodyEvidence => 65_536,
            Self::PublicServicePolicy => 16_384,
            Self::TenantPolicy => 16_384,
            Self::RevocationStatus => 16_384,
            Self::AttemptRequest => 16_384,
            Self::QuotaRequest => 4_096,
            Self::RecoveryHistory => 65_536,
            Self::IdentityProposal => 4_096,
            Self::EnrollmentTranscript => 1_024,
            Self::EnrollmentConfirmation => 168,
            Self::IdentityRevocationRequest => 4_096,
            Self::ControlPlaneAuthorityRing => 32_768,
            Self::ControlPlaneAuthorityStatus => 16_384,
        }
    }
    pub fn wire_magic(self) -> Option<[u8; 4]> {
        match self {
            Self::MtlsIdentity => Some(FCMI),
            Self::CredentialRegistry => Some(*b"FCWR"),
            Self::AdminApproval => Some(*b"FCWA"),
            Self::PossessionProof => Some(FCPP),
            Self::CustodyEvidence => Some(FCCE),
            Self::RevocationStatus => Some(FCTV),
            Self::AttemptRequest => Some(FCAR),
            Self::QuotaRequest => Some(FCQR),
            Self::RecoveryHistory => Some(FCRH),
            Self::IdentityProposal => Some(FCIP),
            Self::EnrollmentTranscript => Some(FCEN),
            Self::EnrollmentConfirmation => Some(FCCF),
            Self::IdentityRevocationRequest => Some(FCIR),
            _ => None,
        }
    }
    pub fn jws_typ(self) -> Option<&'static str> {
        match self {
            Self::AuthorityRing => Some("flycockpit-tenant-authority-ring+jws"),
            Self::AuthorityStatus => Some("flycockpit-tenant-authority-status+jws"),
            Self::IdentityCertificate => Some("flycockpit-remote-identity-certificate+jws"),
            Self::PublicServicePolicy => Some(policy::POLICY_JWS_TYP),
            Self::TenantPolicy => Some("flycockpit-tenant-remote-policy+jws"),
            Self::ControlPlaneAuthorityStatus => Some("flycockpit-remote-authority-status+jws"),
            _ => None,
        }
    }
    pub fn validate(self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.cap() {
            return evidence_err(format!(
                "{} evidence exceeds cap {}",
                self.name(),
                self.cap()
            ));
        }
        match self.category() {
            EvidenceCategory::Binary => {
                let magic = self.wire_magic().ok_or_else(|| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "binary type {} has no wire magic",
                        self.name()
                    ))
                })?;
                if bytes.len() < 5 || bytes[..4] != magic {
                    return evidence_err(format!("{} evidence magic mismatch", self.name()));
                }
                if bytes[4] != 1 {
                    return evidence_err(format!("{} evidence version must be 1", self.name()));
                }
                for other in EvidenceType::ALL {
                    if other == self {
                        continue;
                    }
                    if let Some(other_magic) = other.wire_magic()
                        && bytes.len() >= 4
                        && bytes[..4] == other_magic
                    {
                        return evidence_err(format!(
                            "evidence bytes match {} not {}",
                            other.name(),
                            self.name()
                        ));
                    }
                }
                match self {
                    Self::QuotaRequest => validate_quota_request(bytes)?,
                    Self::IdentityRevocationRequest => validate_identity_revocation_request(bytes)?,
                    Self::MtlsIdentity => validate_mtls_identity(bytes)?,
                    Self::AttemptRequest => validate_attempt_request(bytes)?,
                    Self::RecoveryHistory => validate_recovery_history(bytes)?,
                    Self::RevocationStatus => validate_revocation_status(bytes)?,
                    _ => {}
                }
            }
            EvidenceCategory::CompactJws => {
                if bytes.is_empty() {
                    return evidence_err(format!("{} evidence is empty", self.name()));
                }
                let text = std::str::from_utf8(bytes).map_err(|_| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} evidence is not valid UTF-8",
                        self.name()
                    ))
                })?;
                if text.contains(' ') || text.contains('\t') || text.contains('\n') {
                    return evidence_err(format!("{} compact JWS rejects whitespace", self.name()));
                }
                let parts: Vec<&str> = text.split('.').collect();
                if parts.len() != 3 {
                    return evidence_err(format!(
                        "{} compact JWS must have three segments",
                        self.name()
                    ));
                }
                if parts[2].is_empty() {
                    return evidence_err(format!(
                        "{} compact JWS rejects detached/unencoded payload",
                        self.name()
                    ));
                }
                let header_bytes = URL_SAFE_NO_PAD.decode(parts[0].as_bytes()).map_err(|_| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} compact JWS header decode failed",
                        self.name()
                    ))
                })?;
                let header: serde_json::Value =
                    serde_json::from_slice(&header_bytes).map_err(|_| {
                        TenantAuthorityProtocolError::Evidence(format!(
                            "{} compact JWS header is not valid JSON",
                            self.name()
                        ))
                    })?;
                let expected_typ = self.jws_typ().ok_or_else(|| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "compact-JWS type {} has no typ",
                        self.name()
                    ))
                })?;
                let typ = header.get("typ").and_then(|v| v.as_str()).ok_or_else(|| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} compact JWS missing typ",
                        self.name()
                    ))
                })?;
                if typ != expected_typ {
                    return evidence_err(format!(
                        "{} compact JWS typ mismatch: expected {expected_typ} got {typ}",
                        self.name()
                    ));
                }
                let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} compact JWS missing alg",
                        self.name()
                    ))
                })?;
                if alg != "ES256" {
                    return evidence_err(format!("{} compact JWS alg must be ES256", self.name()));
                }
                if header.get("crit").is_some() {
                    return evidence_err(format!("{} compact JWS rejects crit", self.name()));
                }
            }
            EvidenceCategory::CanonicalJson => {
                if bytes.is_empty() {
                    return evidence_err(format!("{} evidence is empty", self.name()));
                }
                let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} canonical JSON parse failed",
                        self.name()
                    ))
                })?;
                let canonical = policy::canonical_json_value(&value).map_err(|e| {
                    TenantAuthorityProtocolError::Evidence(format!(
                        "{} canonical JSON re-encode failed: {e}",
                        self.name()
                    ))
                })?;
                if canonical.as_bytes() != bytes {
                    return evidence_err(format!(
                        "{} canonical JSON noncanonical bytes",
                        self.name()
                    ));
                }
            }
        }
        Ok(())
    }
}

// FCTA request envelope
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FctaEnvelope {
    pub operation: u8,
    pub request_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub authority_id: [u8; 16],
    pub issuer: String,
    pub governance_epoch: u64,
    pub policy_epoch: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub body_digest: [u8; 32],
    pub body: Vec<u8>,
}

impl FctaEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let op = TenantAuthorityOperation::from_discriminant(self.operation)?;
        validate_nonzero_id(&self.request_id)?;
        validate_nonzero_id(&self.tenant_id)?;
        validate_nonzero_id(&self.authority_id)?;
        if self.tenant_id == self.authority_id {
            return envelope_err("tenantId and authorityId must be distinct");
        }
        let issuer_bytes = normalized_https_origin(&self.issuer)?;
        if self.body.len() > MAX_BODY_BYTES {
            return envelope_err("body exceeds maximum");
        }
        if self.expires_at != self.issued_at + FCTA_VALIDITY_SECONDS {
            return envelope_err("FCTA validity must be exactly 60 seconds");
        }
        let body_digest = Sha256::digest(&self.body);
        if body_digest.as_slice() != self.body_digest {
            return envelope_err("bodyDigest mismatch");
        }
        let mut buf = Vec::with_capacity(64 + issuer_bytes.len() + self.body.len());
        buf.extend_from_slice(&FCTA);
        buf.push(FCTA_ENVELOPE_VERSION);
        buf.push(op.discriminant());
        buf.extend_from_slice(&self.request_id);
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.authority_id);
        buf.extend_from_slice(&(issuer_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(issuer_bytes);
        buf.extend_from_slice(&self.governance_epoch.to_be_bytes());
        buf.extend_from_slice(&self.policy_epoch.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body_digest);
        buf.extend_from_slice(&self.body);
        if buf.len() > MAX_REQUEST_BYTES {
            return envelope_err("request exceeds maximum");
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return envelope_err("truncated magic");
        }
        let magic = &bytes[..4];
        if magic == FCTR || magic == FCRS {
            return magic_err("cross-protocol magic rejected before reading length");
        }
        if magic != FCTA {
            return envelope_err("magic is not FCTA");
        }
        if bytes.len() > MAX_REQUEST_BYTES {
            return envelope_err("request exceeds maximum");
        }
        if bytes.len() < 5 {
            return envelope_err("truncated envelope");
        }
        if bytes[4] != FCTA_ENVELOPE_VERSION {
            return envelope_err("unsupported envelope version");
        }
        let mut n = 5;
        let operation = bytes[n];
        TenantAuthorityOperation::from_discriminant(operation)?;
        n += 1;
        if bytes.len() < n + 16 * 3 {
            return envelope_err("truncated ids");
        }
        let request_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let tenant_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let authority_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        validate_nonzero_id(&request_id)?;
        validate_nonzero_id(&tenant_id)?;
        validate_nonzero_id(&authority_id)?;
        if tenant_id == authority_id {
            return envelope_err("tenantId and authorityId must be distinct");
        }
        if bytes.len() < n + 2 {
            return envelope_err("truncated issuer length");
        }
        let issuer_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
        n += 2;
        if bytes.len() < n + issuer_len {
            return envelope_err("truncated issuer");
        }
        let issuer = std::str::from_utf8(&bytes[n..n + issuer_len])
            .map_err(|_| {
                TenantAuthorityProtocolError::Envelope("issuer is not valid UTF-8".into())
            })?
            .to_string();
        normalized_https_origin(&issuer)?;
        n += issuer_len;
        if bytes.len() < n + 8 * 4 + 4 + 32 {
            return envelope_err("truncated header fields");
        }
        let governance_epoch = u64::from_be_bytes(bytes[n..n + 8].try_into().unwrap());
        n += 8;
        let policy_epoch = u64::from_be_bytes(bytes[n..n + 8].try_into().unwrap());
        n += 8;
        let issued_at = i64::from_be_bytes(bytes[n..n + 8].try_into().unwrap());
        n += 8;
        let expires_at = i64::from_be_bytes(bytes[n..n + 8].try_into().unwrap());
        n += 8;
        if expires_at != issued_at + FCTA_VALIDITY_SECONDS {
            return envelope_err("FCTA validity must be exactly 60 seconds");
        }
        let body_len = u32::from_be_bytes(bytes[n..n + 4].try_into().unwrap()) as usize;
        n += 4;
        if body_len > MAX_BODY_BYTES {
            return envelope_err("body exceeds maximum");
        }
        if bytes.len() < n + 32 + body_len {
            return envelope_err("truncated body/digest");
        }
        let body_digest = bytes[n..n + 32].try_into().unwrap();
        n += 32;
        let body = bytes[n..n + body_len].to_vec();
        n += body_len;
        if n != bytes.len() {
            return envelope_err("trailing bytes");
        }
        let computed = Sha256::digest(&body);
        if computed.as_slice() != body_digest {
            return envelope_err("bodyDigest mismatch");
        }
        Ok(Self {
            operation,
            request_id,
            tenant_id,
            authority_id,
            issuer,
            governance_epoch,
            policy_epoch,
            issued_at,
            expires_at,
            body_digest,
            body,
        })
    }
}

// FCTO result envelope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FctoResultKind {
    Authorized = 1,
    Denied = 2,
    AuthorityStatus = 3,
    IdentityRevocationStatus = 4,
    Error = 5,
}
impl FctoResultKind {
    pub const ALL: [Self; 5] = [
        Self::Authorized,
        Self::Denied,
        Self::AuthorityStatus,
        Self::IdentityRevocationStatus,
        Self::Error,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Authorized),
            2 => Ok(Self::Denied),
            3 => Ok(Self::AuthorityStatus),
            4 => Ok(Self::IdentityRevocationStatus),
            5 => Ok(Self::Error),
            _ => result_err(format!("unknown result kind {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::AuthorityStatus => "authority_status",
            Self::IdentityRevocationStatus => "identity_revocation_status",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FctoReasonCode {
    None = 0,
    Malformed = 1,
    UnsupportedVersion = 2,
    UnknownOperation = 3,
    RequestTooLarge = 4,
    Unauthenticated = 5,
    TenantOrAuthorityNotFound = 6,
    RequestConflict = 7,
    StaleEpoch = 8,
    InvalidEvidence = 9,
    InvalidApproval = 10,
    Revoked = 11,
    QuotaExceeded = 12,
    PolicyDenied = 13,
    ProviderUnavailable = 14,
    Indeterminate = 15,
    DeadlineExceeded = 16,
    NotReady = 17,
    Internal = 18,
}
impl FctoReasonCode {
    pub const ALL: [Self; 19] = [
        Self::None,
        Self::Malformed,
        Self::UnsupportedVersion,
        Self::UnknownOperation,
        Self::RequestTooLarge,
        Self::Unauthenticated,
        Self::TenantOrAuthorityNotFound,
        Self::RequestConflict,
        Self::StaleEpoch,
        Self::InvalidEvidence,
        Self::InvalidApproval,
        Self::Revoked,
        Self::QuotaExceeded,
        Self::PolicyDenied,
        Self::ProviderUnavailable,
        Self::Indeterminate,
        Self::DeadlineExceeded,
        Self::NotReady,
        Self::Internal,
    ];
    pub fn discriminant(self) -> u16 {
        self as u16
    }
    pub fn from_discriminant(v: u16) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Malformed),
            2 => Ok(Self::UnsupportedVersion),
            3 => Ok(Self::UnknownOperation),
            4 => Ok(Self::RequestTooLarge),
            5 => Ok(Self::Unauthenticated),
            6 => Ok(Self::TenantOrAuthorityNotFound),
            7 => Ok(Self::RequestConflict),
            8 => Ok(Self::StaleEpoch),
            9 => Ok(Self::InvalidEvidence),
            10 => Ok(Self::InvalidApproval),
            11 => Ok(Self::Revoked),
            12 => Ok(Self::QuotaExceeded),
            13 => Ok(Self::PolicyDenied),
            14 => Ok(Self::ProviderUnavailable),
            15 => Ok(Self::Indeterminate),
            16 => Ok(Self::DeadlineExceeded),
            17 => Ok(Self::NotReady),
            18 => Ok(Self::Internal),
            _ => result_err(format!("unknown reason code {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownOperation => "unknown_operation",
            Self::RequestTooLarge => "request_too_large",
            Self::Unauthenticated => "unauthenticated",
            Self::TenantOrAuthorityNotFound => "tenant_or_authority_not_found",
            Self::RequestConflict => "request_conflict",
            Self::StaleEpoch => "stale_epoch",
            Self::InvalidEvidence => "invalid_evidence",
            Self::InvalidApproval => "invalid_approval",
            Self::Revoked => "revoked",
            Self::QuotaExceeded => "quota_exceeded",
            Self::PolicyDenied => "policy_denied",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Indeterminate => "indeterminate",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::NotReady => "not_ready",
            Self::Internal => "internal",
        }
    }
    pub fn is_denial_reason(self) -> bool {
        matches!(
            self,
            Self::InvalidEvidence
                | Self::InvalidApproval
                | Self::Revoked
                | Self::QuotaExceeded
                | Self::PolicyDenied
        )
    }
    pub fn is_error_reason(self) -> bool {
        matches!(
            self,
            Self::Malformed
                | Self::UnsupportedVersion
                | Self::UnknownOperation
                | Self::RequestTooLarge
                | Self::Unauthenticated
                | Self::TenantOrAuthorityNotFound
                | Self::RequestConflict
                | Self::StaleEpoch
                | Self::ProviderUnavailable
                | Self::Indeterminate
                | Self::DeadlineExceeded
                | Self::NotReady
                | Self::Internal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FctoEnvelope {
    pub operation: u8,
    pub request_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub authority_id: [u8; 16],
    pub result_kind: u8,
    pub reason_code: u16,
    pub statement_jws: Vec<u8>,
    pub artifact: Vec<u8>,
}

impl FctoEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let op = TenantAuthorityOperation::from_discriminant(self.operation)?;
        let kind = FctoResultKind::from_discriminant(self.result_kind)?;
        let reason = FctoReasonCode::from_discriminant(self.reason_code)?;
        validate_nonzero_id(&self.request_id)?;
        validate_nonzero_id(&self.tenant_id)?;
        validate_nonzero_id(&self.authority_id)?;
        if self.tenant_id == self.authority_id {
            return result_err("tenantId and authorityId must be distinct");
        }
        if self.statement_jws.len() > MAX_STATEMENT_JWS_BYTES {
            return result_err("statement JWS exceeds maximum");
        }
        if self.artifact.len() > MAX_ARTIFACT_BYTES {
            return result_err("artifact exceeds maximum");
        }
        validate_result_matrix(op, kind, reason, &self.statement_jws, &self.artifact)?;
        let mut buf = Vec::with_capacity(
            4 + 1 + 1 + 16 * 3 + 1 + 2 + 2 + self.statement_jws.len() + 2 + self.artifact.len(),
        );
        buf.extend_from_slice(&FCTO);
        buf.push(1);
        buf.push(op.discriminant());
        buf.extend_from_slice(&self.request_id);
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.authority_id);
        buf.push(kind.discriminant());
        buf.extend_from_slice(&reason.discriminant().to_be_bytes());
        buf.extend_from_slice(&(self.statement_jws.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.statement_jws);
        buf.extend_from_slice(&(self.artifact.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.artifact);
        if buf.len() > MAX_RESULT_BYTES {
            return result_err("result exceeds maximum");
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return result_err("truncated magic");
        }
        let magic = &bytes[..4];
        if magic == FCTR || magic == FCRS {
            return magic_err("cross-protocol magic rejected before reading length");
        }
        if magic != FCTO {
            return result_err("magic is not FCTO");
        }
        if bytes.len() > MAX_RESULT_BYTES {
            return result_err("result exceeds maximum");
        }
        if bytes.len() < 5 {
            return result_err("truncated envelope");
        }
        if bytes[4] != 1 {
            return result_err("unsupported version");
        }
        let mut n = 5;
        let operation = bytes[n];
        let op = TenantAuthorityOperation::from_discriminant(operation)?;
        n += 1;
        if bytes.len() < n + 16 * 3 + 1 + 2 {
            return result_err("truncated header");
        }
        let request_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let tenant_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let authority_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        validate_nonzero_id(&request_id)?;
        validate_nonzero_id(&tenant_id)?;
        validate_nonzero_id(&authority_id)?;
        if tenant_id == authority_id {
            return result_err("tenantId and authorityId must be distinct");
        }
        let result_kind = bytes[n];
        let kind = FctoResultKind::from_discriminant(result_kind)?;
        n += 1;
        let reason_code = u16::from_be_bytes([bytes[n], bytes[n + 1]]);
        let reason = FctoReasonCode::from_discriminant(reason_code)?;
        n += 2;
        if bytes.len() < n + 2 {
            return result_err("truncated statement length");
        }
        let stmt_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
        n += 2;
        if bytes.len() < n + stmt_len {
            return result_err("truncated statement");
        }
        let statement_jws = bytes[n..n + stmt_len].to_vec();
        n += stmt_len;
        if bytes.len() < n + 2 {
            return result_err("truncated artifact length");
        }
        let art_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
        n += 2;
        if bytes.len() < n + art_len {
            return result_err("truncated artifact");
        }
        let artifact = bytes[n..n + art_len].to_vec();
        n += art_len;
        if n != bytes.len() {
            return result_err("trailing bytes");
        }
        validate_result_matrix(op, kind, reason, &statement_jws, &artifact)?;
        Ok(Self {
            operation,
            request_id,
            tenant_id,
            authority_id,
            result_kind,
            reason_code,
            statement_jws,
            artifact,
        })
    }
}

fn validate_result_matrix(
    op: TenantAuthorityOperation,
    kind: FctoResultKind,
    reason: FctoReasonCode,
    statement: &[u8],
    artifact: &[u8],
) -> Result<()> {
    match kind {
        FctoResultKind::Authorized => {
            if reason != FctoReasonCode::None {
                return result_err("authorized requires reason none");
            }
            if statement.is_empty() || statement.len() > MAX_STATEMENT_JWS_BYTES {
                return result_err("authorized requires one 1..16000-byte statement");
            }
            if !artifact.is_empty() && artifact.len() > MAX_ARTIFACT_BYTES {
                return result_err("authorized artifact must be 0 or 1..16000 bytes");
            }
        }
        FctoResultKind::Denied => {
            if !reason.is_denial_reason() {
                return result_err("denied requires exactly one denial reason");
            }
            if statement.is_empty() || statement.len() > MAX_STATEMENT_JWS_BYTES {
                return result_err("denied requires one 1..16000-byte denial statement");
            }
            if !artifact.is_empty() && artifact.len() > MAX_ARTIFACT_BYTES {
                return result_err("denied artifact must be 0 or one safe status");
            }
        }
        FctoResultKind::AuthorityStatus => {
            if op != TenantAuthorityOperation::TenantAuthorityStatus {
                return result_err("authority_status is legal only for operation 9");
            }
            if reason != FctoReasonCode::None {
                return result_err("authority_status requires reason none");
            }
            if !statement.is_empty() {
                return result_err("authority_status requires zero statement bytes");
            }
            if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_BYTES {
                return result_err("authority_status requires one 1..16000-byte status");
            }
        }
        FctoResultKind::IdentityRevocationStatus => {
            if op != TenantAuthorityOperation::TenantIdentityRevocationStatus {
                return result_err("identity_revocation_status is legal only for operation 10");
            }
            if reason != FctoReasonCode::None {
                return result_err("identity_revocation_status requires reason none");
            }
            if !statement.is_empty() {
                return result_err("identity_revocation_status requires zero statement bytes");
            }
            if artifact.is_empty() || artifact.len() > MAX_FCTV_RESULT_BYTES {
                return result_err("identity_revocation_status requires one 1..16057-byte FCTV");
            }
        }
        FctoResultKind::Error => {
            if !reason.is_error_reason() {
                return result_err("error requires one of codes 1..8 or 14..18");
            }
            if !statement.is_empty() || !artifact.is_empty() {
                return result_err("error requires both lengths zero");
            }
        }
    }
    Ok(())
}

// Body header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyHeader {
    pub body_version: u8,
    pub action: u8,
    pub evidence_count: u8,
}
impl BodyHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            return evidence_err("truncated body header");
        }
        if bytes[0] != 1 {
            return evidence_err("bodyVersion must be 1");
        }
        Ok(Self {
            body_version: bytes[0],
            action: bytes[1],
            evidence_count: bytes[2],
        })
    }
}

pub fn parse_body_evidence(body: &[u8]) -> Result<Vec<(EvidenceType, Vec<u8>)>> {
    let header = BodyHeader::decode(body)?;
    let mut n = 3;
    let mut out = Vec::with_capacity(header.evidence_count as usize);
    for _ in 0..header.evidence_count {
        if n + 6 > body.len() {
            return evidence_err("truncated evidence header");
        }
        let et = EvidenceType::from_discriminant(body[n])?;
        n += 1;
        if body[n] != 1 {
            return evidence_err("evidenceVersion must be 1");
        }
        n += 1;
        let len = u32::from_be_bytes([body[n], body[n + 1], body[n + 2], body[n + 3]]) as usize;
        n += 4;
        if n + len > body.len() {
            return evidence_err("truncated evidence value");
        }
        let bytes = body[n..n + len].to_vec();
        n += len;
        et.validate(&bytes)?;
        out.push((et, bytes));
    }
    if n != body.len() {
        return evidence_err("trailing bytes in body");
    }
    Ok(out)
}

// FCIR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FcirReason {
    UserRequested = 1,
    DeviceLost = 2,
    KeyCompromised = 3,
    AdminPolicy = 4,
    InstanceRetired = 5,
}
impl FcirReason {
    pub const ALL: [Self; 5] = [
        Self::UserRequested,
        Self::DeviceLost,
        Self::KeyCompromised,
        Self::AdminPolicy,
        Self::InstanceRetired,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn from_discriminant(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::UserRequested),
            2 => Ok(Self::DeviceLost),
            3 => Ok(Self::KeyCompromised),
            4 => Ok(Self::AdminPolicy),
            5 => Ok(Self::InstanceRetired),
            _ => evidence_err(format!("unknown FCIR reason {v}")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::DeviceLost => "device_lost",
            Self::KeyCompromised => "key_compromised",
            Self::AdminPolicy => "admin_policy",
            Self::InstanceRetired => "instance_retired",
        }
    }
    pub fn is_self_client_legal(self, kind: SubjectKind) -> bool {
        matches!(
            (kind, self),
            (
                SubjectKind::Client,
                Self::UserRequested | Self::KeyCompromised
            )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcirRevocationRequest {
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub generation: u64,
    pub reason: FcirReason,
    pub requested_at: i64,
}
impl FcirRevocationRequest {
    pub const WIRE_SIZE: usize = 39;
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_nonzero_id(&self.subject_id)?;
        let mut buf = Vec::with_capacity(39);
        buf.extend_from_slice(&FCIR);
        buf.push(1);
        buf.push(self.subject_kind as u8);
        buf.extend_from_slice(&self.subject_id);
        buf.extend_from_slice(&self.generation.to_be_bytes());
        buf.push(self.reason.discriminant());
        buf.extend_from_slice(&self.requested_at.to_be_bytes());
        debug_assert_eq!(buf.len(), 39);
        Ok(buf)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        validate_identity_revocation_request(bytes)?;
        let subject_kind = SubjectKind::try_from(bytes[5])
            .map_err(|e| TenantAuthorityProtocolError::Evidence(e.0))?;
        let subject_id = bytes[6..22].try_into().unwrap();
        let generation = u64::from_be_bytes(bytes[22..30].try_into().unwrap());
        let reason = FcirReason::from_discriminant(bytes[30])?;
        let requested_at = i64::from_be_bytes(bytes[31..39].try_into().unwrap());
        Ok(Self {
            subject_kind,
            subject_id,
            generation,
            reason,
            requested_at,
        })
    }
}

fn validate_identity_revocation_request(bytes: &[u8]) -> Result<()> {
    if bytes.len() != FcirRevocationRequest::WIRE_SIZE {
        return evidence_err("FCIR must be exactly 39 bytes");
    }
    if bytes[..4] != FCIR {
        return evidence_err("FCIR magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCIR version must be 1");
    }
    let _kind =
        SubjectKind::try_from(bytes[5]).map_err(|e| TenantAuthorityProtocolError::Evidence(e.0))?;
    let id: [u8; 16] = bytes[6..22].try_into().unwrap();
    validate_nonzero_id(&id)?;
    FcirReason::from_discriminant(bytes[30])?;
    Ok(())
}

// FCQR
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcqrQuotaRequest {
    pub requested_turn_bytes: u64,
    pub requested_turn_seconds: u64,
    pub requested_websocket_bytes: u64,
    pub requested_websocket_seconds: u64,
    pub budget_generation: u64,
    pub policy_digest: [u8; 32],
}
impl FcqrQuotaRequest {
    pub const WIRE_SIZE: usize = 77;
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(77);
        buf.extend_from_slice(&FCQR);
        buf.push(1);
        buf.extend_from_slice(&self.requested_turn_bytes.to_be_bytes());
        buf.extend_from_slice(&self.requested_turn_seconds.to_be_bytes());
        buf.extend_from_slice(&self.requested_websocket_bytes.to_be_bytes());
        buf.extend_from_slice(&self.requested_websocket_seconds.to_be_bytes());
        buf.extend_from_slice(&self.budget_generation.to_be_bytes());
        buf.extend_from_slice(&self.policy_digest);
        debug_assert_eq!(buf.len(), 77);
        Ok(buf)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        validate_quota_request(bytes)?;
        Ok(Self {
            requested_turn_bytes: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
            requested_turn_seconds: u64::from_be_bytes(bytes[13..21].try_into().unwrap()),
            requested_websocket_bytes: u64::from_be_bytes(bytes[21..29].try_into().unwrap()),
            requested_websocket_seconds: u64::from_be_bytes(bytes[29..37].try_into().unwrap()),
            budget_generation: u64::from_be_bytes(bytes[37..45].try_into().unwrap()),
            policy_digest: bytes[45..77].try_into().unwrap(),
        })
    }
}

fn validate_quota_request(bytes: &[u8]) -> Result<()> {
    if bytes.len() != FcqrQuotaRequest::WIRE_SIZE {
        return evidence_err("FCQR must be exactly 77 bytes");
    }
    if bytes[..4] != FCQR {
        return evidence_err("FCQR magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCQR version must be 1");
    }
    Ok(())
}

// FCAR
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcarAttemptRequest {
    pub logical_attachment_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub daemon_instance_id: [u8; 16],
    pub transport_bits: u8,
    pub tuple_ids: Vec<u16>,
    pub permission_ceiling: Vec<u8>,
    pub permission_ceiling_digest: [u8; 32],
    pub requested_at: i64,
}
impl FcarAttemptRequest {
    /// Encode the FCAR request. `revoked` is the policy-owned tuple revocation
    /// set threaded from the caller; it is not hardcoded here.
    pub fn encode(&self, revoked: &[u16]) -> Result<Vec<u8>> {
        validate_nonzero_id(&self.logical_attachment_id)?;
        validate_nonzero_id(&self.child_attempt_id)?;
        validate_nonzero_id(&self.daemon_instance_id)?;
        validate_transport_bits(self.transport_bits)
            .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
        let tuple_set = RemoteAuthorizedTupleSetV1 {
            tuple_ids: self.tuple_ids.clone(),
        };
        let tuple_bytes = tuple_set
            .encode(revoked)
            .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
        let ceiling = RemotePermissionCeilingV1::decode(&self.permission_ceiling)
            .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
        let digest = permission_ceiling_digest(&ceiling)
            .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
        if digest.as_bytes() != &self.permission_ceiling_digest {
            return evidence_err("FCAR permission ceiling digest mismatch");
        }
        let mut buf = Vec::with_capacity(64 + tuple_bytes.len() + self.permission_ceiling.len());
        buf.extend_from_slice(&FCAR);
        buf.push(1);
        buf.extend_from_slice(&self.logical_attachment_id);
        buf.extend_from_slice(&self.child_attempt_id);
        buf.extend_from_slice(&self.daemon_instance_id);
        buf.push(self.transport_bits);
        buf.extend_from_slice(&tuple_bytes);
        buf.extend_from_slice(&(self.permission_ceiling.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.permission_ceiling);
        buf.extend_from_slice(&self.permission_ceiling_digest);
        buf.extend_from_slice(&self.requested_at.to_be_bytes());
        if buf.len() > 16_384 {
            return evidence_err("FCAR exceeds 16384 bytes");
        }
        Ok(buf)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        validate_attempt_request(bytes)?;
        let mut n = 5;
        let logical_attachment_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let child_attempt_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let daemon_instance_id = bytes[n..n + 16].try_into().unwrap();
        n += 16;
        let transport_bits = bytes[n];
        n += 1;
        let tuple_count = bytes[n] as usize;
        n += 1;
        let mut tuple_ids = Vec::with_capacity(tuple_count);
        for _ in 0..tuple_count {
            tuple_ids.push(u16::from_be_bytes([bytes[n], bytes[n + 1]]));
            n += 2;
        }
        let perm_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
        n += 2;
        let permission_ceiling = bytes[n..n + perm_len].to_vec();
        n += perm_len;
        let permission_ceiling_digest = bytes[n..n + 32].try_into().unwrap();
        n += 32;
        let requested_at = i64::from_be_bytes(bytes[n..n + 8].try_into().unwrap());
        n += 8;
        debug_assert_eq!(n, bytes.len());
        Ok(Self {
            logical_attachment_id,
            child_attempt_id,
            daemon_instance_id,
            transport_bits,
            tuple_ids,
            permission_ceiling,
            permission_ceiling_digest,
            requested_at,
        })
    }
}

fn validate_attempt_request(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 5 || bytes[..4] != FCAR {
        return evidence_err("FCAR magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCAR version must be 1");
    }
    if bytes.len() > 16_384 {
        return evidence_err("FCAR exceeds 16384 bytes");
    }
    let mut n = 5;
    if bytes.len() < n + 16 * 3 + 1 {
        return evidence_err("FCAR truncated ids");
    }
    for _ in 0..3 {
        let id: [u8; 16] = bytes[n..n + 16].try_into().unwrap();
        validate_nonzero_id(&id)?;
        n += 16;
    }
    let transport_bits = bytes[n];
    validate_transport_bits(transport_bits)
        .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
    n += 1;
    if n >= bytes.len() {
        return evidence_err("FCAR truncated tuple count");
    }
    let tuple_count = bytes[n] as usize;
    n += 1;
    if !(1..=16).contains(&tuple_count) {
        return evidence_err("FCAR tuple count must be 1..16");
    }
    if bytes.len() < n + tuple_count * 2 {
        return evidence_err("FCAR truncated tuple ids");
    }
    let mut prev: u16 = 0;
    for i in 0..tuple_count {
        let id = u16::from_be_bytes([bytes[n + i * 2], bytes[n + i * 2 + 1]]);
        if id == 0 {
            return evidence_err("FCAR tuple id must be nonzero");
        }
        if i > 0 && id <= prev {
            return evidence_err("FCAR tuple ids must be strictly increasing");
        }
        prev = id;
    }
    n += tuple_count * 2;
    if bytes.len() < n + 2 {
        return evidence_err("FCAR truncated permission ceiling length");
    }
    let perm_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
    n += 2;
    if perm_len > 512 {
        return evidence_err("FCAR permission ceiling exceeds 512 bytes");
    }
    if bytes.len() < n + perm_len + 32 + 8 {
        return evidence_err("FCAR truncated permission ceiling/digest/timestamp");
    }
    let permission_ceiling = &bytes[n..n + perm_len];
    let ceiling = RemotePermissionCeilingV1::decode(permission_ceiling)
        .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
    let digest = permission_ceiling_digest(&ceiling)
        .map_err(|e| TenantAuthorityProtocolError::Evidence(e.to_string()))?;
    n += perm_len;
    let declared_digest: [u8; 32] = bytes[n..n + 32].try_into().unwrap();
    if digest.as_bytes() != &declared_digest {
        return evidence_err("FCAR permission ceiling digest mismatch");
    }
    n += 32;
    n += 8;
    if n != bytes.len() {
        return evidence_err("FCAR trailing bytes");
    }
    Ok(())
}

fn validate_recovery_history(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 5 || bytes[..4] != FCRH {
        return evidence_err("FCRH magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCRH version must be 1");
    }
    if bytes.len() > 65_536 {
        return evidence_err("FCRH exceeds 65536 bytes");
    }
    if bytes.len() < 86 {
        return evidence_err("FCRH truncated fixed header");
    }
    Ok(())
}

fn validate_mtls_identity(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 5 || bytes[..4] != FCMI {
        return evidence_err("FCMI magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCMI version must be 1");
    }
    if bytes.len() > 8_192 {
        return evidence_err("FCMI exceeds 8192 bytes");
    }
    if bytes.len() < 6 {
        return evidence_err("FCMI truncated deployment id length");
    }
    let dep_len = bytes[5] as usize;
    if !(1..=64).contains(&dep_len) {
        return evidence_err("FCMI deployment id length must be 1..64");
    }
    if !bytes[6..6 + dep_len]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
    {
        return evidence_err("FCMI deployment id must be [A-Za-z0-9_-]{1,64}");
    }
    let mut n = 6 + dep_len;
    if bytes.len() < n + 96 {
        return evidence_err("FCMI truncated fixed fields");
    }
    n += 96;
    if bytes.len() < n + 2 {
        return evidence_err("FCMI truncated san length");
    }
    let san_len = u16::from_be_bytes([bytes[n], bytes[n + 1]]) as usize;
    n += 2;
    if !(1..=512).contains(&san_len) {
        return evidence_err("FCMI san length must be 1..512");
    }
    if bytes.len() < n + san_len + 16 {
        return evidence_err("FCMI truncated san/timestamps");
    }
    n += san_len;
    n += 16;
    if n != bytes.len() {
        return evidence_err("FCMI trailing bytes");
    }
    Ok(())
}

fn validate_revocation_status(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 5 || bytes[..4] != FCTV {
        return evidence_err("FCTV magic mismatch");
    }
    if bytes[4] != 1 {
        return evidence_err("FCTV version must be 1");
    }
    if bytes.len() > MAX_FCTV_BYTES {
        return evidence_err("FCTV exceeds 16384 bytes");
    }
    if bytes.len() < 57 {
        return evidence_err("FCTV truncated fixed header");
    }
    let status = bytes[22];
    if !matches!(status, 1 | 2) {
        return evidence_err("FCTV status must be 1 (active) or 2 (revoked)");
    }
    let jws_len = u16::from_be_bytes([bytes[55], bytes[56]]) as usize;
    if jws_len == 0 || jws_len > MAX_FCTV_JWS_BYTES {
        return evidence_err("FCTV JWS length must be 1..16000");
    }
    if bytes.len() != 57 + jws_len {
        return evidence_err("FCTV length mismatch");
    }
    Ok(())
}

// Signing-domain enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningDomain {
    TenantAuthorityRingV1,
    TenantRemotePolicyV1,
    TenantAuthorityStatusV1,
    TenantIdentityRevocationStatusV1,
    TenantAuthorizationStatementV1,
    RemoteTenantAuthorityWatermarkV1,
}
impl SigningDomain {
    pub const ALL: [Self; 6] = [
        Self::TenantAuthorityRingV1,
        Self::TenantRemotePolicyV1,
        Self::TenantAuthorityStatusV1,
        Self::TenantIdentityRevocationStatusV1,
        Self::TenantAuthorizationStatementV1,
        Self::RemoteTenantAuthorityWatermarkV1,
    ];
    pub fn jws_typ(self) -> Option<&'static str> {
        match self {
            Self::TenantAuthorityRingV1 => Some("flycockpit-tenant-authority-ring+jws"),
            Self::TenantRemotePolicyV1 => Some("flycockpit-tenant-remote-policy+jws"),
            Self::TenantAuthorityStatusV1 => Some("flycockpit-tenant-authority-status+jws"),
            Self::TenantIdentityRevocationStatusV1 => {
                Some("flycockpit-tenant-identity-revocation-status+jws")
            }
            Self::TenantAuthorizationStatementV1 => {
                Some("flycockpit-tenant-authorization-statement+jws")
            }
            Self::RemoteTenantAuthorityWatermarkV1 => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::TenantAuthorityRingV1 => "TenantAuthorityRingV1",
            Self::TenantRemotePolicyV1 => "TenantRemotePolicyV1",
            Self::TenantAuthorityStatusV1 => "TenantAuthorityStatusV1",
            Self::TenantIdentityRevocationStatusV1 => "TenantIdentityRevocationStatusV1",
            Self::TenantAuthorizationStatementV1 => "TenantAuthorizationStatementV1",
            Self::RemoteTenantAuthorityWatermarkV1 => "RemoteTenantAuthorityWatermarkV1",
        }
    }
}

// Approval cardinality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalCardinality {
    None,
    OneSecurityAdmin,
    OwnerPlusSecurityAdmin,
}

pub fn approval_cardinality(
    op: TenantAuthorityOperation,
    action: Option<u8>,
) -> Result<ApprovalCardinality> {
    match op {
        TenantAuthorityOperation::AuthorityActivation
        | TenantAuthorityOperation::AuthorityRotation
        | TenantAuthorityOperation::RecoveryExecution
        | TenantAuthorityOperation::CredentialRegistryRevision => {
            Ok(ApprovalCardinality::OwnerPlusSecurityAdmin)
        }
        TenantAuthorityOperation::RecoveryLifecycle => {
            let a = action.ok_or_else(|| {
                TenantAuthorityProtocolError::Invalid(
                    "recovery_lifecycle requires a closed action".into(),
                )
            })?;
            let rla = RecoveryLifecycleAction::from_discriminant(a)?;
            match rla {
                RecoveryLifecycleAction::Propose
                | RecoveryLifecycleAction::Reconfirm
                | RecoveryLifecycleAction::Cancel => {
                    Ok(ApprovalCardinality::OwnerPlusSecurityAdmin)
                }
                RecoveryLifecycleAction::Expire => Ok(ApprovalCardinality::None),
            }
        }
        TenantAuthorityOperation::DeviceEnrollment => {
            let a = action.ok_or_else(|| {
                TenantAuthorityProtocolError::Invalid(
                    "device_enrollment requires a closed action".into(),
                )
            })?;
            let dea = DeviceEnrollmentAction::from_discriminant(a)?;
            match dea {
                DeviceEnrollmentAction::Enroll | DeviceEnrollmentAction::Rotate => {
                    Ok(ApprovalCardinality::OneSecurityAdmin)
                }
                DeviceEnrollmentAction::Renew => Ok(ApprovalCardinality::None),
            }
        }
        TenantAuthorityOperation::PolicyRevision => match action {
            Some(1) => Ok(ApprovalCardinality::OneSecurityAdmin),
            Some(2) => Ok(ApprovalCardinality::OwnerPlusSecurityAdmin),
            _ => invalid("policy_revision action must be 1 (equal/strengthening) or 2 (weakening)"),
        },
        TenantAuthorityOperation::IdentityRevocation => {
            let a = action.ok_or_else(|| {
                TenantAuthorityProtocolError::Invalid(
                    "identity_revocation requires a closed action".into(),
                )
            })?;
            let ira = IdentityRevocationAction::from_discriminant(a)?;
            match ira {
                IdentityRevocationAction::SelfClient => Ok(ApprovalCardinality::None),
                IdentityRevocationAction::SecurityAdmin => {
                    Ok(ApprovalCardinality::OneSecurityAdmin)
                }
            }
        }
        TenantAuthorityOperation::AttemptGrant
        | TenantAuthorityOperation::TenantAuthorityStatus
        | TenantAuthorityOperation::TenantIdentityRevocationStatus => Ok(ApprovalCardinality::None),
    }
}

// Helpers
fn validate_nonzero_id(id: &[u8; 16]) -> Result<()> {
    if id.iter().all(|&b| b == 0) {
        return invalid("zero identifier rejected");
    }
    Ok(())
}

pub fn normalized_https_origin(s: &str) -> Result<&[u8]> {
    let Some(authority) = s.strip_prefix("https://") else {
        return invalid("origin must use HTTPS");
    };
    if !(1..=255).contains(&s.len())
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_uppercase())
        || authority.contains(['/', '?', '#', '@'])
        || authority.ends_with(":443")
    {
        return invalid("origin must be a normalized HTTPS origin");
    }
    let host = authority.split_once(':').map_or(authority, |(host, port)| {
        if port.is_empty()
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            ""
        } else {
            host
        }
    });
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return invalid("origin host is noncanonical");
    }
    Ok(s.as_bytes())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn digest_hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("writing to String");
    }
    s
}

// Wire-magic registry guard
pub fn assert_tenant_authority_wire_magics(registry_json: &str) -> Result<()> {
    let registry = parse_registry(registry_json).map_err(TenantAuthorityProtocolError::Magic)?;
    assert_registered(
        &registry,
        &[
            ("FCTA", "RemoteTenantAuthorityAuthorizationV1"),
            ("FCTO", "RemoteTenantAuthorityResultV1"),
            ("FCTV", "RemoteTenantAuthorityRevocationEvidenceV1"),
            ("FCIR", "RemoteIdentityRevocationRequestV1"),
        ],
    )
    .map_err(TenantAuthorityProtocolError::Magic)?;
    assert_registered(
        &registry,
        &[
            ("FCTR", "RemoteTurnProviderResultV1"),
            ("FCRS", "RemoteIpConsentStatusV1"),
        ],
    )
    .map_err(TenantAuthorityProtocolError::Magic)?;
    Ok(())
}

pub fn is_cross_protocol_magic(magic: &[u8; 4]) -> bool {
    magic == &FCTR || magic == &FCRS
}

// Foundation consumption guard
pub fn foundation_consumption_guard() {
    let _ = identity::FCIP;
    let _ = identity::FCEN;
    let _ = identity::FCCE;
    let _ = identity::FCPC;
    let _ = identity::FCPP;
    let _ = identity::FCCF;
    let _ = identity::SubjectKind::Client;
    let _ = policy::POLICY_JWS_TYP;
    let _ = policy::TRANSPORT_BIT_WEBRTC;
    let _ = policy::TUPLE_SET_MIN;
    let _ = policy::PERMISSION_CEILING_MAX_BYTES;
    let _ = magic::parse_registry as fn(&str) -> _;
    let _: fn(
        &RemotePermissionCeilingV1,
    ) -> std::result::Result<
        RemotePermissionCeilingDigestV1,
        policy::RemotePublicPolicyError,
    > = permission_ceiling_digest;
}

// Closed-surface guard
pub fn closed_surface_guard() {
    let _ = TenantAuthorityOperation::ALL.len();
    let _ = EvidenceType::ALL.len();
    let _ = FctoResultKind::ALL.len();
    let _ = FctoReasonCode::ALL.len();
    let _ = SigningDomain::ALL.len();
    let _ = DeviceEnrollmentAction::ALL.len();
    let _ = CredentialRegistryAction::ALL.len();
    let _ = RecoveryLifecycleAction::ALL.len();
    let _ = IdentityRevocationAction::ALL.len();
    let _ = FcirReason::ALL.len();
    assert_eq!(TenantAuthorityOperation::ALL.len(), 11);
    assert_eq!(EvidenceType::ALL.len(), 20);
    assert_eq!(FctoResultKind::ALL.len(), 5);
    assert_eq!(FctoReasonCode::ALL.len(), 19);
    assert_eq!(SigningDomain::ALL.len(), 6);
    assert_eq!(DeviceEnrollmentAction::ALL.len(), 3);
    assert_eq!(CredentialRegistryAction::ALL.len(), 4);
    assert_eq!(RecoveryLifecycleAction::ALL.len(), 4);
    assert_eq!(IdentityRevocationAction::ALL.len(), 2);
    assert_eq!(FcirReason::ALL.len(), 5);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_authority_protocol_closed_surface() {
        closed_surface_guard();
        foundation_consumption_guard();
        for (i, op) in TenantAuthorityOperation::ALL.iter().enumerate() {
            assert_eq!(op.discriminant() as usize, i + 1);
        }
        assert_eq!(
            TenantAuthorityOperation::AuthorityActivation.name(),
            "authority_activation"
        );
        for (i, et) in EvidenceType::ALL.iter().enumerate() {
            assert_eq!(et.discriminant() as usize, i + 1);
        }
        let jws = EvidenceType::ALL
            .iter()
            .filter(|e| e.category() == EvidenceCategory::CompactJws)
            .count();
        let json = EvidenceType::ALL
            .iter()
            .filter(|e| e.category() == EvidenceCategory::CanonicalJson)
            .count();
        let bin = EvidenceType::ALL
            .iter()
            .filter(|e| e.category() == EvidenceCategory::Binary)
            .count();
        assert_eq!(jws, 6);
        assert_eq!(json, 1);
        assert_eq!(bin, 13);
        assert_eq!(FctoResultKind::ALL.len(), 5);
        assert_eq!(FctoReasonCode::ALL.len(), 19);
        assert_eq!(FctoReasonCode::None.discriminant(), 0);
        assert_eq!(SigningDomain::ALL.len(), 6);
    }

    #[test]
    fn tenant_authority_protocol_wire_magic_registry() {
        let json = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-wire-magic-registry-v1.json"
        );
        assert_tenant_authority_wire_magics(json).unwrap();
        assert!(is_cross_protocol_magic(&FCTR));
        assert!(is_cross_protocol_magic(&FCRS));
        assert!(!is_cross_protocol_magic(&FCTA));
    }

    #[test]
    fn fcta_envelope_round_trip() {
        let body = vec![1u8, 0, 0];
        let body_digest = sha256(&body);
        let env = FctaEnvelope {
            operation: 9,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            issuer: "https://tenant.flycockpit.example".to_string(),
            governance_epoch: 1,
            policy_epoch: 1,
            issued_at: 1_000,
            expires_at: 1_060,
            body_digest,
            body,
        };
        let encoded = env.encode().unwrap();
        assert_eq!(&encoded[..4], &FCTA);
        assert!(encoded.len() <= MAX_REQUEST_BYTES);
        let decoded = FctaEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn fcta_rejects_cross_protocol_magic() {
        let mut bad = FCTR.to_vec();
        bad.push(1);
        assert!(matches!(
            FctaEnvelope::decode(&bad).unwrap_err(),
            TenantAuthorityProtocolError::Magic(_)
        ));
        bad[..4].copy_from_slice(&FCRS);
        assert!(matches!(
            FctaEnvelope::decode(&bad).unwrap_err(),
            TenantAuthorityProtocolError::Magic(_)
        ));
    }

    #[test]
    fn fcta_rejects_invalid_validity() {
        let body = vec![1u8, 0, 0];
        let body_digest = sha256(&body);
        let env = FctaEnvelope {
            operation: 9,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            issuer: "https://tenant.flycockpit.example".to_string(),
            governance_epoch: 1,
            policy_epoch: 1,
            issued_at: 1_000,
            expires_at: 1_061,
            body_digest,
            body,
        };
        assert!(env.encode().is_err());
    }

    #[test]
    fn fcto_envelope_round_trip() {
        let env = FctoEnvelope {
            operation: 9,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            result_kind: 3,
            reason_code: 0,
            statement_jws: vec![],
            artifact: vec![0xAB; 100],
        };
        let encoded = env.encode().unwrap();
        assert_eq!(&encoded[..4], &FCTO);
        let decoded = FctoEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn fcto_rejects_cross_protocol_magic() {
        let bad = vec![b'F', b'C', b'T', b'R', 1];
        assert!(matches!(
            FctoEnvelope::decode(&bad).unwrap_err(),
            TenantAuthorityProtocolError::Magic(_)
        ));
    }

    #[test]
    fn fcto_result_matrix_variants() {
        let authorized = FctoEnvelope {
            operation: 1,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            result_kind: 1,
            reason_code: 0,
            statement_jws: vec![0xAB; 100],
            artifact: vec![],
        };
        authorized.encode().unwrap();

        let denied = FctoEnvelope {
            operation: 1,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            result_kind: 2,
            reason_code: 9,
            statement_jws: vec![0xAB; 100],
            artifact: vec![],
        };
        denied.encode().unwrap();

        let error = FctoEnvelope {
            operation: 1,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            result_kind: 5,
            reason_code: 1,
            statement_jws: vec![],
            artifact: vec![],
        };
        error.encode().unwrap();

        // error with denial reason must fail
        let mismatch = FctoEnvelope {
            operation: 1,
            request_id: [1; 16],
            tenant_id: [2; 16],
            authority_id: [3; 16],
            result_kind: 5,
            reason_code: 9,
            statement_jws: vec![],
            artifact: vec![],
        };
        assert!(mismatch.encode().is_err());
    }

    #[test]
    fn fcir_round_trip() {
        let req = FcirRevocationRequest {
            subject_kind: SubjectKind::Client,
            subject_id: [1; 16],
            generation: 1,
            reason: FcirReason::UserRequested,
            requested_at: 1_000,
        };
        let encoded = req.encode().unwrap();
        assert_eq!(encoded.len(), 39);
        assert_eq!(&encoded[..4], &FCIR);
        let decoded = FcirRevocationRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn fcir_rejects_wrong_length() {
        let mut bad = vec![b'F', b'C', b'I', b'R', 1, 1];
        bad.extend(std::iter::repeat_n(0u8, 30));
        assert!(FcirRevocationRequest::decode(&bad).is_err());
    }

    #[test]
    fn fcqr_round_trip() {
        let req = FcqrQuotaRequest {
            requested_turn_bytes: 1000,
            requested_turn_seconds: 60,
            requested_websocket_bytes: 2000,
            requested_websocket_seconds: 120,
            budget_generation: 1,
            policy_digest: [0xAB; 32],
        };
        let encoded = req.encode().unwrap();
        assert_eq!(encoded.len(), 77);
        assert_eq!(&encoded[..4], &FCQR);
        let decoded = FcqrQuotaRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn approval_cardinality_matrix() {
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::AttemptGrant, None).unwrap(),
            ApprovalCardinality::None
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::DeviceEnrollment, Some(1)).unwrap(),
            ApprovalCardinality::OneSecurityAdmin
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::DeviceEnrollment, Some(2)).unwrap(),
            ApprovalCardinality::None
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::AuthorityActivation, None).unwrap(),
            ApprovalCardinality::OwnerPlusSecurityAdmin
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::IdentityRevocation, Some(1)).unwrap(),
            ApprovalCardinality::None
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::IdentityRevocation, Some(2)).unwrap(),
            ApprovalCardinality::OneSecurityAdmin
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::PolicyRevision, Some(1)).unwrap(),
            ApprovalCardinality::OneSecurityAdmin
        );
        assert_eq!(
            approval_cardinality(TenantAuthorityOperation::PolicyRevision, Some(2)).unwrap(),
            ApprovalCardinality::OwnerPlusSecurityAdmin
        );
    }

    #[test]
    fn evidence_type_cross_category_rejection() {
        let fcir = FcirRevocationRequest {
            subject_kind: SubjectKind::Client,
            subject_id: [1; 16],
            generation: 1,
            reason: FcirReason::UserRequested,
            requested_at: 1_000,
        }
        .encode()
        .unwrap();
        assert!(EvidenceType::AuthorityRing.validate(&fcir).is_err());
        assert!(EvidenceType::QuotaRequest.validate(&fcir).is_err());
    }

    #[test]
    fn normalized_https_origin_validation() {
        assert!(normalized_https_origin("https://tenant.flycockpit.example").is_ok());
        assert!(normalized_https_origin("https://tenant.flycockpit.example:8443").is_ok());
        assert!(normalized_https_origin("http://tenant.flycockpit.example").is_err());
        assert!(normalized_https_origin("https://Tenant.flycockpit.example").is_err());
        assert!(normalized_https_origin("https://tenant.flycockpit.example:443").is_err());
        assert!(normalized_https_origin("https://tenant.flycockpit.example/").is_err());
        assert!(normalized_https_origin("https://tenant.flycockpit.example?q=1").is_err());
    }
}
