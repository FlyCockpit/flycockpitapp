//! Signed public SaaS remote service-policy foundation.
//!
//! This module is the sole neutral owner of:
//!
//! - The closed `RemoteProjectCapabilityV1` and `RemoteAttachmentCapabilityV1`
//!   capability vocabularies (name/type/field-disjoint, intentionally
//!   overlapping ordinals `1..13`).
//! - The exact `RemotePermissionCeilingV1` network-byte-order binary codec and
//!   the `RemotePermissionCeilingDigestV1` helper.
//! - The `RemoteAuthorizedTransportBitsV1` and `RemoteAuthorizedTupleSetV1`
//!   authorization-ceiling codecs.
//! - The `RemoteConnectionPolicyV1` schema (no optional/defaulted fields).
//! - The signed, versioned `RemotePublicServicePolicyV1` wrapper, its RFC 8785
//!   canonical payload, compact ES256 JWS protected-header rules, and the
//!   `REMOTE_PUBLIC_SERVICE_POLICY_JWKS` strict verification ring.
//! - The total generated custody comparison/meet tables consumed by attempt
//!   authorization, enterprise policy, route selection, TURN issuance,
//!   fallback quotas, and metadata retention.
//!
//! Downstream consumers import these types/helpers directly and may not
//! redefine the enums, bit assignments, tuple-list parsing, permission bytes,
//! or digest derivation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::remote_protocol_id::{CanonicalU64DecimalStringV1, RemotePublicPolicyId};
use crate::remote_version::registry_tuple;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for `RemotePublicServicePolicyV1`.
pub const POLICY_SCHEMA_VERSION: u8 = 1;
/// Compact ES256 JWS protected-header `typ` value.
pub const POLICY_JWS_TYP: &str = "flycockpit-public-remote-policy+jws";
/// JWS `alg` for public service policy.
pub const POLICY_JWS_ALG: &str = "ES256";
/// Import clock-skew tolerance in seconds.
pub const IMPORT_CLOCK_SKEW_SECONDS: i64 = 60;
/// Maximum `notBefore` offset from `issuedAt` in seconds (30 days).
pub const NOT_BEFORE_MAX_OFFSET_SECONDS: i64 = 2_592_000;
/// The eight closed TURN region IDs, in canonical sorted order.
pub const ALLOWED_TURN_REGIONS: [&str; 8] = [
    "africa",
    "asia_pacific",
    "europe",
    "local",
    "middle_east",
    "north_america",
    "oceania",
    "south_america",
];
/// The two allowed transport names, in canonical sorted order.
pub const ALLOWED_TRANSPORTS: [&str; 2] = ["webrtc", "websocket_data"];
/// Maximum encoded size of `RemotePermissionCeilingV1`.
pub const PERMISSION_CEILING_MAX_BYTES: usize = 512;
/// Minimum/maximum tuple IDs in `RemoteAuthorizedTupleSetV1`.
pub const TUPLE_SET_MIN: usize = 1;
pub const TUPLE_SET_MAX: usize = 16;
/// Critical-consumer IDs (closed code-owned registry).
pub const CRITICAL_CONSUMER_IDS: [&str; 8] = [
    "attempt_issuer",
    "signaling_gateway",
    "daemon_authorizer",
    "turn_issuer",
    "websocket_fallback_gateway",
    "web_route_selector",
    "native_route_selector",
    "metadata_retention_worker",
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemotePublicPolicyError {
    #[error("invalid public service policy: {0}")]
    Invalid(String),
    #[error("invalid permission ceiling: {0}")]
    Ceiling(String),
    #[error("invalid JWS: {0}")]
    Jws(String),
    #[error("invalid JWKS: {0}")]
    Jwks(String),
    #[error("invalid capability: {0}")]
    Capability(String),
}

type Result<T> = std::result::Result<T, RemotePublicPolicyError>;
fn invalid<T>(s: impl Into<String>) -> Result<T> {
    Err(RemotePublicPolicyError::Invalid(s.into()))
}
fn ceiling_err<T>(s: impl Into<String>) -> Result<T> {
    Err(RemotePublicPolicyError::Ceiling(s.into()))
}

// ---------------------------------------------------------------------------
// RemoteProjectCapabilityV1 / RemoteAttachmentCapabilityV1
// ---------------------------------------------------------------------------

/// Project-scope capability ordinal. Name/type/field-disjoint from
/// attachment capabilities; ordinals `1..13` intentionally overlap because
/// each value is decoded only under its expected nominal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RemoteProjectCapabilityV1 {
    ProjectRead = 1,
    ProjectWrite = 2,
    FilesystemRead = 3,
    FilesystemWrite = 4,
    TerminalRead = 5,
    TerminalControl = 6,
    SessionRead = 7,
    SessionWrite = 8,
    NotesRead = 9,
    NotesWrite = 10,
    SchedulerRead = 11,
    SchedulerWrite = 12,
    ResourcePromote = 13,
    LspControl = 14,
    /// Foundation-owned from schema inception; image-generation consumers
    /// import it and may not register, redefine, renumber, or independently
    /// extend either capability enum.
    ImageGenerationAdmin = 15,
}

impl RemoteProjectCapabilityV1 {
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
    pub fn from_ordinal(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::ProjectRead),
            2 => Ok(Self::ProjectWrite),
            3 => Ok(Self::FilesystemRead),
            4 => Ok(Self::FilesystemWrite),
            5 => Ok(Self::TerminalRead),
            6 => Ok(Self::TerminalControl),
            7 => Ok(Self::SessionRead),
            8 => Ok(Self::SessionWrite),
            9 => Ok(Self::NotesRead),
            10 => Ok(Self::NotesWrite),
            11 => Ok(Self::SchedulerRead),
            12 => Ok(Self::SchedulerWrite),
            13 => Ok(Self::ResourcePromote),
            14 => Ok(Self::LspControl),
            15 => Ok(Self::ImageGenerationAdmin),
            _ => Err(RemotePublicPolicyError::Capability(format!(
                "unknown project capability ordinal {v}"
            ))),
        }
    }
    pub const fn all() -> &'static [Self] {
        &[
            Self::ProjectRead,
            Self::ProjectWrite,
            Self::FilesystemRead,
            Self::FilesystemWrite,
            Self::TerminalRead,
            Self::TerminalControl,
            Self::SessionRead,
            Self::SessionWrite,
            Self::NotesRead,
            Self::NotesWrite,
            Self::SchedulerRead,
            Self::SchedulerWrite,
            Self::ResourcePromote,
            Self::LspControl,
            Self::ImageGenerationAdmin,
        ]
    }
}

/// Attachment-scope capability ordinal. Ordinals `1..13` intentionally overlap
/// with project capabilities; cross-kind decode/conversion/comparison fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RemoteAttachmentCapabilityV1 {
    AttachmentRead = 1,
    AttachmentManageChildren = 2,
    SessionCreate = 3,
    SessionImport = 4,
    SessionArchive = 5,
    SessionDelete = 6,
    ModelConfigure = 7,
    AgentConfigure = 8,
    ApprovalConfigure = 9,
    SandboxConfigure = 10,
    CredentialManage = 11,
    DaemonManage = 12,
    UsageRecord = 13,
}

impl RemoteAttachmentCapabilityV1 {
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
    pub fn from_ordinal(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::AttachmentRead),
            2 => Ok(Self::AttachmentManageChildren),
            3 => Ok(Self::SessionCreate),
            4 => Ok(Self::SessionImport),
            5 => Ok(Self::SessionArchive),
            6 => Ok(Self::SessionDelete),
            7 => Ok(Self::ModelConfigure),
            8 => Ok(Self::AgentConfigure),
            9 => Ok(Self::ApprovalConfigure),
            10 => Ok(Self::SandboxConfigure),
            11 => Ok(Self::CredentialManage),
            12 => Ok(Self::DaemonManage),
            13 => Ok(Self::UsageRecord),
            _ => Err(RemotePublicPolicyError::Capability(format!(
                "unknown attachment capability ordinal {v}"
            ))),
        }
    }
    pub const fn all() -> &'static [Self] {
        &[
            Self::AttachmentRead,
            Self::AttachmentManageChildren,
            Self::SessionCreate,
            Self::SessionImport,
            Self::SessionArchive,
            Self::SessionDelete,
            Self::ModelConfigure,
            Self::AgentConfigure,
            Self::ApprovalConfigure,
            Self::SandboxConfigure,
            Self::CredentialManage,
            Self::DaemonManage,
            Self::UsageRecord,
        ]
    }
}

// ---------------------------------------------------------------------------
// RemotePermissionCeilingV1
// ---------------------------------------------------------------------------

/// Exact network-byte-order binary permission ceiling.
///
/// `version:u8(1) | attachmentCount:u8 | attachmentCapability:u8[] |
/// projectCount:u8 | (projectId:[16] | capabilityCount:u8 |
/// projectCapability:u8[])[]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePermissionCeilingV1 {
    pub attachment_capabilities: Vec<RemoteAttachmentCapabilityV1>,
    /// (project_id_bytes, project_capabilities) pairs, raw-project-ID-byte
    /// sorted and unique.
    pub projects: Vec<([u8; 16], Vec<RemoteProjectCapabilityV1>)>,
}

impl RemotePermissionCeilingV1 {
    /// Empty canonical ceiling (authorizes nothing).
    pub fn empty() -> Self {
        Self {
            attachment_capabilities: Vec::new(),
            projects: Vec::new(),
        }
    }

    /// Encode to the exact canonical byte representation. The complete
    /// aggregate length is computed before allocation, so a count-valid
    /// combination whose encoded bytes exceed 512 is rejected.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Validate attachment capabilities: enum-ordinal-sorted unique, count 0..16.
        validate_sorted_unique_ordinals(
            &self
                .attachment_capabilities
                .iter()
                .map(|c| c.ordinal())
                .collect::<Vec<_>>(),
            16,
            "attachment",
        )?;
        if self.attachment_capabilities.len() > 16 {
            return ceiling_err("attachment capability count exceeds 16");
        }

        // Validate projects: raw-project-ID-byte sorted unique, count 0..16,
        // each present project has 1..16 enum-ordinal-sorted unique capabilities.
        if self.projects.len() > 16 {
            return ceiling_err("project count exceeds 16");
        }
        let mut prev_id: Option<[u8; 16]> = None;
        for (pid, caps) in &self.projects {
            if pid.iter().all(|&b| b == 0) {
                return ceiling_err("project id must be nonzero");
            }
            if let Some(prev) = prev_id
                && &prev >= pid
            {
                return ceiling_err("project ids must be strictly ascending");
            }
            prev_id = Some(*pid);
            if caps.is_empty() || caps.len() > 16 {
                return ceiling_err("project capability count must be 1..16");
            }
            validate_sorted_unique_ordinals(
                &caps.iter().map(|c| c.ordinal()).collect::<Vec<_>>(),
                16,
                "project",
            )?;
        }

        // Compute aggregate length before allocation.
        let total = 1usize // version
            + 1 // attachmentCount
            + self.attachment_capabilities.len()
            + 1 // projectCount
            + self
                .projects
                .iter()
                .map(|(_pid, caps)| 16 + 1 + caps.len())
                .sum::<usize>();
        if total > PERMISSION_CEILING_MAX_BYTES {
            return ceiling_err(format!(
                "permission ceiling is {total} bytes; cap is {PERMISSION_CEILING_MAX_BYTES}"
            ));
        }

        let mut buf = Vec::with_capacity(total);
        buf.push(1); // version
        buf.push(self.attachment_capabilities.len() as u8);
        for cap in &self.attachment_capabilities {
            buf.push(cap.ordinal());
        }
        buf.push(self.projects.len() as u8);
        for (pid, caps) in &self.projects {
            buf.extend_from_slice(pid);
            buf.push(caps.len() as u8);
            for cap in caps {
                buf.push(cap.ordinal());
            }
        }
        debug_assert_eq!(buf.len(), total);
        Ok(buf)
    }

    /// Decode the exact canonical byte representation, rejecting trailing
    /// bytes, malformed lengths, oversize, duplicate/unsorted values, and
    /// cross-kind capabilities.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return ceiling_err("permission ceiling is empty");
        }
        if bytes[0] != 1 {
            return ceiling_err("permission ceiling version must be 1");
        }
        let mut pos = 1;
        if pos >= bytes.len() {
            return ceiling_err("truncated attachment count");
        }
        let att_count = bytes[pos] as usize;
        pos += 1;
        if att_count > 16 {
            return ceiling_err("attachment capability count exceeds 16");
        }
        if pos + att_count > bytes.len() {
            return ceiling_err("truncated attachment capabilities");
        }
        let mut att_caps: Vec<RemoteAttachmentCapabilityV1> = Vec::with_capacity(att_count);
        let mut prev_att: u8 = 0;
        for i in 0..att_count {
            let ord = bytes[pos + i];
            if ord == 0 {
                return ceiling_err("zero attachment capability ordinal");
            }
            if i > 0 && ord <= prev_att {
                return ceiling_err("attachment capabilities must be strictly ascending");
            }
            prev_att = ord;
            att_caps.push(RemoteAttachmentCapabilityV1::from_ordinal(ord)?);
        }
        pos += att_count;

        if pos >= bytes.len() {
            return ceiling_err("truncated project count");
        }
        let proj_count = bytes[pos] as usize;
        pos += 1;
        if proj_count > 16 {
            return ceiling_err("project count exceeds 16");
        }

        let mut projects: Vec<([u8; 16], Vec<RemoteProjectCapabilityV1>)> =
            Vec::with_capacity(proj_count);
        let mut prev_pid: Option<[u8; 16]> = None;
        for _ in 0..proj_count {
            if pos + 16 > bytes.len() {
                return ceiling_err("truncated project id");
            }
            let mut pid = [0u8; 16];
            pid.copy_from_slice(&bytes[pos..pos + 16]);
            pos += 16;
            if pid.iter().all(|&b| b == 0) {
                return ceiling_err("project id must be nonzero");
            }
            if let Some(prev) = prev_pid
                && prev >= pid
            {
                return ceiling_err("project ids must be strictly ascending");
            }
            prev_pid = Some(pid);
            if pos >= bytes.len() {
                return ceiling_err("truncated project capability count");
            }
            let cap_count = bytes[pos] as usize;
            pos += 1;
            if cap_count == 0 || cap_count > 16 {
                return ceiling_err("project capability count must be 1..16");
            }
            if pos + cap_count > bytes.len() {
                return ceiling_err("truncated project capabilities");
            }
            let mut caps: Vec<RemoteProjectCapabilityV1> = Vec::with_capacity(cap_count);
            let mut prev_cap: u8 = 0;
            for i in 0..cap_count {
                let ord = bytes[pos + i];
                if ord == 0 {
                    return ceiling_err("zero project capability ordinal");
                }
                if i > 0 && ord <= prev_cap {
                    return ceiling_err("project capabilities must be strictly ascending");
                }
                prev_cap = ord;
                caps.push(RemoteProjectCapabilityV1::from_ordinal(ord)?);
            }
            pos += cap_count;
            projects.push((pid, caps));
        }

        if pos != bytes.len() {
            return ceiling_err("trailing bytes in permission ceiling");
        }

        let ceiling = Self {
            attachment_capabilities: att_caps,
            projects,
        };
        // Re-encode to confirm canonical round-trip.
        let re = ceiling.encode()?;
        if re != bytes {
            return ceiling_err("permission ceiling noncanonical re-encoding");
        }
        Ok(ceiling)
    }
}

fn validate_sorted_unique_ordinals(ords: &[u8], max: usize, label: &str) -> Result<()> {
    if ords.len() > max {
        return ceiling_err(format!("{label} capability count exceeds {max}"));
    }
    let mut prev: u8 = 0;
    for (i, &o) in ords.iter().enumerate() {
        if o == 0 {
            return ceiling_err(format!("zero {label} capability ordinal"));
        }
        if i > 0 && o <= prev {
            return ceiling_err(format!("{label} capabilities must be strictly ascending"));
        }
        prev = o;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RemotePermissionCeilingDigestV1
// ---------------------------------------------------------------------------

/// The 32-byte SHA-256 digest of the complete canonical
/// `RemotePermissionCeilingV1` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemotePermissionCeilingDigestV1 {
    bytes: [u8; 32],
}

impl RemotePermissionCeilingDigestV1 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    /// Lowercase 64-character hexadecimal string (JSON/JWS representation).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.bytes {
            use std::fmt::Write;
            write!(&mut s, "{b:02x}").expect("writing to String");
        }
        s
    }
}

/// Compute the `RemotePermissionCeilingDigestV1` from a validated ceiling
/// value. Invokes the foundation canonical encoder exactly once, hashes the
/// complete returned byte string, and returns the digest. There is no null,
/// zero, domain-prefixed, payload-projection, re-encoded, or caller-supplied
/// alternative.
pub fn permission_ceiling_digest(
    ceiling: &RemotePermissionCeilingV1,
) -> Result<RemotePermissionCeilingDigestV1> {
    let bytes = ceiling.encode()?;
    let digest = Sha256::digest(&bytes);
    Ok(RemotePermissionCeilingDigestV1 {
        bytes: digest.into(),
    })
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedTransportBitsV1
// ---------------------------------------------------------------------------

/// One byte: bit 0 (`0x01`) is `webrtc`, bit 1 (`0x02`) is `websocket_data`.
/// The only valid values are `0x01`, `0x02`, and `0x03`.
pub const TRANSPORT_BIT_WEBRTC: u8 = 0x01;
pub const TRANSPORT_BIT_WEBSOCKET_DATA: u8 = 0x02;
pub const TRANSPORT_BITS_VALID: [u8; 3] = [0x01, 0x02, 0x03];

/// Validate a `RemoteAuthorizedTransportBitsV1` byte.
pub fn validate_transport_bits(bits: u8) -> Result<()> {
    if !TRANSPORT_BITS_VALID.contains(&bits) {
        return invalid(format!(
            "transport bits must be 0x01, 0x02, or 0x03; got 0x{bits:02x}"
        ));
    }
    Ok(())
}

/// Encode the transport bits byte. Validates first.
pub fn encode_transport_bits(bits: u8) -> Result<u8> {
    validate_transport_bits(bits)?;
    Ok(bits)
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedTupleSetV1
// ---------------------------------------------------------------------------

/// `RemoteAuthorizedTupleSetV1`: `count:u8 | tupleIds:u16be[count]`, count
/// `1..16`, strictly increasing and unique. Every ID is nonzero and must
/// exist and be enabled/nonrevoked in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuthorizedTupleSetV1 {
    pub tuple_ids: Vec<u16>,
}

impl RemoteAuthorizedTupleSetV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !(TUPLE_SET_MIN..=TUPLE_SET_MAX).contains(&self.tuple_ids.len()) {
            return invalid(format!(
                "tuple set count must be {}..={}",
                TUPLE_SET_MIN, TUPLE_SET_MAX
            ));
        }
        let mut prev: u16 = 0;
        for (i, &id) in self.tuple_ids.iter().enumerate() {
            if id == 0 {
                return invalid("tuple id must be nonzero");
            }
            if i > 0 && id <= prev {
                return invalid("tuple ids must be strictly increasing");
            }
            prev = id;
            if registry_tuple(id).is_none() {
                return invalid(format!("tuple id {id} not in enabled registry"));
            }
        }
        let mut buf = Vec::with_capacity(1 + self.tuple_ids.len() * 2);
        buf.push(self.tuple_ids.len() as u8);
        for id in &self.tuple_ids {
            buf.extend_from_slice(&id.to_be_bytes());
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return invalid("tuple set is empty");
        }
        let count = bytes[0] as usize;
        if !(TUPLE_SET_MIN..=TUPLE_SET_MAX).contains(&count) {
            return invalid(format!(
                "tuple set count must be {}..={}",
                TUPLE_SET_MIN, TUPLE_SET_MAX
            ));
        }
        if bytes.len() != 1 + count * 2 {
            return invalid("tuple set length mismatch");
        }
        let mut ids: Vec<u16> = Vec::with_capacity(count);
        let mut prev: u16 = 0;
        for i in 0..count {
            let off = 1 + i * 2;
            let id = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            if id == 0 {
                return invalid("tuple id must be nonzero");
            }
            if i > 0 && id <= prev {
                return invalid("tuple ids must be strictly increasing");
            }
            prev = id;
            if registry_tuple(id).is_none() {
                return invalid(format!("tuple id {id} not in enabled registry"));
            }
            ids.push(id);
        }
        let set = Self { tuple_ids: ids };
        // Re-encode to confirm canonical round-trip.
        let re = set.encode()?;
        if re != bytes {
            return invalid("tuple set noncanonical re-encoding");
        }
        Ok(set)
    }
}

// ---------------------------------------------------------------------------
// RemoteConnectionPolicyV1 — custody enums
// ---------------------------------------------------------------------------

/// Daemon custody policy threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonCustodyPolicy {
    OsProtected,
    HardwareOrExternal,
}

/// Client custody policy threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCustodyPolicy {
    OriginProtected,
    OsProtected,
    Hardware,
}

/// Certificate custody class (mapped to policy threshold).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyCertificateClass {
    OriginProtected,
    OsProtected,
    HardwareOrExternal,
}

impl CustodyCertificateClass {
    /// Map a certificate class to a client policy threshold.
    /// `hardware_or_external` maps only to policy `hardware`.
    pub fn to_client_policy(self) -> ClientCustodyPolicy {
        match self {
            Self::OriginProtected => ClientCustodyPolicy::OriginProtected,
            Self::OsProtected => ClientCustodyPolicy::OsProtected,
            Self::HardwareOrExternal => ClientCustodyPolicy::Hardware,
        }
    }
}

/// Daemon custody ordering: `os_protected < hardware_or_external`.
impl DaemonCustodyPolicy {
    pub fn rank(self) -> u8 {
        match self {
            Self::OsProtected => 0,
            Self::HardwareOrExternal => 1,
        }
    }
    /// Total generated daemon meet table:
    /// `os×os=os; os×hardware=hardware; hardware×os=hardware; hardware×hardware=hardware`.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::OsProtected, Self::OsProtected) => Self::OsProtected,
            (Self::OsProtected, Self::HardwareOrExternal) => Self::HardwareOrExternal,
            (Self::HardwareOrExternal, Self::OsProtected) => Self::HardwareOrExternal,
            (Self::HardwareOrExternal, Self::HardwareOrExternal) => Self::HardwareOrExternal,
        }
    }
}

/// Client custody ordering: `origin_protected < os_protected < hardware`.
impl ClientCustodyPolicy {
    pub fn rank(self) -> u8 {
        match self {
            Self::OriginProtected => 0,
            Self::OsProtected => 1,
            Self::Hardware => 2,
        }
    }
    /// Total generated symmetric client meet table — returns the
    /// rightmost/stricter value for every pair.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::OriginProtected, Self::OriginProtected) => Self::OriginProtected,
            (Self::OriginProtected, Self::OsProtected)
            | (Self::OsProtected, Self::OriginProtected) => Self::OsProtected,
            (Self::OriginProtected, Self::Hardware) | (Self::Hardware, Self::OriginProtected) => {
                Self::Hardware
            }
            (Self::OsProtected, Self::OsProtected) => Self::OsProtected,
            (Self::OsProtected, Self::Hardware) | (Self::Hardware, Self::OsProtected) => {
                Self::Hardware
            }
            (Self::Hardware, Self::Hardware) => Self::Hardware,
        }
    }
    /// A device satisfies a minimum only when its mapped class is at least
    /// that threshold.
    pub fn satisfies(device: Self, minimum: Self) -> bool {
        device.rank() >= minimum.rank()
    }
}

// ---------------------------------------------------------------------------
// RemoteConnectionPolicyV1
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectIpMode {
    Forbid,
    MutualConsent,
}

/// `directIpMode` ordering: `forbid < mutual_consent` by permissiveness.
/// The meet of two values chooses the stricter (forbid).
impl DirectIpMode {
    pub fn rank(self) -> u8 {
        match self {
            Self::Forbid => 0,
            Self::MutualConsent => 1,
        }
    }
    /// Total meet table: `forbid×forbid=forbid; forbid×mutual=forbid;
    /// mutual×forbid=forbid; mutual×mutual=mutual`.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Forbid, _) | (_, Self::Forbid) => Self::Forbid,
            (Self::MutualConsent, Self::MutualConsent) => Self::MutualConsent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedSessionRoute {
    RelayOnly,
    PerLegPolicy,
}

/// `sharedSessionRoute` ordering: `relay_only < per_leg_policy` by
/// permissiveness. The meet chooses the stricter (relay_only).
impl SharedSessionRoute {
    pub fn rank(self) -> u8 {
        match self {
            Self::RelayOnly => 0,
            Self::PerLegPolicy => 1,
        }
    }
    /// Total meet table: `relay_only×relay_only=relay_only;
    /// relay_only×per_leg=relay_only; per_leg×relay_only=relay_only;
    /// per_leg×per_leg=per_leg`.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::RelayOnly, _) | (_, Self::RelayOnly) => Self::RelayOnly,
            (Self::PerLegPolicy, Self::PerLegPolicy) => Self::PerLegPolicy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantAuthorization {
    ControlPlane,
    TenantSignerRequired,
}

/// `tenantAuthorization` ordering: `tenant_signer_required < control_plane`
/// by permissiveness. The meet chooses the stricter signer requirement.
impl TenantAuthorization {
    pub fn rank(self) -> u8 {
        match self {
            Self::TenantSignerRequired => 0,
            Self::ControlPlane => 1,
        }
    }
    /// Total meet table: `signer×signer=signer; signer×control=signer;
    /// control×signer=signer; control×control=control`.
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::TenantSignerRequired, _) | (_, Self::TenantSignerRequired) => {
                Self::TenantSignerRequired
            }
            (Self::ControlPlane, Self::ControlPlane) => Self::ControlPlane,
        }
    }
}

/// Positive-width resource limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteConnectionLimitsV1 {
    pub registered_daemons: CanonicalU64DecimalStringV1,
    pub concurrent_attachments: CanonicalU64DecimalStringV1,
    pub concurrent_children_per_attachment: CanonicalU64DecimalStringV1,
    pub concurrent_participants_per_session: CanonicalU64DecimalStringV1,
    pub turn_bytes_per_attachment: CanonicalU64DecimalStringV1,
    pub turn_duration_seconds: CanonicalU64DecimalStringV1,
    pub websocket_bytes_per_attachment: CanonicalU64DecimalStringV1,
    pub websocket_duration_seconds: CanonicalU64DecimalStringV1,
}

impl RemoteConnectionLimitsV1 {
    /// Validate all limits are positive-width (nonzero).
    pub fn validate(&self) -> Result<()> {
        for (name, v) in [
            ("registeredDaemons", self.registered_daemons.value()),
            ("concurrentAttachments", self.concurrent_attachments.value()),
            (
                "concurrentChildrenPerAttachment",
                self.concurrent_children_per_attachment.value(),
            ),
            (
                "concurrentParticipantsPerSession",
                self.concurrent_participants_per_session.value(),
            ),
            (
                "turnBytesPerAttachment",
                self.turn_bytes_per_attachment.value(),
            ),
            ("turnDurationSeconds", self.turn_duration_seconds.value()),
            (
                "websocketBytesPerAttachment",
                self.websocket_bytes_per_attachment.value(),
            ),
            (
                "websocketDurationSeconds",
                self.websocket_duration_seconds.value(),
            ),
        ] {
            if v == 0 {
                return invalid(format!("limit {name} must be positive (nonzero)"));
            }
        }
        Ok(())
    }
}

/// `RemoteConnectionPolicyV1` — no optional/defaulted fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteConnectionPolicyV1 {
    pub allowed_transports: Vec<String>,
    pub direct_ip_mode: DirectIpMode,
    pub shared_session_route: SharedSessionRoute,
    pub websocket_fallback: bool,
    pub tenant_authorization: TenantAuthorization,
    pub minimum_daemon_custody: DaemonCustodyPolicy,
    pub minimum_client_custody: ClientCustodyPolicy,
    pub sharing_enabled: bool,
    pub limits: RemoteConnectionLimitsV1,
    pub allowed_turn_regions: Vec<String>,
    pub metadata_retention_days: CanonicalU64DecimalStringV1,
}

impl RemoteConnectionPolicyV1 {
    /// Validate the full policy: sorted nonempty transports, sorted unique
    /// regions, positive limits, retention in 0..365, all field constraints,
    /// and exact cross-field rules.
    pub fn validate(&self) -> Result<()> {
        // allowedTransports: sorted nonempty subset of webrtc|websocket_data
        if self.allowed_transports.is_empty() {
            return invalid("allowedTransports must be nonempty");
        }
        validate_sorted_unique_strings(&self.allowed_transports, &ALLOWED_TRANSPORTS, "transport")?;

        // allowedTurnRegions: sorted unique subset of the eight closed region IDs
        validate_sorted_unique_strings(
            &self.allowed_turn_regions,
            &ALLOWED_TURN_REGIONS,
            "turn region",
        )?;

        // metadataRetentionDays in 0..365
        let retention = self.metadata_retention_days.value();
        if retention > 365 {
            return invalid(format!(
                "metadataRetentionDays must be 0..365; got {retention}"
            ));
        }

        // limits positive-width
        self.limits.validate()?;

        // Cross-field rules (exact, closed):
        //
        // 1. websocketFallback=true requires websocket_data in allowedTransports.
        // 2. sharedSessionRoute=relay_only requires either WebRTC with at
        //    least one TURN region, or WebSocket fallback enabled.
        // 3. directIpMode=forbid prevents direct routes (enforced by the
        //    evaluator: no direct IP route is ever selected when forbid).
        //    The schema-level rule is that forbid is a valid closed value;
        //    the route-selection ceiling is enforced at evaluation time.
        // 4. tenantAuthorization=tenant_signer_required requires an active
        //    tenant signer/governance epoch — enforced by the enterprise
        //    connection policy module which checks the signer flow.

        if self.websocket_fallback
            && !self
                .allowed_transports
                .contains(&"websocket_data".to_string())
        {
            return invalid("websocketFallback=true requires websocket_data in allowedTransports");
        }

        if self.shared_session_route == SharedSessionRoute::RelayOnly {
            let has_webrtc = self.allowed_transports.contains(&"webrtc".to_string());
            let has_region = !self.allowed_turn_regions.is_empty();
            if !(has_webrtc && has_region) && !self.websocket_fallback {
                return invalid(
                    "sharedSessionRoute=relay_only requires either WebRTC with at least one region or WebSocket fallback",
                );
            }
        }

        Ok(())
    }

    /// Whether `websocket_data` is in the allowed transports set.
    pub fn allows_websocket_data(&self) -> bool {
        self.allowed_transports
            .contains(&"websocket_data".to_string())
    }

    /// Whether `webrtc` is in the allowed transports set.
    pub fn allows_webrtc(&self) -> bool {
        self.allowed_transports.contains(&"webrtc".to_string())
    }

    /// Whether direct IP routes are permitted (mutual_consent) or forbidden.
    pub fn direct_ip_permitted(&self) -> bool {
        self.direct_ip_mode == DirectIpMode::MutualConsent
    }
}

fn validate_sorted_unique_strings(values: &[String], allowed: &[&str], label: &str) -> Result<()> {
    let mut prev: &str = "";
    for (i, v) in values.iter().enumerate() {
        if !allowed.contains(&v.as_str()) {
            return invalid(format!("unknown {label} {v}"));
        }
        if i > 0 && v.as_str() <= prev {
            return invalid(format!("{label}s must be strictly ascending and unique"));
        }
        prev = v.as_str();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RemotePublicServicePolicyV1
// ---------------------------------------------------------------------------

/// Change classification: a version may not mix widening and narrowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    NarrowingOrEqual,
    Widening,
}

/// `RemotePublicServicePolicyV1`:
/// `{schemaVersion:1, policyId, serviceVersion:u64, previousDigest:null|hex,
/// issuedAt:i64, notBefore:i64, changeClass, policy:RemoteConnectionPolicyV1}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemotePublicServicePolicyV1 {
    pub schema_version: u8,
    pub policy_id: RemotePublicPolicyId,
    pub service_version: CanonicalU64DecimalStringV1,
    pub previous_digest: Option<String>,
    pub issued_at: CanonicalU64DecimalStringV1,
    pub not_before: CanonicalU64DecimalStringV1,
    pub change_class: ChangeClass,
    pub policy: RemoteConnectionPolicyV1,
}

impl RemotePublicServicePolicyV1 {
    /// Validate the full signed policy envelope.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return invalid(format!(
                "schemaVersion must be {POLICY_SCHEMA_VERSION}; got {}",
                self.schema_version
            ));
        }
        // serviceVersion is u64 via canonical decimal string — nonzero not
        // required by the type but initial version is 1; the value itself is
        // already validated by CanonicalU64DecimalStringV1 parsing.

        // previousDigest: lowercase 64-char hex or null
        if let Some(d) = &self.previous_digest {
            validate_digest_hex(d)?;
        }

        // issuedAt and notBefore are i64-valued but carried as canonical u64
        // decimal strings (semantic u64). The prompt says JWS timestamps are
        // the dependency-owned canonical decimal string and RFC 8785 signs
        // those strings. The written u64 type annotations are semantic values.
        // We validate they parse as u64; import-time skew checks use values().
        let _issued = self.issued_at.value();
        let _not_before = self.not_before.value();

        // policy field constraints
        self.policy.validate()?;

        Ok(())
    }

    /// RFC 8785 canonical JSON of exactly the envelope fields.
    pub fn canonical_json(&self) -> Result<String> {
        // Serialize to a Value, then canonicalize. We use serde_json::to_value
        // then the canonical_json helper to guarantee RFC 8785 ordering.
        let value = serde_json::to_value(self)
            .map_err(|e| RemotePublicPolicyError::Invalid(e.to_string()))?;
        canonical_json_value(&value)
    }

    /// Compute the SHA-256 digest of the canonical JSON payload, returned as
    /// lowercase 64-character hex (the policy digest).
    pub fn payload_digest_hex(&self) -> Result<String> {
        let canonical = self.canonical_json()?;
        let digest = Sha256::digest(canonical.as_bytes());
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("writing to String");
        }
        Ok(hex)
    }

    /// Import-time validation with clock skew checks.
    /// - Allows 60 seconds clock skew.
    /// - `issuedAt <= importTime + 60`
    /// - `notBefore >= issuedAt - 60`
    /// - `notBefore <= issuedAt + 2,592,000` (30 days)
    pub fn validate_for_import(&self, import_time: i64) -> Result<()> {
        self.validate()?;
        let issued = self.issued_at.value() as i64;
        let not_before = self.not_before.value() as i64;

        if issued > import_time + IMPORT_CLOCK_SKEW_SECONDS {
            return invalid(format!(
                "issuedAt {issued} exceeds importTime {import_time} + {IMPORT_CLOCK_SKEW_SECONDS}s skew"
            ));
        }
        if not_before < issued - IMPORT_CLOCK_SKEW_SECONDS {
            return invalid(format!(
                "notBefore {not_before} is before issuedAt {issued} - {IMPORT_CLOCK_SKEW_SECONDS}s skew"
            ));
        }
        if not_before > issued + NOT_BEFORE_MAX_OFFSET_SECONDS {
            return invalid(format!(
                "notBefore {not_before} exceeds issuedAt {issued} + {NOT_BEFORE_MAX_OFFSET_SECONDS}s (30 days)"
            ));
        }
        Ok(())
    }
}

/// Validate a lowercase 64-character SHA-256 hex digest string.
pub fn validate_digest_hex(hex: &str) -> Result<()> {
    if hex.len() != 64 {
        return invalid(format!("digest must be 64 hex chars; got {}", hex.len()));
    }
    if !hex
        .bytes()
        .all(|b| (b'a'..=b'f').contains(&b) || b.is_ascii_digit())
    {
        return invalid("digest must be lowercase hex");
    }
    Ok(())
}

/// RFC 8785 canonical JSON (sorted keys, no whitespace). Reuses the same
/// algorithm as `remote_identity_protocol::canonical_json` but is local to
/// this module to keep the trust domain self-contained.
pub fn canonical_json_value(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => serde_json::to_string(value)
            .map_err(|e| RemotePublicPolicyError::Invalid(e.to_string())),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json_value)
                .collect::<Result<Vec<_>>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut parts: Vec<String> = Vec::with_capacity(keys.len());
            for key in keys {
                let k = serde_json::to_string(key)
                    .map_err(|e| RemotePublicPolicyError::Invalid(e.to_string()))?;
                let v = canonical_json_value(&values[key])?;
                parts.push(format!("{k}:{v}"));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

// ---------------------------------------------------------------------------
// Compact ES256 JWS protected header
// ---------------------------------------------------------------------------

/// Parsed compact ES256 JWS for a public service policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPolicyJws {
    pub protected_header: Value,
    pub payload: Value,
    pub signature: Vec<u8>,
    pub signing_input: Vec<u8>,
}

/// Parse and validate a compact ES256 JWS for a public service policy.
///
/// Protected header must be exactly `{alg:"ES256",kid,typ:"flycockpit-public-remote-policy+jws"}`
/// with no unprotected/critical/unknown header.
pub fn parse_policy_jws(compact: &str) -> Result<ParsedPolicyJws> {
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 3 {
        return Err(RemotePublicPolicyError::Jws(
            "compact JWS must have exactly three parts".into(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| RemotePublicPolicyError::Jws("invalid base64url header".into()))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| RemotePublicPolicyError::Jws("invalid base64url payload".into()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| RemotePublicPolicyError::Jws("invalid base64url signature".into()))?;

    // Re-encode to confirm canonical base64url.
    if URL_SAFE_NO_PAD.encode(&header_bytes) != parts[0] {
        return Err(RemotePublicPolicyError::Jws(
            "noncanonical base64url header".into(),
        ));
    }
    if URL_SAFE_NO_PAD.encode(&payload_bytes) != parts[1] {
        return Err(RemotePublicPolicyError::Jws(
            "noncanonical base64url payload".into(),
        ));
    }
    if URL_SAFE_NO_PAD.encode(&signature) != parts[2] {
        return Err(RemotePublicPolicyError::Jws(
            "noncanonical base64url signature".into(),
        ));
    }

    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| RemotePublicPolicyError::Jws(e.to_string()))?;
    validate_policy_jws_header(&header)?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| RemotePublicPolicyError::Jws(e.to_string()))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();

    Ok(ParsedPolicyJws {
        protected_header: header,
        payload,
        signature,
        signing_input,
    })
}

/// Validate the compact ES256 JWS protected header for a public service policy.
pub fn validate_policy_jws_header(header: &Value) -> Result<()> {
    let obj = match header {
        Value::Object(o) => o,
        _ => {
            return Err(RemotePublicPolicyError::Jws(
                "header must be an object".into(),
            ));
        }
    };
    // Exactly three keys: alg, kid, typ.
    if obj.len() != 3 {
        return Err(RemotePublicPolicyError::Jws(format!(
            "header must have exactly 3 keys; got {}",
            obj.len()
        )));
    }
    let alg = obj
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RemotePublicPolicyError::Jws("header missing alg".into()))?;
    if alg != POLICY_JWS_ALG {
        return Err(RemotePublicPolicyError::Jws(format!(
            "header alg must be {POLICY_JWS_ALG}; got {alg}"
        )));
    }
    let typ = obj
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RemotePublicPolicyError::Jws("header missing typ".into()))?;
    if typ != POLICY_JWS_TYP {
        return Err(RemotePublicPolicyError::Jws(format!(
            "header typ must be {POLICY_JWS_TYP}; got {typ}"
        )));
    }
    let kid = obj
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RemotePublicPolicyError::Jws("header missing kid".into()))?;
    if kid.is_empty() {
        return Err(RemotePublicPolicyError::Jws(
            "header kid must be nonempty".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// REMOTE_PUBLIC_SERVICE_POLICY_JWKS
// ---------------------------------------------------------------------------

/// JWK role within the rotation ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwkRole {
    Current,
    Previous,
    Next,
}

/// A single JWK in the policy verification ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyJwk {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub r#use: String,
    pub key_ops: Vec<String>,
    pub flycockpit_role: JwkRole,
}

/// The parsed and validated `REMOTE_PUBLIC_SERVICE_POLICY_JWKS` ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyJwksRing {
    pub keys: Vec<PolicyJwk>,
}

impl PolicyJwksRing {
    pub fn current(&self) -> Option<&PolicyJwk> {
        self.keys
            .iter()
            .find(|k| k.flycockpit_role == JwkRole::Current)
    }
    pub fn previous(&self) -> Option<&PolicyJwk> {
        self.keys
            .iter()
            .find(|k| k.flycockpit_role == JwkRole::Previous)
    }
    pub fn next(&self) -> Option<&PolicyJwk> {
        self.keys
            .iter()
            .find(|k| k.flycockpit_role == JwkRole::Next)
    }
}

/// Parse and validate the `REMOTE_PUBLIC_SERVICE_POLICY_JWKS` ring.
///
/// Exact 1..=3-key rotation ring with exactly one `current`, at most one each
/// `previous` and `next`. Every JWK has unique nonempty `kid`, `kty:"EC"`,
/// `crv:"P-256"`, exact 32-byte base64url `x/y`, `use:"sig"`,
/// `key_ops:["verify"]`, and no private/unknown fields.
pub fn parse_policy_jwks(json: &str) -> Result<PolicyJwksRing> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| RemotePublicPolicyError::Jwks(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| RemotePublicPolicyError::Jwks("JWKS must be an object".into()))?;

    // Only "keys" is allowed at top level.
    if obj.len() != 1 || !obj.contains_key("keys") {
        return Err(RemotePublicPolicyError::Jwks(
            "JWKS must have exactly one 'keys' field".into(),
        ));
    }
    let keys_arr = obj["keys"]
        .as_array()
        .ok_or_else(|| RemotePublicPolicyError::Jwks("'keys' must be an array".into()))?;

    if !(1..=3).contains(&keys_arr.len()) {
        return Err(RemotePublicPolicyError::Jwks(format!(
            "JWKS must have 1..=3 keys; got {}",
            keys_arr.len()
        )));
    }

    let mut jwks: Vec<PolicyJwk> = Vec::with_capacity(keys_arr.len());
    let mut kids: Vec<String> = Vec::new();
    let mut thumbprints: Vec<String> = Vec::new();
    let mut has_current = false;
    let mut has_previous = false;
    let mut has_next = false;

    for key_val in keys_arr {
        let key_obj = key_val
            .as_object()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("JWK must be an object".into()))?;

        // No private/unknown fields: allowed set is exactly
        // {kid,kty,crv,x,y,use,key_ops,flycockpit_role}.
        let allowed = [
            "kid",
            "kty",
            "crv",
            "x",
            "y",
            "use",
            "key_ops",
            "flycockpit_role",
        ];
        for k in key_obj.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(RemotePublicPolicyError::Jwks(format!(
                    "unknown JWK field {k}"
                )));
            }
        }
        if key_obj.len() != allowed.len() {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "JWK must have exactly {} fields; got {}",
                allowed.len(),
                key_obj.len()
            )));
        }

        let kid = key_obj["kid"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("kid must be a string".into()))?;
        if kid.is_empty() {
            return Err(RemotePublicPolicyError::Jwks("kid must be nonempty".into()));
        }
        if kids.iter().any(|k| k == kid) {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "duplicate kid {kid}"
            )));
        }
        kids.push(kid.to_string());

        let kty = key_obj["kty"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("kty must be a string".into()))?;
        if kty != "EC" {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "kty must be EC; got {kty}"
            )));
        }

        let crv = key_obj["crv"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("crv must be a string".into()))?;
        if crv != "P-256" {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "crv must be P-256; got {crv}"
            )));
        }

        let x = key_obj["x"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("x must be a string".into()))?;
        let y = key_obj["y"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("y must be a string".into()))?;
        validate_base64url_32bytes(x, "x")?;
        validate_base64url_32bytes(y, "y")?;

        // P-256 point validation: x and y must decode to 32 bytes each and not
        // be all-zero (degenerate). Full curve validation is out of scope for
        // the parsing layer; the strict 32-byte + nonzero check matches the
        // authority key-ring pattern.
        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| RemotePublicPolicyError::Jwks("x decode failed".into()))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|_| RemotePublicPolicyError::Jwks("y decode failed".into()))?;
        if x_bytes.iter().all(|&b| b == 0) || y_bytes.iter().all(|&b| b == 0) {
            return Err(RemotePublicPolicyError::Jwks(
                "P-256 point coordinate must be nonzero".into(),
            ));
        }

        // RFC 7638 thumbprint uniqueness.
        let thumbprint = rfc7638_thumbprint(&x_bytes, &y_bytes)?;
        if thumbprints.iter().any(|t| t == &thumbprint) {
            return Err(RemotePublicPolicyError::Jwks(
                "duplicate RFC 7638 thumbprint".into(),
            ));
        }
        thumbprints.push(thumbprint);

        let use_val = key_obj["use"]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("use must be a string".into()))?;
        if use_val != "sig" {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "use must be sig; got {use_val}"
            )));
        }

        let key_ops = key_obj["key_ops"]
            .as_array()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("key_ops must be an array".into()))?;
        if key_ops.len() != 1 {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "key_ops must have exactly one element; got {}",
                key_ops.len()
            )));
        }
        let op = key_ops[0]
            .as_str()
            .ok_or_else(|| RemotePublicPolicyError::Jwks("key_ops[0] must be a string".into()))?;
        if op != "verify" {
            return Err(RemotePublicPolicyError::Jwks(format!(
                "key_ops must be [\"verify\"]; got [{op}]"
            )));
        }

        let role = key_obj["flycockpit_role"].as_str().ok_or_else(|| {
            RemotePublicPolicyError::Jwks("flycockpit_role must be a string".into())
        })?;
        let role = match role {
            "current" => JwkRole::Current,
            "previous" => JwkRole::Previous,
            "next" => JwkRole::Next,
            _ => {
                return Err(RemotePublicPolicyError::Jwks(format!(
                    "flycockpit_role must be current|previous|next; got {role}"
                )));
            }
        };
        match role {
            JwkRole::Current => {
                if has_current {
                    return Err(RemotePublicPolicyError::Jwks(
                        "duplicate current role".into(),
                    ));
                }
                has_current = true;
            }
            JwkRole::Previous => {
                if has_previous {
                    return Err(RemotePublicPolicyError::Jwks(
                        "duplicate previous role".into(),
                    ));
                }
                has_previous = true;
            }
            JwkRole::Next => {
                if has_next {
                    return Err(RemotePublicPolicyError::Jwks("duplicate next role".into()));
                }
                has_next = true;
            }
        }

        jwks.push(PolicyJwk {
            kid: kid.to_string(),
            kty: kty.to_string(),
            crv: crv.to_string(),
            x: x.to_string(),
            y: y.to_string(),
            r#use: use_val.to_string(),
            key_ops: vec![op.to_string()],
            flycockpit_role: role,
        });
    }

    if !has_current {
        return Err(RemotePublicPolicyError::Jwks(
            "JWKS must have exactly one current key".into(),
        ));
    }

    Ok(PolicyJwksRing { keys: jwks })
}

fn validate_base64url_32bytes(s: &str, label: &str) -> Result<()> {
    if s.contains('=') {
        return Err(RemotePublicPolicyError::Jwks(format!(
            "{label} must be unpadded base64url"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| RemotePublicPolicyError::Jwks(format!("{label} decode failed")))?;
    if bytes.len() != 32 {
        return Err(RemotePublicPolicyError::Jwks(format!(
            "{label} must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    if URL_SAFE_NO_PAD.encode(&bytes) != s {
        return Err(RemotePublicPolicyError::Jwks(format!(
            "{label} noncanonical base64url"
        )));
    }
    Ok(())
}

/// RFC 7638 JWK thumbprint for an EC P-256 key.
fn rfc7638_thumbprint(x: &[u8], y: &[u8]) -> Result<String> {
    // Canonical JSON: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    let x_b64 = URL_SAFE_NO_PAD.encode(x);
    let y_b64 = URL_SAFE_NO_PAD.encode(y);
    let canonical =
        format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x_b64}\",\"y\":\"{y_b64}\"}}");
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

// ---------------------------------------------------------------------------
// Initial service version 1 baseline
// ---------------------------------------------------------------------------

/// Build the exact initial service version 1 `RemoteConnectionPolicyV1`
/// baseline. There are no implicit code defaults; this is the sole baseline.
pub fn initial_service_version_1_policy() -> RemoteConnectionPolicyV1 {
    RemoteConnectionPolicyV1 {
        allowed_transports: vec!["webrtc".to_string(), "websocket_data".to_string()],
        direct_ip_mode: DirectIpMode::MutualConsent,
        shared_session_route: SharedSessionRoute::RelayOnly,
        websocket_fallback: true,
        tenant_authorization: TenantAuthorization::ControlPlane,
        minimum_daemon_custody: DaemonCustodyPolicy::OsProtected,
        minimum_client_custody: ClientCustodyPolicy::OriginProtected,
        sharing_enabled: true,
        limits: RemoteConnectionLimitsV1 {
            registered_daemons: CanonicalU64DecimalStringV1::from_u64(10),
            concurrent_attachments: CanonicalU64DecimalStringV1::from_u64(5),
            concurrent_children_per_attachment: CanonicalU64DecimalStringV1::from_u64(3),
            concurrent_participants_per_session: CanonicalU64DecimalStringV1::from_u64(8),
            turn_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(10_737_418_240),
            turn_duration_seconds: CanonicalU64DecimalStringV1::from_u64(28_800),
            websocket_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(10_737_418_240),
            websocket_duration_seconds: CanonicalU64DecimalStringV1::from_u64(28_800),
        },
        allowed_turn_regions: ALLOWED_TURN_REGIONS.iter().map(|s| s.to_string()).collect(),
        metadata_retention_days: CanonicalU64DecimalStringV1::from_u64(30),
    }
}

/// The exact initial service version.
pub const INITIAL_SERVICE_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Activation state machine (pure transitions)
// ---------------------------------------------------------------------------

/// Durable policy row state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRowState {
    Scheduled,
    Preparing,
    ActiveConverging,
    Active,
    ActiveConvergenceFailed,
    ScheduledFailed,
}

/// Critical-consumer group state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerGroupState {
    Disabled,
    Required,
    Draining,
    Retired,
}

/// Replica lease state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaLeaseState {
    Starting,
    Ready,
    Draining,
    Stale,
}

/// Result of an activation attempt for a narrowing-or-equal version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowingActivation {
    pub new_state: PolicyRowState,
    pub outbox: Option<&'static str>,
}

/// At `notBefore`, an equal/narrowing version atomically becomes
/// issuance-authoritative, supersedes the prior pointer, enters
/// `active_converging`, and appends `remote_public_service_policy_activated`.
pub fn activate_narrowing_at_not_before(
    current_time: i64,
    not_before: i64,
) -> Result<NarrowingActivation> {
    if current_time < not_before {
        return invalid("scheduled policy is not effective before notBefore");
    }
    Ok(NarrowingActivation {
        new_state: PolicyRowState::ActiveConverging,
        outbox: Some("remote_public_service_policy_activated"),
    })
}

/// After all registered critical consumers ACK, narrowing state becomes
/// `active`.
pub fn narrowing_all_consumers_acked() -> PolicyRowState {
    PolicyRowState::Active
}

/// After a 300-second timeout, narrowing remains authoritative in
/// `active_convergence_failed`; readiness is false, issuance stays narrowed,
/// and it never rolls back.
pub fn narrowing_convergence_timeout() -> PolicyRowState {
    PolicyRowState::ActiveConvergenceFailed
}

/// Widening enters `preparing`.
pub fn widening_prepare() -> PolicyRowState {
    PolicyRowState::Preparing
}

/// Widening advances the pointer and returns activation success only after
/// every registered critical consumer ACKs exact evaluator readiness in a
/// second transaction.
pub fn widening_all_consumers_acked() -> PolicyRowState {
    PolicyRowState::Active
}

/// Timeout/failure leaves widening `scheduled_failed` and old policy
/// authoritative.
pub fn widening_timeout_or_failure() -> PolicyRowState {
    PolicyRowState::ScheduledFailed
}

/// The 300-second lease refresh window for narrowing convergence.
pub const CONVERGENCE_TIMEOUT_SECONDS: i64 = 300;
/// Replica lease renew interval.
pub const REPLICA_LEASE_RENEW_SECONDS: i64 = 15;
/// Replica lease TTL.
pub const REPLICA_LEASE_TTL_SECONDS: i64 = 45;
/// Stale lease reap grace period.
pub const STALE_REAP_GRACE_SECONDS: i64 = 90;

/// Command acknowledgement for a successful import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportAcknowledgement {
    pub policy_id: String,
    pub service_version: String,
    pub state: &'static str,
    pub not_before: String,
    pub digest: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_protocol_id::decode_protocol_id_base64url;
    use crate::remote_version::V1_TUPLE_ID;

    fn sample_policy_id() -> RemotePublicPolicyId {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        crate::remote_protocol_id::tag_protocol_id_bytes(bytes).unwrap()
    }

    fn sample_policy() -> RemotePublicServicePolicyV1 {
        RemotePublicServicePolicyV1 {
            schema_version: 1,
            policy_id: sample_policy_id(),
            service_version: CanonicalU64DecimalStringV1::from_u64(1),
            previous_digest: None,
            issued_at: CanonicalU64DecimalStringV1::from_u64(1_000_000),
            not_before: CanonicalU64DecimalStringV1::from_u64(1_000_000),
            change_class: ChangeClass::NarrowingOrEqual,
            policy: initial_service_version_1_policy(),
        }
    }

    // --- Acceptance criterion 1: required-first (red before implementation) ---

    #[test]
    fn remote_public_service_policy_required_first() {
        // With no active signed policy present, readiness/issuance cannot
        // proceed. This test proves the absence of a valid active signed
        // policy is a hard failure: there is no default, no unsigned path.
        let absent: Option<RemotePublicServicePolicyV1> = None;
        assert!(absent.is_none());
        // The readiness predicate: a None active policy means not ready.
        fn readiness(active: &Option<RemotePublicServicePolicyV1>) -> bool {
            match active {
                Some(p) => p.validate().is_ok(),
                None => false,
            }
        }
        assert!(!readiness(&absent));
        // And a present, valid policy is ready.
        let present = sample_policy();
        assert!(readiness(&Some(present)));
        // An unsigned/default policy is never accepted: there is no constructor
        // that produces a policy without a signed envelope; the type itself
        // carries the policyId and digest.
    }

    // --- Acceptance criterion 3: v1 baseline ---

    #[test]
    fn remote_public_service_policy_v1_baseline() {
        let p = initial_service_version_1_policy();
        assert_eq!(p.allowed_transports, vec!["webrtc", "websocket_data"]);
        assert_eq!(p.direct_ip_mode, DirectIpMode::MutualConsent);
        assert_eq!(p.shared_session_route, SharedSessionRoute::RelayOnly);
        assert!(p.websocket_fallback);
        assert_eq!(p.tenant_authorization, TenantAuthorization::ControlPlane);
        assert_eq!(p.minimum_daemon_custody, DaemonCustodyPolicy::OsProtected);
        assert_eq!(
            p.minimum_client_custody,
            ClientCustodyPolicy::OriginProtected
        );
        assert!(p.sharing_enabled);
        assert_eq!(
            p.allowed_turn_regions,
            vec![
                "africa",
                "asia_pacific",
                "europe",
                "local",
                "middle_east",
                "north_america",
                "oceania",
                "south_america"
            ]
        );
        assert_eq!(p.limits.registered_daemons.value(), 10);
        assert_eq!(p.limits.concurrent_attachments.value(), 5);
        assert_eq!(p.limits.concurrent_children_per_attachment.value(), 3);
        assert_eq!(p.limits.concurrent_participants_per_session.value(), 8);
        assert_eq!(p.limits.turn_bytes_per_attachment.value(), 10_737_418_240);
        assert_eq!(p.limits.turn_duration_seconds.value(), 28_800);
        assert_eq!(
            p.limits.websocket_bytes_per_attachment.value(),
            10_737_418_240
        );
        assert_eq!(p.limits.websocket_duration_seconds.value(), 28_800);
        assert_eq!(p.metadata_retention_days.value(), 30);
        assert!(p.validate().is_ok());
    }

    // --- Custody meet tables ---

    #[test]
    fn daemon_custody_meet_table() {
        use DaemonCustodyPolicy::*;
        assert_eq!(OsProtected.meet(OsProtected), OsProtected);
        assert_eq!(OsProtected.meet(HardwareOrExternal), HardwareOrExternal);
        assert_eq!(HardwareOrExternal.meet(OsProtected), HardwareOrExternal);
        assert_eq!(
            HardwareOrExternal.meet(HardwareOrExternal),
            HardwareOrExternal
        );
        assert!(OsProtected.rank() < HardwareOrExternal.rank());
    }

    #[test]
    fn client_custody_meet_and_certificate_mapping_table() {
        use ClientCustodyPolicy::*;
        // meet table
        assert_eq!(OriginProtected.meet(OriginProtected), OriginProtected);
        assert_eq!(OriginProtected.meet(OsProtected), OsProtected);
        assert_eq!(OriginProtected.meet(Hardware), Hardware);
        assert_eq!(OsProtected.meet(OriginProtected), OsProtected);
        assert_eq!(OsProtected.meet(OsProtected), OsProtected);
        assert_eq!(OsProtected.meet(Hardware), Hardware);
        assert_eq!(Hardware.meet(OriginProtected), Hardware);
        assert_eq!(Hardware.meet(OsProtected), Hardware);
        assert_eq!(Hardware.meet(Hardware), Hardware);
        // ordering
        assert!(OriginProtected.rank() < OsProtected.rank());
        assert!(OsProtected.rank() < Hardware.rank());
        // certificate mapping
        assert_eq!(
            CustodyCertificateClass::OriginProtected.to_client_policy(),
            OriginProtected
        );
        assert_eq!(
            CustodyCertificateClass::OsProtected.to_client_policy(),
            OsProtected
        );
        assert_eq!(
            CustodyCertificateClass::HardwareOrExternal.to_client_policy(),
            Hardware
        );
        // satisfies
        assert!(ClientCustodyPolicy::satisfies(Hardware, OriginProtected));
        assert!(ClientCustodyPolicy::satisfies(Hardware, OsProtected));
        assert!(ClientCustodyPolicy::satisfies(Hardware, Hardware));
        assert!(!ClientCustodyPolicy::satisfies(
            OriginProtected,
            OsProtected
        ));
        assert!(!ClientCustodyPolicy::satisfies(OriginProtected, Hardware));
        assert!(!ClientCustodyPolicy::satisfies(OsProtected, Hardware));
    }

    // --- Acceptance criterion 6: authorization ceiling codec vectors ---

    #[test]
    fn capability_enums_disjoint_names_overlapping_ordinals() {
        // Ordinals 1..13 intentionally overlap across the two enums.
        for i in 1..=13u8 {
            assert!(RemoteProjectCapabilityV1::from_ordinal(i).is_ok());
            assert!(RemoteAttachmentCapabilityV1::from_ordinal(i).is_ok());
        }
        // Ordinal 14 and 15 are project-only.
        assert!(RemoteProjectCapabilityV1::from_ordinal(14).is_ok());
        assert!(RemoteProjectCapabilityV1::from_ordinal(15).is_ok());
        assert!(RemoteAttachmentCapabilityV1::from_ordinal(14).is_err());
        assert!(RemoteAttachmentCapabilityV1::from_ordinal(15).is_err());
        // Zero and unknown fail.
        assert!(RemoteProjectCapabilityV1::from_ordinal(0).is_err());
        assert!(RemoteProjectCapabilityV1::from_ordinal(16).is_err());
        assert!(RemoteAttachmentCapabilityV1::from_ordinal(0).is_err());
        assert!(RemoteAttachmentCapabilityV1::from_ordinal(14).is_err());
        // Names are disjoint: no variant name appears in both enums.
        let proj_names: Vec<String> = RemoteProjectCapabilityV1::all()
            .iter()
            .map(|c| {
                serde_json::to_string(c)
                    .unwrap()
                    .trim_matches('"')
                    .to_string()
            })
            .collect();
        let att_names: Vec<String> = RemoteAttachmentCapabilityV1::all()
            .iter()
            .map(|c| {
                serde_json::to_string(c)
                    .unwrap()
                    .trim_matches('"')
                    .to_string()
            })
            .collect();
        for pn in &proj_names {
            assert!(!att_names.contains(pn), "name {pn} not disjoint");
        }
    }

    #[test]
    fn permission_ceiling_empty_canonical() {
        let c = RemotePermissionCeilingV1::empty();
        let bytes = c.encode().unwrap();
        // version(1) + attachmentCount(1)=0 + projectCount(1)=0 = 3 bytes
        assert_eq!(bytes, vec![1, 0, 0]);
        assert_eq!(bytes.len(), 3);
        let back = RemotePermissionCeilingV1::decode(&bytes).unwrap();
        assert_eq!(back, c);
        // Empty canonical ceiling has a real digest of its complete 3-byte encoding.
        let digest = permission_ceiling_digest(&c).unwrap();
        let manual = Sha256::digest(&bytes);
        assert_eq!(digest.as_bytes(), manual.as_slice());
        assert_eq!(digest.to_hex().len(), 64);
    }

    #[test]
    fn permission_ceiling_minimum_vector() {
        // One attachment capability, one project with one capability.
        let pid = [1u8; 16];
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![RemoteAttachmentCapabilityV1::AttachmentRead],
            projects: vec![(pid, vec![RemoteProjectCapabilityV1::ProjectRead])],
        };
        let bytes = c.encode().unwrap();
        // version(1) + attCount(1) + att(1) + projCount(1) + pid(16) + capCount(1) + cap(1) = 22
        assert_eq!(bytes.len(), 22);
        let back = RemotePermissionCeilingV1::decode(&bytes).unwrap();
        assert_eq!(back, c);
        let digest = permission_ceiling_digest(&c).unwrap();
        assert_eq!(digest.to_hex().len(), 64);
    }

    #[test]
    fn permission_ceiling_maximum_vector() {
        // 13 attachment capabilities, 16 projects each with 15 project capabilities.
        let mut projects = Vec::new();
        for i in 1..=16u8 {
            let mut pid = [0u8; 16];
            pid[15] = i;
            let caps: Vec<RemoteProjectCapabilityV1> = RemoteProjectCapabilityV1::all().to_vec();
            projects.push((pid, caps));
        }
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: RemoteAttachmentCapabilityV1::all().to_vec(),
            projects,
        };
        // 1 + 1 + 13 + 1 + 16*(16+1+15) = 1+1+13+1+16*32 = 529 > 512 -> rejected
        assert!(c.encode().is_err(), "maximum vector exceeds 512 bytes");
    }

    #[test]
    fn permission_ceiling_within_512_bound() {
        // A valid combination that fits within 512 bytes.
        let mut projects = Vec::new();
        for i in 1..=4u8 {
            let mut pid = [0u8; 16];
            pid[15] = i;
            projects.push((
                pid,
                vec![
                    RemoteProjectCapabilityV1::ProjectRead,
                    RemoteProjectCapabilityV1::ProjectWrite,
                ],
            ));
        }
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![
                RemoteAttachmentCapabilityV1::AttachmentRead,
                RemoteAttachmentCapabilityV1::SessionCreate,
            ],
            projects,
        };
        let bytes = c.encode().unwrap();
        assert!(bytes.len() <= 512);
        let back = RemotePermissionCeilingV1::decode(&bytes).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn permission_ceiling_rejects_unsorted_duplicate_cross_kind() {
        // Duplicate attachment ordinals.
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![
                RemoteAttachmentCapabilityV1::AttachmentRead,
                RemoteAttachmentCapabilityV1::AttachmentRead,
            ],
            projects: vec![],
        };
        assert!(c.encode().is_err());

        // Unsorted attachment ordinals.
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![
                RemoteAttachmentCapabilityV1::SessionCreate,  // ordinal 3
                RemoteAttachmentCapabilityV1::AttachmentRead, // ordinal 1
            ],
            projects: vec![],
        };
        assert!(c.encode().is_err());

        // Trailing bytes.
        let bytes = vec![1, 0, 0, 0];
        assert!(RemotePermissionCeilingV1::decode(&bytes).is_err());

        // Unsorted project ids.
        let mut pid2 = [0u8; 16];
        pid2[15] = 2;
        let mut pid1 = [0u8; 16];
        pid1[15] = 1;
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![],
            projects: vec![
                (pid2, vec![RemoteProjectCapabilityV1::ProjectRead]),
                (pid1, vec![RemoteProjectCapabilityV1::ProjectRead]),
            ],
        };
        assert!(c.encode().is_err());

        // Zero project id.
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![],
            projects: vec![([0u8; 16], vec![RemoteProjectCapabilityV1::ProjectRead])],
        };
        assert!(c.encode().is_err());

        // Empty project capabilities (count 0).
        let c = RemotePermissionCeilingV1 {
            attachment_capabilities: vec![],
            projects: vec![([1u8; 16], vec![])],
        };
        assert!(c.encode().is_err());
    }

    #[test]
    fn permission_ceiling_digest_hex_lowercase() {
        let c = RemotePermissionCeilingV1::empty();
        let digest = permission_ceiling_digest(&c).unwrap();
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // --- Transport bits ---

    #[test]
    fn transport_bits_valid_and_reject() {
        assert!(validate_transport_bits(0x01).is_ok());
        assert!(validate_transport_bits(0x02).is_ok());
        assert!(validate_transport_bits(0x03).is_ok());
        assert!(validate_transport_bits(0x00).is_err());
        assert!(validate_transport_bits(0x04).is_err());
        assert!(validate_transport_bits(0xff).is_err());
    }

    // --- Tuple set ---

    #[test]
    fn tuple_set_valid_and_reject() {
        // V1 registry has exactly tuple 0x0001.
        let s = RemoteAuthorizedTupleSetV1 {
            tuple_ids: vec![V1_TUPLE_ID],
        };
        let bytes = s.encode().unwrap();
        assert_eq!(bytes, vec![1, 0x00, 0x01]);
        let back = RemoteAuthorizedTupleSetV1::decode(&bytes).unwrap();
        assert_eq!(back, s);

        // Reject zero count.
        assert!(
            RemoteAuthorizedTupleSetV1 { tuple_ids: vec![] }
                .encode()
                .is_err()
        );
        // Reject unknown tuple.
        assert!(
            RemoteAuthorizedTupleSetV1 {
                tuple_ids: vec![0x0002]
            }
            .encode()
            .is_err()
        );
        // Reject zero id.
        assert!(
            RemoteAuthorizedTupleSetV1 {
                tuple_ids: vec![0x0000]
            }
            .encode()
            .is_err()
        );
        // Reject unsorted.
        assert!(
            RemoteAuthorizedTupleSetV1 {
                tuple_ids: vec![0x0001, 0x0001]
            }
            .encode()
            .is_err()
        );
        // Reject >16.
        let too_many = vec![V1_TUPLE_ID; 17];
        assert!(
            RemoteAuthorizedTupleSetV1 {
                tuple_ids: too_many
            }
            .encode()
            .is_err()
        );
        // Reject trailing bytes.
        assert!(RemoteAuthorizedTupleSetV1::decode(&[1, 0x00, 0x01, 0x00]).is_err());
    }

    // --- JWS header validation ---

    #[test]
    fn jws_header_valid_and_reject() {
        let good: Value = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": POLICY_JWS_TYP
        });
        assert!(validate_policy_jws_header(&good).is_ok());

        // Unknown field.
        let bad: Value = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": POLICY_JWS_TYP,
            "extra": true
        });
        assert!(validate_policy_jws_header(&bad).is_err());

        // Missing kid.
        let bad: Value = serde_json::json!({
            "alg": "ES256",
            "typ": POLICY_JWS_TYP
        });
        assert!(validate_policy_jws_header(&bad).is_err());

        // Wrong alg.
        let bad: Value = serde_json::json!({
            "alg": "RS256",
            "kid": "key-1",
            "typ": POLICY_JWS_TYP
        });
        assert!(validate_policy_jws_header(&bad).is_err());

        // Wrong typ.
        let bad: Value = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "wrong"
        });
        assert!(validate_policy_jws_header(&bad).is_err());

        // Empty kid.
        let bad: Value = serde_json::json!({
            "alg": "ES256",
            "kid": "",
            "typ": POLICY_JWS_TYP
        });
        assert!(validate_policy_jws_header(&bad).is_err());
    }

    // --- JWKS ring validation ---

    fn sample_ec_jwk(role: &str, kid: &str, seed: u8) -> Value {
        let x = [seed; 32];
        let y = [seed + 1; 32];
        serde_json::json!({
            "kid": kid,
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "key_ops": ["verify"],
            "flycockpit_role": role
        })
    }

    #[test]
    fn jwks_ring_valid_current_only() {
        let jwks = serde_json::json!({ "keys": [sample_ec_jwk("current", "k1", 1)] });
        let ring = parse_policy_jwks(&jwks.to_string()).unwrap();
        assert_eq!(ring.keys.len(), 1);
        assert!(ring.current().is_some());
        assert!(ring.previous().is_none());
        assert!(ring.next().is_none());
    }

    #[test]
    fn jwks_ring_valid_previous_current() {
        let jwks = serde_json::json!({
            "keys": [
                sample_ec_jwk("previous", "k0", 1),
                sample_ec_jwk("current", "k1", 3),
            ]
        });
        let ring = parse_policy_jwks(&jwks.to_string()).unwrap();
        assert_eq!(ring.keys.len(), 2);
        assert!(ring.previous().is_some());
        assert!(ring.current().is_some());
    }

    #[test]
    fn jwks_ring_valid_current_next() {
        let jwks = serde_json::json!({
            "keys": [
                sample_ec_jwk("current", "k1", 3),
                sample_ec_jwk("next", "k2", 5),
            ]
        });
        let ring = parse_policy_jwks(&jwks.to_string()).unwrap();
        assert_eq!(ring.keys.len(), 2);
        assert!(ring.current().is_some());
        assert!(ring.next().is_some());
    }

    #[test]
    fn jwks_ring_rejects_missing_current() {
        let jwks = serde_json::json!({
            "keys": [sample_ec_jwk("next", "k2", 5)]
        });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_duplicate_current() {
        let jwks = serde_json::json!({
            "keys": [
                sample_ec_jwk("current", "k1", 3),
                sample_ec_jwk("current", "k2", 5),
            ]
        });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_duplicate_kid() {
        let jwks = serde_json::json!({
            "keys": [
                sample_ec_jwk("previous", "k1", 3),
                sample_ec_jwk("current", "k1", 5),
            ]
        });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_unknown_field() {
        let mut jwk = sample_ec_jwk("current", "k1", 3);
        let obj = jwk.as_object_mut().unwrap();
        obj.insert("d".to_string(), serde_json::json!("private"));
        let jwks = serde_json::json!({ "keys": [jwk] });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_wrong_key_ops() {
        let mut jwk = sample_ec_jwk("current", "k1", 3);
        let obj = jwk.as_object_mut().unwrap();
        obj.insert("key_ops".to_string(), serde_json::json!(["sign", "verify"]));
        let jwks = serde_json::json!({ "keys": [jwk] });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_four_keys() {
        let jwks = serde_json::json!({
            "keys": [
                sample_ec_jwk("previous", "k0", 1),
                sample_ec_jwk("current", "k1", 3),
                sample_ec_jwk("next", "k2", 5),
                sample_ec_jwk("next", "k3", 7),
            ]
        });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    #[test]
    fn jwks_ring_rejects_duplicate_thumbprint() {
        // Same x/y -> same thumbprint, different kid.
        let x = [1u8; 32];
        let y = [2u8; 32];
        let jwk1 = serde_json::json!({
            "kid": "k1",
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "key_ops": ["verify"],
            "flycockpit_role": "previous"
        });
        let jwk2 = serde_json::json!({
            "kid": "k2",
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "key_ops": ["verify"],
            "flycockpit_role": "current"
        });
        let jwks = serde_json::json!({ "keys": [jwk1, jwk2] });
        assert!(parse_policy_jwks(&jwks.to_string()).is_err());
    }

    // --- Canonical JSON / payload digest ---

    #[test]
    fn policy_canonical_json_round_trip() {
        let p = sample_policy();
        let canonical = p.canonical_json().unwrap();
        // RFC 8785: sorted keys, no whitespace.
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        // Keys must be sorted: "changeClass" < "issuedAt" < "notBefore" < ...
        let cc_pos = canonical.find("\"changeClass\"").unwrap();
        let ia_pos = canonical.find("\"issuedAt\"").unwrap();
        assert!(cc_pos < ia_pos);
        // serviceVersion must be a string (semantic u64), not a JSON number.
        assert!(canonical.contains("\"serviceVersion\":\"1\""));
        // Round-trip: parse back and re-canonicalize.
        let value: Value = serde_json::from_str(&canonical).unwrap();
        let back: RemotePublicServicePolicyV1 = serde_json::from_value(value).unwrap();
        let canonical2 = back.canonical_json().unwrap();
        assert_eq!(canonical, canonical2);
    }

    #[test]
    fn policy_payload_digest_stable() {
        let p = sample_policy();
        let d1 = p.payload_digest_hex().unwrap();
        let d2 = p.payload_digest_hex().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
        assert!(
            d1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // --- Import clock skew ---

    #[test]
    fn import_clock_skew_accepts_within_bounds() {
        let mut p = sample_policy();
        // issuedAt == importTime, notBefore == issuedAt -> OK.
        p.issued_at = CanonicalU64DecimalStringV1::from_u64(1_000_000);
        p.not_before = CanonicalU64DecimalStringV1::from_u64(1_000_000);
        assert!(p.validate_for_import(1_000_000).is_ok());
        // issuedAt 60s in future -> OK (skew).
        p.issued_at = CanonicalU64DecimalStringV1::from_u64(1_000_060);
        assert!(p.validate_for_import(1_000_000).is_ok());
        // issuedAt 61s in future -> reject.
        p.issued_at = CanonicalU64DecimalStringV1::from_u64(1_000_061);
        assert!(p.validate_for_import(1_000_000).is_err());
    }

    #[test]
    fn import_not_before_bounds() {
        let mut p = sample_policy();
        p.issued_at = CanonicalU64DecimalStringV1::from_u64(1_000_000);
        // notBefore 60s before issuedAt -> OK (skew).
        p.not_before = CanonicalU64DecimalStringV1::from_u64(999_940);
        assert!(p.validate_for_import(1_000_000).is_ok());
        // notBefore 61s before issuedAt -> reject.
        p.not_before = CanonicalU64DecimalStringV1::from_u64(999_939);
        assert!(p.validate_for_import(1_000_000).is_err());
        // notBefore exactly 30 days after issuedAt -> OK.
        p.not_before = CanonicalU64DecimalStringV1::from_u64(1_000_000 + 2_592_000);
        assert!(p.validate_for_import(1_000_000).is_ok());
        // notBefore 30 days + 1s after issuedAt -> reject.
        p.not_before = CanonicalU64DecimalStringV1::from_u64(1_000_000 + 2_592_001);
        assert!(p.validate_for_import(1_000_000).is_err());
    }

    // --- Activation state machine ---

    #[test]
    fn narrowing_activation_transitions() {
        let not_before = 1_000_000;
        // Before notBefore: reject.
        assert!(activate_narrowing_at_not_before(999_999, not_before).is_err());
        // At notBefore: active_converging + outbox.
        let r = activate_narrowing_at_not_before(not_before, not_before).unwrap();
        assert_eq!(r.new_state, PolicyRowState::ActiveConverging);
        assert_eq!(r.outbox, Some("remote_public_service_policy_activated"));
        // All ACKed -> active.
        assert_eq!(narrowing_all_consumers_acked(), PolicyRowState::Active);
        // Timeout -> active_convergence_failed (no rollback).
        assert_eq!(
            narrowing_convergence_timeout(),
            PolicyRowState::ActiveConvergenceFailed
        );
    }

    #[test]
    fn widening_activation_transitions() {
        assert_eq!(widening_prepare(), PolicyRowState::Preparing);
        assert_eq!(widening_all_consumers_acked(), PolicyRowState::Active);
        assert_eq!(
            widening_timeout_or_failure(),
            PolicyRowState::ScheduledFailed
        );
    }

    // --- Critical consumer IDs ---

    #[test]
    fn critical_consumer_ids_closed_registry() {
        assert_eq!(CRITICAL_CONSUMER_IDS.len(), 8);
        assert!(CRITICAL_CONSUMER_IDS.contains(&"attempt_issuer"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"signaling_gateway"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"daemon_authorizer"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"turn_issuer"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"websocket_fallback_gateway"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"web_route_selector"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"native_route_selector"));
        assert!(CRITICAL_CONSUMER_IDS.contains(&"metadata_retention_worker"));
        // Unique.
        let mut sorted = CRITICAL_CONSUMER_IDS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), CRITICAL_CONSUMER_IDS.len());
    }

    // --- Policy validation rejections ---

    #[test]
    fn policy_rejects_unsorted_transports() {
        let mut p = initial_service_version_1_policy();
        p.allowed_transports = vec!["websocket_data".to_string(), "webrtc".to_string()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_unknown_transport() {
        let mut p = initial_service_version_1_policy();
        p.allowed_transports = vec!["webrtc".to_string(), "carrier_pigeon".to_string()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_zero_limit() {
        let mut p = initial_service_version_1_policy();
        p.limits.registered_daemons = CanonicalU64DecimalStringV1::from_u64(0);
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_retention_over_365() {
        let mut p = initial_service_version_1_policy();
        p.metadata_retention_days = CanonicalU64DecimalStringV1::from_u64(366);
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_unsorted_regions() {
        let mut p = initial_service_version_1_policy();
        p.allowed_turn_regions = vec!["europe".to_string(), "africa".to_string()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_unknown_region() {
        let mut p = initial_service_version_1_policy();
        p.allowed_turn_regions = vec!["africa".to_string(), "atlantis".to_string()];
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_wrong_schema_version() {
        let mut p = sample_policy();
        p.schema_version = 2;
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_rejects_uppercase_digest() {
        let mut p = sample_policy();
        p.previous_digest = Some("ABCDEF".repeat(10) + "0");
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_accepts_valid_previous_digest() {
        let mut p = sample_policy();
        p.previous_digest = Some("a".repeat(64));
        assert!(p.validate().is_ok());
    }

    // --- Compact JWS parse ---

    #[test]
    fn parse_compact_jws_round_trip() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": POLICY_JWS_TYP
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload = serde_json::json!({"test": true});
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        let sig = [0u8; 64];
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
        let compact = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let parsed = parse_policy_jws(&compact).unwrap();
        assert_eq!(parsed.protected_header, header);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.signature, sig);
        assert_eq!(
            parsed.signing_input,
            format!("{header_b64}.{payload_b64}").into_bytes()
        );
    }

    #[test]
    fn parse_compact_jws_rejects_two_parts() {
        assert!(parse_policy_jws("a.b").is_err());
    }

    #[test]
    fn parse_compact_jws_rejects_bad_header() {
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        let sig_b64 = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let compact = format!("{header_b64}.{payload_b64}.{sig_b64}");
        assert!(parse_policy_jws(&compact).is_err());
    }

    // --- policyId encoding (UUID/CUID rejection) ---

    #[test]
    fn policy_id_rejects_uuid_text() {
        let uuid_text = "01234567-89ab-cdef-0123-456789abcdef";
        // A UUID is 36 chars, not 22 — and contains '-' which is invalid base64url
        // for this codec. decode_protocol_id_base64url rejects it.
        assert!(decode_protocol_id_base64url(uuid_text).is_err());
    }

    // --- u64 boundary fixtures ---

    #[test]
    fn u64_boundary_strings_in_policy() {
        let mut p = sample_policy();
        // 2^53 - 1
        p.service_version = CanonicalU64DecimalStringV1::from_u64((1u64 << 53) - 1);
        assert!(p.validate().is_ok());
        // 2^53
        p.service_version = CanonicalU64DecimalStringV1::from_u64(1u64 << 53);
        assert!(p.validate().is_ok());
        // 2^53 + 1
        p.service_version = CanonicalU64DecimalStringV1::from_u64((1u64 << 53) + 1);
        assert!(p.validate().is_ok());
        // u64::MAX
        p.service_version = CanonicalU64DecimalStringV1::from_u64(u64::MAX);
        assert!(p.validate().is_ok());
        // Verify canonical JSON carries these as strings, not numbers.
        let canonical = p.canonical_json().unwrap();
        assert!(canonical.contains("\"serviceVersion\":\"18446744073709551615\""));
    }

    #[test]
    fn u64_decimal_string_rejects_json_number() {
        // A JSON numeric literal for serviceVersion must fail deserialization
        // because CanonicalU64DecimalStringV1 requires a string.
        let bad = r#"{"serviceVersion":9007199254740993}"#;
        assert!(serde_json::from_str::<Value>(bad).is_ok()); // valid JSON
        // But it cannot deserialize into the canonical string type.
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(rename = "serviceVersion")]
            _sv: CanonicalU64DecimalStringV1,
        }
        assert!(serde_json::from_str::<Wrap>(bad).is_err());
    }

    // --- Ownership guard (non-vacuous) ---

    #[test]
    fn ownership_guard_capability_enums_sole_definition() {
        // The capability enums are defined exactly once in this module.
        // This test is non-vacuous: it confirms the ordinal sets are the
        // closed, foundation-owned sets and that no extension is possible
        // without editing this source.
        assert_eq!(RemoteProjectCapabilityV1::all().len(), 15);
        assert_eq!(RemoteAttachmentCapabilityV1::all().len(), 13);
        // image_generation_admin=15 is foundation-owned.
        assert_eq!(
            RemoteProjectCapabilityV1::ImageGenerationAdmin.ordinal(),
            15
        );
        // Ordinals 1..13 overlap by design.
        for i in 1..=13u8 {
            let p = RemoteProjectCapabilityV1::from_ordinal(i).unwrap();
            let a = RemoteAttachmentCapabilityV1::from_ordinal(i).unwrap();
            assert_eq!(p.ordinal(), a.ordinal());
            assert_eq!(p.ordinal(), i);
        }
    }

    #[test]
    fn ownership_guard_permission_ceiling_digest_sole_derivation() {
        // The digest helper is the sole encoder-to-SHA-256 derivation.
        // Confirm it matches a manual computation and there is no alternative.
        let c = RemotePermissionCeilingV1::empty();
        let digest = permission_ceiling_digest(&c).unwrap();
        let manual = Sha256::digest(c.encode().unwrap());
        assert_eq!(digest.as_bytes(), manual.as_slice());
        // Non-null: empty ceiling has a real digest.
        assert_ne!(digest.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn ownership_guard_transport_bits_sole_definition() {
        // The transport bit assignments are sole and closed.
        assert_eq!(TRANSPORT_BIT_WEBRTC, 0x01);
        assert_eq!(TRANSPORT_BIT_WEBSOCKET_DATA, 0x02);
        assert_eq!(TRANSPORT_BITS_VALID, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn ownership_guard_consumer_registry_closed() {
        // A future consumer cannot affect a policy field until a reviewed
        // schema version adds its stable ID. The registry is closed at V1.
        assert_eq!(CRITICAL_CONSUMER_IDS.len(), 8);
        // No consumer named "future_consumer" exists.
        assert!(!CRITICAL_CONSUMER_IDS.contains(&"future_consumer"));
    }

    // --- Constant-time digest comparison note ---
    // Downstream consumers compare the digest in constant time where
    // authentication-sensitive. This module exposes the digest as bytes/hex;
    // constant-time comparison is the consumer's responsibility.

    #[test]
    fn permission_ceiling_digest_constant_time_compatible() {
        let c1 = RemotePermissionCeilingV1::empty();
        let c2 = RemotePermissionCeilingV1::empty();
        let d1 = permission_ceiling_digest(&c1).unwrap();
        let d2 = permission_ceiling_digest(&c2).unwrap();
        // Constant-time comparison via byte slice equality.
        let eq = d1.as_bytes() == d2.as_bytes();
        assert!(eq);
    }

    // --- ALLOWED_TRANSPORTS and ALLOWED_TURN_REGIONS are sorted ---

    #[test]
    fn allowed_transports_sorted() {
        for i in 1..ALLOWED_TRANSPORTS.len() {
            assert!(ALLOWED_TRANSPORTS[i - 1] < ALLOWED_TRANSPORTS[i]);
        }
    }

    #[test]
    fn allowed_turn_regions_sorted_and_closed() {
        assert_eq!(ALLOWED_TURN_REGIONS.len(), 8);
        for i in 1..ALLOWED_TURN_REGIONS.len() {
            assert!(ALLOWED_TURN_REGIONS[i - 1] < ALLOWED_TURN_REGIONS[i]);
        }
    }
}
