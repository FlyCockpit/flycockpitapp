//! Capability and permission-ceiling vocabulary shared by local and remote clients.
//!
//! This module deliberately contains no signing, JWKS, transport, account, or
//! public-service policy machinery. It remains available in the default local
//! build for daemon authorization and image-generation admission.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum encoded size of a canonical permission ceiling.
pub const PERMISSION_CEILING_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityCeilingError {
    #[error("invalid permission ceiling: {0}")]
    Ceiling(String),
    #[error("invalid capability: {0}")]
    Capability(String),
}

type Result<T> = std::result::Result<T, CapabilityCeilingError>;
fn ceiling_err<T>(s: impl Into<String>) -> Result<T> {
    Err(CapabilityCeilingError::Ceiling(s.into()))
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
            _ => Err(CapabilityCeilingError::Capability(format!(
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
            _ => Err(CapabilityCeilingError::Capability(format!(
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


