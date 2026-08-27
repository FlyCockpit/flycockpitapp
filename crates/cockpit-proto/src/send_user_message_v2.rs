//! Canonical, transport-neutral user-message application parameters.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use uuid::Uuid;

pub const FCM2_MAGIC: [u8; 4] = *b"FCM2";
pub const FCM2_SCHEMA_VERSION: u8 = 2;
/// Closed outer allocation bound for an FCM2 envelope.  This deliberately
/// leaves 128 KiB of prerelease headroom above the largest encoding accepted
/// by the current field limits; it is not a field-level budget.
pub const MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES: usize = 17_439_564;
pub const MAX_MESSAGE_TEXT_BYTES: usize = 8_388_608;
pub const MAX_MESSAGE_TEXT_SCALARS: usize = 8_388_608;
/// The exact largest encoding admitted by the current FCM2 field layout.
pub const MAX_CURRENT_FCM2_ENCODING_BYTES: usize = 17_311_565;
pub const MAX_TAG_EXPANSIONS: usize = 64;
pub const MAX_MESSAGE_ATTACHMENTS: usize = 16;
const MESSAGE_DIGEST_DOMAIN: &[u8] = b"flycockpit-send-user-message-v2\0";
const ATTACHMENT_SET_DIGEST_DOMAIN: &[u8] = b"flycockpit-message-attachment-set-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageAttachmentKind {
    Image,
    Audio,
    Video,
}

impl MessageAttachmentKind {
    fn code(self) -> u8 {
        match self {
            Self::Image => 1,
            Self::Audio => 2,
            Self::Video => 3,
        }
    }
    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Image),
            2 => Ok(Self::Audio),
            3 => Ok(Self::Video),
            _ => bail!("unknown attachment kind"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAttachmentIdentity {
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    /// Full SHA-256, represented as bytes internally (never a path or upload id).
    pub checksum: [u8; 32],
    pub kind: MessageAttachmentKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageTagExpansion {
    pub tool: String,
    pub path: String,
    pub detail: String,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendUserMessageV2 {
    pub client_submission_id: Uuid,
    /// Required provenance, bound into canonical bytes and replay identity.
    pub origin: crate::UserMessageOrigin,
    pub text: String,
    pub display_text: Option<String>,
    pub tag_expansions: Vec<MessageTagExpansion>,
    pub forced_skill: Option<String>,
    pub attachments: Vec<MessageAttachmentIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSendUserMessageV2 {
    pub session_id: Uuid,
    pub canonical_project_digest: [u8; 32],
    pub model_config_generation: u64,
    pub canonical_model_digest: [u8; 32],
    pub request: SendUserMessageV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalOwnerDirectSendUserMessageV2 {
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub session_locator: String,
    pub request: SendUserMessageV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedRemoteOperationEnvelopeV2 {
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub session_locator: String,
    pub request: SendUserMessageV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMessageIngress {
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub session_locator: String,
    pub command: SendUserMessageV2,
    pub provenance: MessageIngressProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageIngressProvenance {
    LocalOwner,
    AuthenticatedRemote {
        actor_id: [u8; 16],
        actor_generation: u64,
    },
}

fn validate_ingress(
    request_id: Uuid,
    operation_id: Uuid,
    session_locator: String,
    command: SendUserMessageV2,
    provenance: MessageIngressProvenance,
) -> Result<ValidatedMessageIngress> {
    ensure!(
        request_id.get_version_num() == 7 && request_id.get_variant() == uuid::Variant::RFC4122,
        "request_id must be RFC UUIDv7"
    );
    ensure!(
        operation_id.get_version_num() == 7 && operation_id.get_variant() == uuid::Variant::RFC4122,
        "operation_id must be RFC UUIDv7"
    );
    ensure!(!session_locator.is_empty(), "empty session locator");
    ensure!(
        request_id != operation_id
            && request_id != command.client_submission_id
            && operation_id != command.client_submission_id,
        "request, operation, and submission identities must be pairwise distinct"
    );
    if let MessageIngressProvenance::AuthenticatedRemote {
        actor_id,
        actor_generation,
    } = provenance
    {
        ensure!(
            actor_id != [0; 16] && actor_generation > 0,
            "invalid remote actor binding"
        );
    }
    Ok(ValidatedMessageIngress {
        request_id,
        operation_id,
        session_locator,
        command,
        provenance,
    })
}

impl LocalOwnerDirectSendUserMessageV2 {
    pub fn into_validated(self) -> Result<ValidatedMessageIngress> {
        validate_ingress(
            self.request_id,
            self.operation_id,
            self.session_locator,
            self.request,
            MessageIngressProvenance::LocalOwner,
        )
    }
}

impl AuthenticatedRemoteOperationEnvelopeV2 {
    pub fn into_validated(
        self,
        actor_id: [u8; 16],
        actor_generation: u64,
    ) -> Result<ValidatedMessageIngress> {
        validate_ingress(
            self.request_id,
            self.operation_id,
            self.session_locator,
            self.request,
            MessageIngressProvenance::AuthenticatedRemote {
                actor_id,
                actor_generation,
            },
        )
    }
}

pub fn has_message_text(text: &str) -> bool {
    text.chars().any(|c| {
        !matches!(c,
        '\u{0009}'..='\u{000D}' | '\u{0020}' | '\u{0085}' | '\u{00A0}' |
        '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' |
        '\u{202F}' | '\u{205F}' | '\u{3000}')
    })
}

/// Checks the outer allocation bound before a decoder allocates any field.
pub fn validate_fcm2_length(length: usize) -> Result<()> {
    ensure!(
        length <= MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
        "FCM2 exceeds maximum size"
    );
    Ok(())
}

fn validate_text(value: &str, name: &str) -> Result<()> {
    ensure!(
        value.len() <= MAX_MESSAGE_TEXT_BYTES,
        "{name} exceeds byte limit"
    );
    ensure!(
        value.chars().count() <= MAX_MESSAGE_TEXT_SCALARS,
        "{name} exceeds scalar limit"
    );
    Ok(())
}

impl CanonicalSendUserMessageV2 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.request.client_submission_id.is_nil(),
            "invalid nonnil UUID"
        );
        ensure!(!self.session_id.is_nil(), "invalid nonnil UUID");
        ensure!(
            self.canonical_project_digest.iter().any(|&b| b != 0),
            "zero project digest"
        );
        ensure!(
            self.canonical_model_digest.iter().any(|&b| b != 0),
            "zero model digest"
        );
        validate_text(&self.request.text, "text")?;
        if let Some(value) = &self.request.display_text {
            validate_text(value, "display text")?;
        }
        ensure!(
            has_message_text(&self.request.text) || !self.request.attachments.is_empty(),
            "message has no content"
        );
        ensure!(
            self.request.tag_expansions.len() <= MAX_TAG_EXPANSIONS,
            "too many tags"
        );
        for tag in &self.request.tag_expansions {
            ensure!(!tag.tool.is_empty(), "fcm2_empty_tag_tool");
            ensure!(tag.tool.len() <= 128, "fcm2_tag_tool_too_long");
            ensure!(tag.path.len() <= 4096, "fcm2_tag_path_too_long");
            ensure!(tag.detail.len() <= 4096, "fcm2_tag_detail_too_long");
        }
        if let Some(skill) = &self.request.forced_skill {
            ensure!(!skill.is_empty(), "fcm2_empty_forced_skill");
            ensure!(skill.len() <= 128, "fcm2_forced_skill_too_long");
            ensure!(
                skill
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
                "fcm2_invalid_forced_skill"
            );
        }
        ensure!(
            self.request.attachments.len() <= MAX_MESSAGE_ATTACHMENTS,
            "too many attachments"
        );
        let mut ids = HashSet::with_capacity(self.request.attachments.len());
        for item in &self.request.attachments {
            ensure!(!item.attachment_id.is_nil(), "invalid nonnil UUID");
            ensure!(item.attachment_version > 0, "invalid attachment version");
            ensure!(ids.insert(item.attachment_id), "duplicate attachment id");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&FCM2_MAGIC);
        out.push(FCM2_SCHEMA_VERSION);
        out.extend_from_slice(self.request.client_submission_id.as_bytes());
        out.push(self.request.origin.fcm2_code());
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(&self.canonical_project_digest);
        out.extend_from_slice(&self.model_config_generation.to_be_bytes());
        out.extend_from_slice(&self.canonical_model_digest);
        put_u32_text(&mut out, &self.request.text)?;
        put_optional_u32_text(&mut out, self.request.display_text.as_deref())?;
        out.extend_from_slice(&(self.request.tag_expansions.len() as u16).to_be_bytes());
        for tag in &self.request.tag_expansions {
            put_u16_text(&mut out, &tag.tool)?;
            put_u32_text(&mut out, &tag.path)?;
            put_u32_text(&mut out, &tag.detail)?;
            out.push(u8::from(tag.ok));
        }
        match self.request.forced_skill.as_deref() {
            Some(v) => {
                out.push(1);
                put_u16_text(&mut out, v)?;
            }
            None => out.push(0),
        }
        out.push(self.request.attachments.len() as u8);
        for item in &self.request.attachments {
            out.extend_from_slice(item.attachment_id.as_bytes());
            out.extend_from_slice(&item.attachment_version.to_be_bytes());
            out.extend_from_slice(&item.checksum);
            out.push(item.kind.code());
        }
        ensure!(
            out.len() <= MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
            "FCM2 exceeds maximum size"
        );
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        validate_fcm2_length(bytes.len())?;
        let mut r = Reader { bytes, at: 0 };
        ensure!(r.take(4)? == FCM2_MAGIC, "invalid FCM2 header");
        ensure!(r.u8()? == FCM2_SCHEMA_VERSION, "invalid FCM2 header");
        let client_submission_id = r.uuid()?;
        let origin = crate::UserMessageOrigin::from_fcm2_code(r.u8()?)?;
        let session_id = r.uuid()?;
        let canonical_project_digest = r.array()?;
        let model_config_generation = r.u64()?;
        let canonical_model_digest = r.array()?;
        let text = r.u32_text()?;
        let display_text = r.optional_u32_text()?;
        let tag_count = r.u16()? as usize;
        ensure!(tag_count <= MAX_TAG_EXPANSIONS, "too many tags");
        let mut tag_expansions = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            tag_expansions.push(MessageTagExpansion {
                tool: r.u16_text()?,
                path: r.u32_text()?,
                detail: r.u32_text()?,
                ok: r.bool()?,
            });
        }
        let forced_skill = match r.u8()? {
            0 => None,
            1 => Some(r.u16_text()?),
            _ => bail!("invalid forced skill presence"),
        };
        let attachment_count = r.u8()? as usize;
        ensure!(
            attachment_count <= MAX_MESSAGE_ATTACHMENTS,
            "too many attachments"
        );
        let mut attachments = Vec::with_capacity(attachment_count);
        for _ in 0..attachment_count {
            attachments.push(MessageAttachmentIdentity {
                attachment_id: r.uuid()?,
                attachment_version: r.u64()?,
                checksum: r.array()?,
                kind: MessageAttachmentKind::from_code(r.u8()?)?,
            });
        }
        ensure!(r.at == bytes.len(), "trailing FCM2 bytes");
        let value = Self {
            session_id,
            canonical_project_digest,
            model_config_generation,
            canonical_model_digest,
            request: SendUserMessageV2 {
                client_submission_id,
                origin,
                text,
                display_text,
                tag_expansions,
                forced_skill,
                attachments,
            },
        };
        value.validate()?;
        Ok(value)
    }

    pub fn message_request_digest(&self) -> Result<[u8; 32]> {
        let bytes = self.encode()?;
        Ok(digest_parts(&[MESSAGE_DIGEST_DOMAIN, &bytes]))
    }
    pub fn attachment_set_digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(1 + self.request.attachments.len() * 57);
        bytes.push(self.request.attachments.len() as u8);
        for a in &self.request.attachments {
            bytes.extend_from_slice(a.attachment_id.as_bytes());
            bytes.extend_from_slice(&a.attachment_version.to_be_bytes());
            bytes.extend_from_slice(&a.checksum);
            bytes.push(a.kind.code());
        }
        Ok(digest_parts(&[ATTACHMENT_SET_DIGEST_DOMAIN, &bytes]))
    }
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn put_u16_text(out: &mut Vec<u8>, v: &str) -> Result<()> {
    let n = u16::try_from(v.len()).context("string exceeds u16")?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(v.as_bytes());
    Ok(())
}
fn put_u32_text(out: &mut Vec<u8>, v: &str) -> Result<()> {
    let n = u32::try_from(v.len()).context("string exceeds u32")?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(v.as_bytes());
    Ok(())
}
fn put_optional_u32_text(out: &mut Vec<u8>, v: Option<&str>) -> Result<()> {
    match v {
        Some(v) => {
            out.push(1);
            put_u32_text(out, v)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).context("FCM2 length overflow")?;
        ensure!(end <= self.bytes.len(), "truncated FCM2");
        let v = &self.bytes[self.at..end];
        self.at = end;
        Ok(v)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => bail!("invalid boolean"),
        }
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
    fn uuid(&mut self) -> Result<Uuid> {
        Ok(Uuid::from_bytes(self.array()?))
    }
    fn text(&mut self, n: usize) -> Result<String> {
        String::from_utf8(self.take(n)?.to_vec()).context("invalid UTF-8")
    }
    fn u16_text(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        self.text(n)
    }
    fn u32_text(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        self.text(n)
    }
    fn optional_u32_text(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u32_text()?)),
            _ => bail!("invalid display presence"),
        }
    }
}
