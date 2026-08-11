//! Media-egress authorization for transcription.
//!
//! Central `AuthorizationRequest::MediaEgress` for purpose `transcription`,
//! bound to provider, selected model, credential fingerprint, origin,
//! resolved location, project, session, attachment checksum, exact media
//! interval, prompt bytes, ordered keywords, ordered languages,
//! timestamp/diarization options, and purpose through a versioned canonical
//! `transcription_request_digest`.

use sha2::{Digest, Sha256};

use super::result::RequestedLanguageV1;

// ---------------------------------------------------------------------------
// Authorization request
// ---------------------------------------------------------------------------

/// The media-egress authorization request for transcription.
///
/// Every caller context field is bound into authorization identity through
/// the `transcription_request_digest`. Ask grants once/session/machine-local
/// project; standing grant identity remains destination/project/purpose
/// policy, while every use independently authorizes and audits the exact
/// request digest. There is no global grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaEgressTranscriptionRequest {
    pub provider_id: String,
    pub model_id: String,
    pub credential_fingerprint_digest: String,
    pub origin: String,
    pub resolved_location: String,
    pub project_digest: String,
    pub session_id: String,
    pub attachment_id: String,
    pub attachment_checksum: String,
    pub interval_start_us: u64,
    pub interval_end_us: u64,
    pub prompt_bytes: Vec<u8>,
    pub keywords: Vec<String>,
    pub languages: Vec<RequestedLanguageV1>,
    pub timestamps: super::result::TimestampsKind,
    pub diarization: bool,
    pub purpose: TranscriptionPurpose,
}

/// The transcription purpose. Always `transcription` for this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptionPurpose {
    Transcription,
}

impl TranscriptionPurpose {
    pub fn as_str(self) -> &'static str {
        "transcription"
    }
}

/// The versioned canonical digest version.
pub const TRANSCRIPTION_REQUEST_DIGEST_VERSION: u8 = 1;

/// Compute the versioned canonical `transcription_request_digest`.
///
/// The canonical input is a deterministic byte sequence covering every bound
/// field. Same canonical input is byte-stable; any mutation of any bound
/// field changes the digest.
pub fn transcription_request_digest(req: &MediaEgressTranscriptionRequest) -> String {
    let mut hasher = Sha256::new();
    // Version prefix
    hasher.update([TRANSCRIPTION_REQUEST_DIGEST_VERSION]);
    // Deterministic field order
    hasher.update(b"provider_id:");
    hasher.update(req.provider_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"model_id:");
    hasher.update(req.model_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"credential_fingerprint_digest:");
    hasher.update(req.credential_fingerprint_digest.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"origin:");
    hasher.update(req.origin.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"resolved_location:");
    hasher.update(req.resolved_location.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"project_digest:");
    hasher.update(req.project_digest.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"session_id:");
    hasher.update(req.session_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"attachment_id:");
    hasher.update(req.attachment_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"attachment_checksum:");
    hasher.update(req.attachment_checksum.as_bytes());
    hasher.update(b"\n");
    hasher.update(b"interval_start_us:");
    hasher.update(req.interval_start_us.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(b"interval_end_us:");
    hasher.update(req.interval_end_us.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(b"prompt_bytes:");
    hasher.update(&req.prompt_bytes);
    hasher.update(b"\n");
    hasher.update(b"keywords:");
    for kw in &req.keywords {
        hasher.update(kw.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"languages:");
    for lang in &req.languages {
        hasher.update(lang.code.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"timestamps:");
    hasher.update(timestamps_str(req.timestamps).as_bytes());
    hasher.update(b"\n");
    hasher.update(b"diarization:");
    hasher.update(if req.diarization { b"true" } else { b"false" });
    hasher.update(b"\n");
    hasher.update(b"purpose:");
    hasher.update(req.purpose.as_str().as_bytes());
    hasher.update(b"\n");
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn timestamps_str(ts: super::result::TimestampsKind) -> &'static str {
    match ts {
        super::result::TimestampsKind::Off => "off",
        super::result::TimestampsKind::Segment => "segment",
        super::result::TimestampsKind::Word => "word",
    }
}
