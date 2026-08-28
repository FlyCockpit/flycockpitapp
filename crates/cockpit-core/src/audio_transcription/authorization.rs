//! Media-egress authorization for transcription.
//!
//! Central `AuthorizationRequest::MediaEgress` for purpose `transcription`,
//! bound to provider, selected model, credential fingerprint, origin,
//! resolved location, project, session, attachment checksum, exact media
//! interval, prompt bytes, ordered keywords, ordered languages,
//! timestamp/diarization options, and purpose through a versioned canonical
//! `transcription_request_digest`.

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::result::RequestedLanguageV1;
use crate::approval::{Approver, AuthorizationRequest, Decision};
pub use crate::image_sidecar::CredentialFingerprintDigest;

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
    /// The credential FINGERPRINT digest — a type-enforced opaque digest, never
    /// the credential token. See [`CredentialFingerprintDigest`].
    pub credential_fingerprint_digest: CredentialFingerprintDigest,
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

/// The versioned canonical `transcription_request_digest` under authorization.
///
/// A type-enforced newtype with a private inner string: the only production way
/// to obtain one is [`transcription_request_digest`] (the canonical-encode +
/// SHA-256 of a [`MediaEgressTranscriptionRequest`]). This makes a raw provider
/// token, prompt string, or other arbitrary text *unrepresentable* here, so
/// nothing but a real request digest can be placed in
/// [`crate::approval::AuthorizationRequest::MediaEgress`]'s `request_digest`
/// field and reach the logged / prompt sink. Mirrors
/// [`crate::image_generation_agent_tools::PlanDigest`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaEgressRequestDigest(String);

impl MediaEgressRequestDigest {
    /// The full lowercase 64-hex digest, for display/prefixing at the authz
    /// boundary. Read-only: there is no public way to construct this from an
    /// arbitrary string in production.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only raw constructor. `#[cfg(test)]`-gated so production code cannot
    /// bypass [`transcription_request_digest`]; tests may synthesize a digest
    /// without assembling a full request.
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl MediaEgressTranscriptionRequest {
    /// The versioned canonical `transcription_request_digest` binding every
    /// caller-context field of this request.
    pub fn digest(&self) -> MediaEgressRequestDigest {
        transcription_request_digest(self)
    }

    /// Route this request through the real central authorization chokepoint.
    ///
    /// This is the ONLY transcription authorize path: it computes the exact
    /// `transcription_request_digest`, projects the request to the secret-free
    /// redacted facts, and hands them to
    /// [`Approver::authorize`] via [`AuthorizationRequest::MediaEgress`]. No
    /// prompt text, keyword or language strings, credential token, or audio
    /// bytes cross the seam — the digest binds them. This type is a builder for
    /// the central request, never a bypass of the Approver.
    pub async fn authorize(&self, approver: &Approver) -> Result<Decision> {
        let request_digest = self.digest();
        let keyword_count = u32::try_from(self.keywords.len())
            .map_err(|_| anyhow::anyhow!("keyword count exceeds u32"))?;
        let language_count = u32::try_from(self.languages.len())
            .map_err(|_| anyhow::anyhow!("language count exceeds u32"))?;
        approver
            .authorize(AuthorizationRequest::MediaEgress {
                request_digest: &request_digest,
                purpose: self.purpose.as_str(),
                provider_id: &self.provider_id,
                model_id: &self.model_id,
                credential_fingerprint_digest: &self.credential_fingerprint_digest,
                origin: &self.origin,
                resolved_location: &self.resolved_location,
                project_digest: &self.project_digest,
                session_id: &self.session_id,
                attachment_id: &self.attachment_id,
                attachment_checksum: &self.attachment_checksum,
                interval_start_us: self.interval_start_us,
                interval_end_us: self.interval_end_us,
                prompt_present: !self.prompt_bytes.is_empty(),
                keyword_count,
                language_count,
                timestamps: timestamps_str(self.timestamps),
                diarization: self.diarization,
            })
            .await
    }
}

/// The versioned canonical digest version. Bumped to 2 for the unambiguous
/// length-prefixed canonical encoding (v1 used label/newline delimiters that
/// were collision-prone under embedded newlines).
pub const TRANSCRIPTION_REQUEST_DIGEST_VERSION: u8 = 2;

/// Length-prefix a variable-length field into the hasher: an 8-byte
/// little-endian byte count, then the bytes. This makes the concatenation
/// unambiguous — no field's content can be misread as a delimiter or bleed into
/// an adjacent field, because the reader always knows each field's exact length.
fn update_lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Compute the versioned canonical `transcription_request_digest`.
///
/// The canonical encoding is unambiguous: every field is length-prefixed, every
/// list is prefixed with its element count and each element is itself
/// length-prefixed, and fixed-width integers/booleans are written as raw
/// little-endian bytes. No label or newline delimiter is used, so embedded
/// `\n`/label bytes cannot shift content between fields or across list
/// boundaries — every field and boundary is uniquely bound. Same request is
/// byte-stable; any mutation of any bound field (or list order/length) changes
/// the digest. This is the SOLE production constructor of
/// [`MediaEgressRequestDigest`].
pub fn transcription_request_digest(
    req: &MediaEgressTranscriptionRequest,
) -> MediaEgressRequestDigest {
    let mut hasher = Sha256::new();
    // Version prefix (fixed width).
    hasher.update([TRANSCRIPTION_REQUEST_DIGEST_VERSION]);
    // Scalars, each length-prefixed and in a fixed order.
    update_lp(&mut hasher, req.provider_id.as_bytes());
    update_lp(&mut hasher, req.model_id.as_bytes());
    update_lp(
        &mut hasher,
        req.credential_fingerprint_digest.as_str().as_bytes(),
    );
    update_lp(&mut hasher, req.origin.as_bytes());
    update_lp(&mut hasher, req.resolved_location.as_bytes());
    update_lp(&mut hasher, req.project_digest.as_bytes());
    update_lp(&mut hasher, req.session_id.as_bytes());
    update_lp(&mut hasher, req.attachment_id.as_bytes());
    update_lp(&mut hasher, req.attachment_checksum.as_bytes());
    // Fixed-width integers as raw LE bytes (no decimal string ambiguity).
    hasher.update(req.interval_start_us.to_le_bytes());
    hasher.update(req.interval_end_us.to_le_bytes());
    // Prompt bytes, length-prefixed (may contain any byte, incl. newlines).
    update_lp(&mut hasher, &req.prompt_bytes);
    // Keywords list: element count, then each element length-prefixed.
    hasher.update((req.keywords.len() as u64).to_le_bytes());
    for kw in &req.keywords {
        update_lp(&mut hasher, kw.as_bytes());
    }
    // Languages list: element count, then each code length-prefixed.
    hasher.update((req.languages.len() as u64).to_le_bytes());
    for lang in &req.languages {
        update_lp(&mut hasher, lang.code.as_bytes());
    }
    // Timestamps token, length-prefixed; diarization as a single byte.
    update_lp(&mut hasher, timestamps_str(req.timestamps).as_bytes());
    hasher.update([u8::from(req.diarization)]);
    // Purpose, length-prefixed.
    update_lp(&mut hasher, req.purpose.as_str().as_bytes());

    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        hex.push_str(&format!("{byte:02x}"));
    }
    MediaEgressRequestDigest(hex)
}

fn timestamps_str(ts: super::result::TimestampsKind) -> &'static str {
    match ts {
        super::result::TimestampsKind::Off => "off",
        super::result::TimestampsKind::Segment => "segment",
        super::result::TimestampsKind::Word => "word",
    }
}
