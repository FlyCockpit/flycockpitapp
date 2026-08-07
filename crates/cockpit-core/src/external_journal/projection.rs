//! Versioned sanitized tagged-union projection of an external operation.
//!
//! This is the only shape that may reach the filesystem capsule. Every field
//! is either a fixed-width hex digest or a short safe token, so pixels, media
//! bytes, prompts, typed input, raw paths/URLs, credentials, headers, provider
//! payloads, and signed query values are unrepresentable rather than merely
//! discouraged. The encoder enforces a strict 24-KiB cap.
//!
//! [`Digest`] and [`SafeToken`] are the same validated types the database
//! boundary uses (`cockpit_db::external_journal`). One definition, enforced in
//! both places, so a value that cannot be stored also cannot be projected.

use serde::{Deserialize, Serialize};

pub use cockpit_db::external_journal::{
    EXTERNAL_JOURNAL_TOKEN_MAX_LEN as MAX_SAFE_TOKEN_LEN, ExternalJournalDigest as Digest,
    ExternalJournalToken as SafeToken,
};

use super::ExternalJournalError;

/// Wire version of the projection envelope.
pub const PROJECTION_SCHEMA_VERSION: u16 = 1;

/// Strict encoder cap for one encoded projection.
pub const MAX_PROJECTION_BYTES: usize =
    cockpit_db::external_journal::EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES;

/// The sanitized tagged union. New consumers add a variant here rather than
/// inventing a second spool or smuggling bytes through an existing one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationBody {
    /// Computer input: which target, how many synthetic actions.
    ComputerInput {
        target_digest: Digest,
        action_count: u32,
    },
    /// Transcription: which audio source, how long it was.
    Transcription {
        source_digest: Digest,
        duration_ms: u64,
    },
    /// Sidecar process invocation.
    Sidecar {
        sidecar_kind: SafeToken,
        request_digest: Digest,
    },
    /// Image generation request.
    ImageGeneration {
        request_digest: Digest,
        image_count: u32,
    },
    /// Inference recovery. The inference-specific integration itself stays in
    /// `inference-audit-recovery-spool`; this is only the generic projection.
    InferenceRecovery {
        request_digest: Digest,
        provider_digest: Digest,
    },
}

impl OperationBody {
    /// Canonical operation-kind token for the identity triple.
    pub fn operation_kind(&self) -> &'static str {
        match self {
            Self::ComputerInput { .. } => "computer_input",
            Self::Transcription { .. } => "transcription",
            Self::Sidecar { .. } => "sidecar",
            Self::ImageGeneration { .. } => "image_generation",
            Self::InferenceRecovery { .. } => "inference_recovery",
        }
    }

    /// The same value as a validated token, for the database boundary.
    pub fn operation_kind_token(&self) -> SafeToken {
        SafeToken::parse(self.operation_kind()).expect("operation kinds are valid tokens")
    }
}

/// The versioned envelope written into a capsule slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedProjection {
    pub schema_version: u16,
    pub body: OperationBody,
}

impl SanitizedProjection {
    pub fn new(body: OperationBody) -> Self {
        Self {
            schema_version: PROJECTION_SCHEMA_VERSION,
            body,
        }
    }

    /// Canonical encoding with the strict 24-KiB cap.
    pub fn encode(&self) -> Result<Vec<u8>, ExternalJournalError> {
        if self.schema_version != PROJECTION_SCHEMA_VERSION {
            return Err(ExternalJournalError::Projection(format!(
                "unsupported projection schema version {}",
                self.schema_version
            )));
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| ExternalJournalError::Projection(error.to_string()))?;
        if bytes.len() > MAX_PROJECTION_BYTES {
            return Err(ExternalJournalError::ProjectionTooLarge {
                len: bytes.len(),
                cap: MAX_PROJECTION_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decode a projection produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ExternalJournalError> {
        if bytes.len() > MAX_PROJECTION_BYTES {
            return Err(ExternalJournalError::ProjectionTooLarge {
                len: bytes.len(),
                cap: MAX_PROJECTION_BYTES,
            });
        }
        let decoded: Self = serde_json::from_slice(bytes)
            .map_err(|error| ExternalJournalError::Projection(error.to_string()))?;
        if decoded.schema_version != PROJECTION_SCHEMA_VERSION {
            return Err(ExternalJournalError::Projection(format!(
                "unsupported projection schema version {}",
                decoded.schema_version
            )));
        }
        Ok(decoded)
    }

    /// Immutable payload digest recorded alongside the journal record.
    pub fn payload_digest(&self) -> Result<Digest, ExternalJournalError> {
        Ok(Digest::of(&self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> OperationBody {
        OperationBody::ComputerInput {
            target_digest: Digest::of(b"target"),
            action_count: 3,
        }
    }

    #[test]
    fn external_journal_redaction_sentinels_are_unrepresentable() {
        const SENTINELS: &[&str] = &[
            "SENTINEL-PROMPT-TEXT",
            "SENTINEL-TYPED-INPUT",
            "Bearer SENTINEL-CREDENTIAL",
            "/sentinel/raw/path",
            "https://sentinel.example/a?sig=SENTINEL",
            "x-sentinel-header: value",
        ];
        for sentinel in SENTINELS {
            assert!(
                Digest::parse(sentinel).is_err(),
                "digest accepted {sentinel}"
            );
            assert!(
                SafeToken::parse(sentinel).is_err(),
                "safe token accepted {sentinel}"
            );
        }

        // The sanitized encoding of a real operation contains no sentinel.
        let encoded = SanitizedProjection::new(OperationBody::Sidecar {
            sidecar_kind: SafeToken::parse("transcode").unwrap(),
            request_digest: Digest::of(b"SENTINEL-PROMPT-TEXT"),
        })
        .encode()
        .unwrap();
        let text = String::from_utf8(encoded).unwrap();
        for sentinel in SENTINELS {
            assert!(!text.contains(sentinel), "{sentinel} leaked into {text}");
        }
    }

    #[test]
    fn external_journal_redaction_sentinels_rejected_on_decode() {
        // A hand-forged payload that smuggles a raw path into a digest field
        // fails to deserialize, so a hostile spool file cannot reintroduce it.
        let forged = concat!(
            r#"{"schema_version":1,"body":{"kind":"computer_input","#,
            r#""target_digest":"/sentinel/raw/path","action_count":1}}"#
        );
        assert!(SanitizedProjection::decode(forged.as_bytes()).is_err());
    }

    #[test]
    fn external_journal_spool_limits_projection_cap_boundary() {
        assert_eq!(MAX_PROJECTION_BYTES, 24 * 1024);
        let ok = vec![b'x'; MAX_PROJECTION_BYTES];
        assert!(SanitizedProjection::decode(&ok).is_err()); // invalid JSON, not oversize
        let over = vec![b'x'; MAX_PROJECTION_BYTES + 1];
        match SanitizedProjection::decode(&over) {
            Err(ExternalJournalError::ProjectionTooLarge { len, cap }) => {
                assert_eq!(len, MAX_PROJECTION_BYTES + 1);
                assert_eq!(cap, MAX_PROJECTION_BYTES);
            }
            other => panic!("expected ProjectionTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn external_journal_spool_limits_projection_roundtrip_is_canonical() {
        let projection = SanitizedProjection::new(body());
        let encoded = projection.encode().unwrap();
        assert!(encoded.len() <= MAX_PROJECTION_BYTES);
        assert_eq!(SanitizedProjection::decode(&encoded).unwrap(), projection);
        // Encoding is deterministic, so the payload digest is immutable.
        assert_eq!(
            projection.payload_digest().unwrap(),
            projection.payload_digest().unwrap()
        );
    }

    #[test]
    fn external_journal_spool_limits_safe_token_bounds() {
        assert!(SafeToken::parse(&"a".repeat(MAX_SAFE_TOKEN_LEN)).is_ok());
        assert!(SafeToken::parse(&"a".repeat(MAX_SAFE_TOKEN_LEN + 1)).is_err());
        assert!(SafeToken::parse("").is_err());
        assert!(SafeToken::parse("Uppercase").is_err());
        assert!(SafeToken::parse("with space").is_err());
    }
}
