//! Normalized transcription result types (`NormalizedTranscriptionResultV1`).
//!
//! The public normalized result is the closed product:
//! `{schema_version, text, content, requested_languages, applied_languages,
//! detected_languages, timestamps, diarization, usage, provenance, complete,
//! omitted_text_scalars, omitted_text_utf8_bytes, omitted_segments,
//! omitted_words}`.
//!
//! Language elements use three noninterchangeable closed codecs:
//! [`RequestedLanguageV1`], [`AppliedLanguageV1`], [`DetectedLanguageV1`].

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Language codecs
// ---------------------------------------------------------------------------

/// A caller-requested language: exactly `{kind:"requested",code}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename = "requested", deny_unknown_fields)]
pub struct RequestedLanguageV1 {
    pub code: String,
}

impl RequestedLanguageV1 {
    pub fn new(code: String) -> Self {
        Self { code }
    }
}

/// An applied (sent) language: exactly `{kind:"applied",code}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename = "applied", deny_unknown_fields)]
pub struct AppliedLanguageV1 {
    pub code: String,
}

impl AppliedLanguageV1 {
    pub fn new(code: String) -> Self {
        Self { code }
    }
}

/// A provider-detected language: exactly `{kind:"detected",code}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename = "detected", deny_unknown_fields)]
pub struct DetectedLanguageV1 {
    pub code: String,
}

impl DetectedLanguageV1 {
    pub fn new(code: String) -> Self {
        Self { code }
    }
}

/// Tag-convert a requested language to an applied language (same code, new tag).
pub fn requested_to_applied(req: &RequestedLanguageV1) -> AppliedLanguageV1 {
    AppliedLanguageV1 {
        code: req.code.clone(),
    }
}

// ---------------------------------------------------------------------------
// Timestamp / diarization options
// ---------------------------------------------------------------------------

/// The requested timestamp granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampsKind {
    Off,
    Segment,
    Word,
}

/// The timestamp pair: `{requested, applied}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TimestampsV1 {
    pub requested: TimestampsKind,
    pub applied: TimestampsKind,
}

/// The diarization pair: `{requested, applied}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DiarizationV1 {
    pub requested: bool,
    pub applied: bool,
}

// ---------------------------------------------------------------------------
// Content variants
// ---------------------------------------------------------------------------

/// The closed content union: exactly one tagged variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptionContentV1 {
    /// Plain text (timestamps off/off).
    Plain { text: String },
    /// Segment timestamps (segment/segment).
    Segments { items: Vec<TranscriptSegmentV1> },
    /// Word timestamps (word/word).
    Words { items: Vec<TranscriptWordV1> },
    /// Diarized (diarization on, timestamps off/off).
    Diarized {
        duration_us: u64,
        items: Vec<DiarizedSegmentV1>,
    },
}

/// A transcript segment: `{id:u32, start_us:u64, end_us:u64, text}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TranscriptSegmentV1 {
    pub id: u32,
    pub start_us: u64,
    pub end_us: u64,
    pub text: String,
}

/// A transcript word: `{word, start_us:u64, end_us:u64}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TranscriptWordV1 {
    pub word: String,
    pub start_us: u64,
    pub end_us: u64,
}

/// A diarized segment: `{kind:"speech", id:u32, start_us:u64, end_us:u64, text, speaker}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiarizedSegmentV1 {
    pub id: u32,
    pub start_us: u64,
    pub end_us: u64,
    pub text: String,
    pub speaker: String,
}

impl DiarizedSegmentV1 {
    /// The fixed local kind emitted for every diarized segment.
    pub const KIND: &'static str = "speech";

    pub fn new(id: u32, start_us: u64, end_us: u64, text: String, speaker: String) -> Self {
        Self {
            id,
            start_us,
            end_us,
            text,
            speaker,
        }
    }
}

impl Serialize for DiarizedSegmentV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("DiarizedSegmentV1", 6)?;
        s.serialize_field("kind", &Self::KIND)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("start_us", &self.start_us)?;
        s.serialize_field("end_us", &self.end_us)?;
        s.serialize_field("text", &self.text)?;
        s.serialize_field("speaker", &self.speaker)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for DiarizedSegmentV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename = "kind", deny_unknown_fields)]
        enum Helper {
            #[serde(rename = "speech")]
            Speech {
                id: u32,
                start_us: u64,
                end_us: u64,
                text: String,
                speaker: String,
            },
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(match h {
            Helper::Speech {
                id,
                start_us,
                end_us,
                text,
                speaker,
            } => Self::new(id, start_us, end_us, text, speaker),
        })
    }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

/// The closed usage union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptionUsageV1 {
    NotReported,
    Tokens {
        input_tokens: u64,
        text_tokens: u64,
        audio_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
    },
    Duration {
        duration_us: u64,
    },
}

impl TranscriptionUsageV1 {
    /// Validate the token usage equations:
    /// `input_tokens = text_tokens + audio_tokens` and
    /// `total_tokens = input_tokens + output_tokens`.
    pub fn validate_tokens(
        input_tokens: u64,
        text_tokens: u64,
        audio_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
    ) -> Option<Self> {
        let input_check = text_tokens.checked_add(audio_tokens)?;
        if input_check != input_tokens {
            return None;
        }
        let total_check = input_tokens.checked_add(output_tokens)?;
        if total_check != total_tokens {
            return None;
        }
        Some(Self::Tokens {
            input_tokens,
            text_tokens,
            audio_tokens,
            output_tokens,
            total_tokens,
        })
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Exact safe identity provenance. Every digest is the exact full lowercase
/// 64-hex value owned by its prerequisite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TranscriptionProvenanceV1 {
    pub attachment_id: String,
    pub attachment_version: u64,
    pub attachment_checksum: String,
    pub interval_start_us: u64,
    pub interval_end_us: u64,
    pub session_id: String,
    pub canonical_project_digest: String,
    pub provider_id: String,
    pub endpoint_identity_digest: String,
    pub endpoint_config_generation: u64,
    pub model_id: String,
    pub credential_fingerprint_digest: String,
    pub transcription_request_digest: String,
    pub external_operation_id: String,
    pub external_attempt_number: u64,
}

// ---------------------------------------------------------------------------
// The closed normalized result
// ---------------------------------------------------------------------------

/// The public normalized transcription result.
///
/// Unknown, missing, null, cross-variant, or unsolicited fields reject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NormalizedTranscriptionResultV1 {
    pub schema_version: u8,
    pub text: String,
    pub content: TranscriptionContentV1,
    pub requested_languages: Vec<RequestedLanguageV1>,
    pub applied_languages: Vec<AppliedLanguageV1>,
    pub detected_languages: Vec<DetectedLanguageV1>,
    pub timestamps: TimestampsV1,
    pub diarization: DiarizationV1,
    pub usage: TranscriptionUsageV1,
    pub provenance: TranscriptionProvenanceV1,
    pub complete: bool,
    pub omitted_text_scalars: u64,
    pub omitted_text_utf8_bytes: u64,
    pub omitted_segments: u64,
    pub omitted_words: u64,
}

/// Projection limits.
pub const TEXT_PROJECTION_MAX_SCALARS: usize = 262_144;
pub const TEXT_PROJECTION_MAX_UTF8_BYTES: usize = 1_048_576;
pub const SEGMENT_PROJECTION_MAX_ITEMS: usize = 50_000;

/// The result of projecting root text and segments/words to the bounded
/// normalized result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionOutcome {
    pub text: String,
    pub complete: bool,
    pub omitted_text_scalars: u64,
    pub omitted_text_utf8_bytes: u64,
    pub omitted_segments: u64,
    pub omitted_words: u64,
}

/// Project root text to the longest valid UTF-8 prefix satisfying both
/// 262,144 scalars and 1,048,576 bytes. Truncation never splits a scalar.
pub fn project_text(text: &str) -> ProjectionOutcome {
    let bytes = text.as_bytes();
    if bytes.len() <= TEXT_PROJECTION_MAX_UTF8_BYTES {
        let scalars = text.chars().count();
        if scalars <= TEXT_PROJECTION_MAX_SCALARS {
            return ProjectionOutcome {
                text: text.to_string(),
                complete: true,
                omitted_text_scalars: 0,
                omitted_text_utf8_bytes: 0,
                omitted_segments: 0,
                omitted_words: 0,
            };
        }
    }

    // Find the longest valid UTF-8 prefix within the byte cap.
    let byte_cap = TEXT_PROJECTION_MAX_UTF8_BYTES.min(bytes.len());
    let mut valid_byte_end = byte_cap;
    while valid_byte_end > 0 && !text.is_char_boundary(valid_byte_end) {
        valid_byte_end -= 1;
    }
    let prefix = &text[..valid_byte_end];
    let prefix_chars: Vec<char> = prefix.chars().take(TEXT_PROJECTION_MAX_SCALARS).collect();
    let projected: String = prefix_chars.iter().collect();
    let projected_bytes = projected.len();
    let projected_scalars = projected.chars().count();

    let omitted_scalars = text.chars().count().saturating_sub(projected_scalars) as u64;
    let omitted_bytes = bytes.len().saturating_sub(projected_bytes) as u64;
    ProjectionOutcome {
        text: projected,
        complete: false,
        omitted_text_scalars: omitted_scalars,
        omitted_text_utf8_bytes: omitted_bytes,
        omitted_segments: 0,
        omitted_words: 0,
    }
}

/// Validate the local diarized speaker code grammar:
/// `speaker_(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-6])`.
pub fn is_valid_local_speaker(speaker: &str) -> bool {
    let Some(rest) = speaker.strip_prefix("speaker_") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    // Must be all ASCII digits
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Grammar forbids leading zeros (`[1-9]` first digit).
    if rest.starts_with('0') {
        return false;
    }
    let n: u32 = match rest.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    (1..=256).contains(&n)
}

/// Map provider speaker codes to local `speaker_1..N` in first-appearance
/// order without gaps, aliases, case folding, identity inference, or
/// provider-code exposure.
pub fn map_provider_speakers(provider_speakers: &[Option<String>]) -> Vec<Option<String>> {
    let mut mapping: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut next_id: u32 = 1;
    let mut result = Vec::with_capacity(provider_speakers.len());
    for ps in provider_speakers {
        match ps {
            None => result.push(None),
            Some(code) => {
                let local = if let Some(&id) = mapping.get(code) {
                    id
                } else {
                    let id = next_id;
                    mapping.insert(code.clone(), id);
                    next_id += 1;
                    id
                };
                result.push(Some(format!("speaker_{local}")));
            }
        }
    }
    result
}

/// Convert decimal seconds to integer microseconds with checked
/// round-to-nearest, ties-to-even.
pub fn decimal_seconds_to_microseconds(seconds: f64) -> Option<u64> {
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    let us = seconds * 1_000_000.0;
    if !us.is_finite() || us < 0.0 {
        return None;
    }
    // Round to nearest, ties to even
    let rounded = us.round_ties_even();
    if rounded < 0.0 || rounded > u64::MAX as f64 {
        return None;
    }
    Some(rounded as u64)
}

/// Validate that the content variant matches the timestamp/diarization
/// invariants. Plain and diarized content require off/off; segments
/// require segment/segment; words require word/word. Diarized content
/// requires diarization true/true; every other variant requires false/false.
/// An option/result mismatch is `invalid_output`, never a degraded flag.
pub fn validate_content_timestamps(
    content: &TranscriptionContentV1,
    timestamps: &TimestampsV1,
    diarization: &DiarizationV1,
) -> Result<(), String> {
    match content {
        TranscriptionContentV1::Plain { .. } => {
            if timestamps.requested != TimestampsKind::Off
                || timestamps.applied != TimestampsKind::Off
            {
                return Err("plain content requires timestamps off/off".into());
            }
            if diarization.requested || diarization.applied {
                return Err("plain content requires diarization false/false".into());
            }
        }
        TranscriptionContentV1::Segments { .. } => {
            if timestamps.requested != TimestampsKind::Segment
                || timestamps.applied != TimestampsKind::Segment
            {
                return Err("segments content requires timestamps segment/segment".into());
            }
            if diarization.requested || diarization.applied {
                return Err("segments content requires diarization false/false".into());
            }
        }
        TranscriptionContentV1::Words { .. } => {
            if timestamps.requested != TimestampsKind::Word
                || timestamps.applied != TimestampsKind::Word
            {
                return Err("words content requires timestamps word/word".into());
            }
            if diarization.requested || diarization.applied {
                return Err("words content requires diarization false/false".into());
            }
        }
        TranscriptionContentV1::Diarized { .. } => {
            if timestamps.requested != TimestampsKind::Off
                || timestamps.applied != TimestampsKind::Off
            {
                return Err("diarized content requires timestamps off/off".into());
            }
            if !diarization.requested || !diarization.applied {
                return Err("diarized content requires diarization true/true".into());
            }
        }
    }
    Ok(())
}
