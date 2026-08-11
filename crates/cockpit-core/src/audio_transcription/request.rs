//! Multipart transcription request encoding with exact length planning.
//!
//! The normalized audio file part is exactly `1..=25_000_000` bytes, the
//! encoded multipart overhead excluding those file bytes is at most `65_536`
//! bytes, and the complete encoded request body is at most `25_065_536` bytes.
//! Compute the exact encoded length before allocation or send with checked
//! `u64` additions and checked conversion to every platform/client length
//! type; reject file-cap, overhead-cap, total-cap, or arithmetic/conversion
//! overflow before reservation/HTTP.

use std::collections::HashSet;

use anyhow::{Result, bail};

use super::catalogs::{
    GptTranscribeLanguageCodeV1, WhisperLanguageCodeV1, gpt_transcribe_iso639_1_subset,
};
use super::result::RequestedLanguageV1;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum normalized audio file bytes.
pub const MAX_FILE_BYTES: u64 = 25_000_000;
/// Minimum normalized audio file bytes.
pub const MIN_FILE_BYTES: u64 = 1;
/// Maximum encoded multipart overhead (excluding file bytes).
pub const MAX_OVERHEAD_BYTES: u64 = 65_536;
/// Maximum complete encoded request body.
pub const MAX_TOTAL_BYTES: u64 = 25_065_536;
/// Boundary collisions allowed before failing.
pub const MAX_BOUNDARY_ATTEMPTS: usize = 8;
/// Boundary prefix.
pub const BOUNDARY_PREFIX: &str = "flycockpit-";
/// Constant file name for the audio part.
pub const AUDIO_PART_FILENAME: &str = "audio.wav";
/// Constant part type for the audio part.
pub const AUDIO_PART_CONTENT_TYPE: &str = "audio/wav";

// ---------------------------------------------------------------------------
// Model descriptor
// ---------------------------------------------------------------------------

/// The selected transcription model. Pure and feature-driven: ordinary
/// completed-file transcription always uses `gpt-transcribe`; timestamps
/// require `whisper-1`; diarization requires `gpt-4o-transcribe-diarize`;
/// requesting timestamps and diarization together is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptionModel {
    GptTranscribe,
    Gpt4oTranscribeDiarize,
    Whisper1,
}

impl TranscriptionModel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GptTranscribe => "gpt-transcribe",
            Self::Gpt4oTranscribeDiarize => "gpt-4o-transcribe-diarize",
            Self::Whisper1 => "whisper-1",
        }
    }

    /// Whether this model accepts multiple requested languages.
    pub fn accepts_multiple_languages(self) -> bool {
        self == Self::GptTranscribe
    }

    /// Maximum number of requested languages this model accepts.
    pub fn max_languages(self) -> usize {
        match self {
            Self::GptTranscribe => LANGUAGES_MAX_ENTRIES,
            Self::Gpt4oTranscribeDiarize | Self::Whisper1 => 1,
        }
    }

    /// Select the model from the requested timestamps and diarization.
    /// Returns an error if timestamps and diarization are both requested
    /// (unsupported), or if an unsupported combination is given.
    pub fn select(timestamps: super::result::TimestampsKind, diarization: bool) -> Result<Self> {
        use super::result::TimestampsKind;
        match (timestamps, diarization) {
            (TimestampsKind::Off, false) => Ok(Self::GptTranscribe),
            (TimestampsKind::Off, true) => Ok(Self::Gpt4oTranscribeDiarize),
            (TimestampsKind::Segment | TimestampsKind::Word, false) => Ok(Self::Whisper1),
            (TimestampsKind::Segment | TimestampsKind::Word, true) => {
                bail!("unsupported: timestamps and diarization cannot both be requested")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Caller context (validated, bounded)
// ---------------------------------------------------------------------------

/// The requested timestamp granularity for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerTimestamps {
    Off,
    Segment,
    Word,
}

/// Validated caller context for a transcription request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    pub prompt: Option<String>,
    pub keywords: Vec<String>,
    pub languages: Vec<RequestedLanguageV1>,
    pub timestamps: CallerTimestamps,
    pub diarization: bool,
}

/// Maximum prompt: 4,096 Unicode scalars and 16,384 UTF-8 bytes.
pub const PROMPT_MAX_SCALARS: usize = 4_096;
pub const PROMPT_MAX_UTF8_BYTES: usize = 16_384;
/// Maximum keywords: 0..64 entries.
pub const KEYWORDS_MAX_ENTRIES: usize = 64;
/// Each keyword: cap at 64 scalars and 256 UTF-8 bytes.
pub const KEYWORD_MAX_SCALARS: usize = 64;
pub const KEYWORD_MAX_UTF8_BYTES: usize = 256;
/// Aggregate keywords: at most 4,096 scalars/16,384 bytes.
pub const KEYWORDS_AGGREGATE_MAX_SCALARS: usize = 4_096;
pub const KEYWORDS_AGGREGATE_MAX_UTF8_BYTES: usize = 16_384;
/// Maximum languages: 0..16 unique values in caller order.
pub const LANGUAGES_MAX_ENTRIES: usize = 16;

/// Trim only leading/trailing ASCII SP (0x20) and TAB (0x09); preserve every
/// internal byte.
pub fn trim_sp_tab(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// Validate the caller prompt: trim only leading/trailing SP/TAB; preserve
/// internal bytes; omit the field when the result is empty; cap at 4,096
/// scalars and 16,384 UTF-8 bytes. First validate UTF-8.
pub fn validate_prompt(raw: &str) -> Result<Option<String>> {
    let trimmed = trim_sp_tab(raw);
    if trimmed.is_empty() {
        return Ok(None);
    }
    let scalars = trimmed.chars().count();
    if scalars > PROMPT_MAX_SCALARS {
        bail!("prompt_too_long: {scalars} scalars exceeds {PROMPT_MAX_SCALARS}");
    }
    let utf8_bytes = trimmed.len();
    if utf8_bytes > PROMPT_MAX_UTF8_BYTES {
        bail!("prompt_too_long: {utf8_bytes} bytes exceeds {PROMPT_MAX_UTF8_BYTES}");
    }
    Ok(Some(trimmed.to_string()))
}

/// Validate a single keyword: reject `<`, `>`, CR, or LF anywhere in the
/// original bytes; then trim only leading/trailing SP/TAB; require nonempty;
/// cap at 64 scalars and 256 UTF-8 bytes.
pub fn validate_keyword(raw: &str) -> Result<String> {
    // Reject forbidden bytes in the ORIGINAL (pre-trim) string
    for b in raw.bytes() {
        if b == b'<' || b == b'>' || b == b'\r' || b == b'\n' {
            bail!("keyword_forbidden_byte: < > CR LF are not allowed");
        }
    }
    let trimmed = trim_sp_tab(raw);
    if trimmed.is_empty() {
        bail!("keyword_empty: trimmed keyword must be nonempty");
    }
    let scalars = trimmed.chars().count();
    if scalars > KEYWORD_MAX_SCALARS {
        bail!("keyword_too_long: {scalars} scalars exceeds {KEYWORD_MAX_SCALARS}");
    }
    let utf8_bytes = trimmed.len();
    if utf8_bytes > KEYWORD_MAX_UTF8_BYTES {
        bail!("keyword_too_long: {utf8_bytes} bytes exceeds {KEYWORD_MAX_UTF8_BYTES}");
    }
    Ok(trimmed.to_string())
}

/// Validate the keywords array: 0..64 entries; each entry validated; aggregate
/// at most 4,096 scalars/16,384 bytes; exact post-trim UTF-8 duplicates reject
/// rather than dedupe.
pub fn validate_keywords(raw: &[String]) -> Result<Vec<String>> {
    if raw.len() > KEYWORDS_MAX_ENTRIES {
        bail!(
            "too_many_keywords: {} exceeds {KEYWORDS_MAX_ENTRIES}",
            raw.len()
        );
    }
    let mut validated = Vec::with_capacity(raw.len());
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut agg_scalars = 0usize;
    let mut agg_bytes = 0usize;
    for entry in raw {
        let trimmed = validate_keyword(entry)?;
        let bytes = trimmed.as_bytes().to_vec();
        if !seen.insert(bytes) {
            bail!("keyword_duplicate: exact post-trim UTF-8 duplicates reject");
        }
        agg_scalars = agg_scalars
            .checked_add(trimmed.chars().count())
            .ok_or_else(|| anyhow::anyhow!("keyword_aggregate_overflow: scalar count overflow"))?;
        if agg_scalars > KEYWORDS_AGGREGATE_MAX_SCALARS {
            bail!(
                "keywords_aggregate_too_long: {agg_scalars} scalars exceeds {KEYWORDS_AGGREGATE_MAX_SCALARS}"
            );
        }
        agg_bytes = agg_bytes
            .checked_add(trimmed.len())
            .ok_or_else(|| anyhow::anyhow!("keyword_aggregate_overflow: byte count overflow"))?;
        if agg_bytes > KEYWORDS_AGGREGATE_MAX_UTF8_BYTES {
            bail!(
                "keywords_aggregate_too_long: {agg_bytes} bytes exceeds {KEYWORDS_AGGREGATE_MAX_UTF8_BYTES}"
            );
        }
        validated.push(trimmed);
    }
    Ok(validated)
}

/// Validate the languages array for the gpt-transcribe model: 0..16 unique
/// values in caller order; each must be a member of the GPT catalog.
pub fn validate_gpt_languages(raw: &[String]) -> Result<Vec<RequestedLanguageV1>> {
    if raw.len() > LANGUAGES_MAX_ENTRIES {
        bail!(
            "too_many_languages: {} exceeds {LANGUAGES_MAX_ENTRIES}",
            raw.len()
        );
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut result = Vec::with_capacity(raw.len());
    for code in raw {
        if !seen.insert(code.clone()) {
            bail!("language_duplicate: exact caller duplicates reject");
        }
        if GptTranscribeLanguageCodeV1::new(code).is_none() {
            bail!("language_unlisted: {code} is not in the GPT-transcribe catalog");
        }
        result.push(RequestedLanguageV1::new(code.clone()));
    }
    Ok(result)
}

/// Validate the languages array for the whisper-1 model: zero or one exact
/// `en|WhisperLanguageCodeV1`.
pub fn validate_whisper_languages(raw: &[String]) -> Result<Vec<RequestedLanguageV1>> {
    if raw.len() > 1 {
        bail!("whisper_language_count: whisper-1 accepts zero or one language");
    }
    let mut result = Vec::with_capacity(raw.len());
    for code in raw {
        if WhisperLanguageCodeV1::new(code).is_none() {
            bail!("language_unlisted: {code} is not in the Whisper catalog");
        }
        result.push(RequestedLanguageV1::new(code.clone()));
    }
    Ok(result)
}

/// Validate the languages array for the diarization model: zero or one value
/// only from the assigned ISO 639-1 subset of the GPT catalog.
pub fn validate_diarize_languages(raw: &[String]) -> Result<Vec<RequestedLanguageV1>> {
    if raw.len() > 1 {
        bail!("diarize_language_count: diarization accepts zero or one language");
    }
    let mut result = Vec::with_capacity(raw.len());
    for code in raw {
        // Must be in the ISO 639-1 subset (alpha-2 only)
        if gpt_transcribe_iso639_1_subset()
            .iter()
            .all(|c| *c != code.as_str())
        {
            bail!("language_unlisted: {code} is not in the diarization ISO 639-1 subset");
        }
        result.push(RequestedLanguageV1::new(code.clone()));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Multipart length planning
// ---------------------------------------------------------------------------

/// A single multipart part specification.
#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub name: String,
    pub value: Vec<u8>,
    pub is_file: bool,
}

/// The planned multipart request: the exact encoded length and the parts.
#[derive(Debug, Clone)]
pub struct PlannedMultipart {
    pub boundary: String,
    pub parts: Vec<MultipartPart>,
    pub encoded_length: u64,
    pub file_bytes: u64,
    pub overhead_bytes: u64,
}

/// Compute the encoded length of one part (excluding file bytes for the file
/// part, which are accounted separately).
fn part_encoded_length(part: &MultipartPart, boundary: &str) -> Result<u64> {
    let mut len: u64 = 0;
    // --<boundary>\r\n
    len = len
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    len = len
        .checked_add(boundary.len() as u64)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    len = len
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    // Content-Disposition: form-data; name="<name>"
    let disposition = if part.is_file {
        format!(
            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
            part.name, AUDIO_PART_FILENAME
        )
    } else {
        format!("Content-Disposition: form-data; name=\"{}\"\r\n", part.name)
    };
    len = len
        .checked_add(disposition.len() as u64)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    if part.is_file {
        len = len
            .checked_add(format!("Content-Type: {}\r\n", AUDIO_PART_CONTENT_TYPE).len() as u64)
            .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    }
    // blank line before value
    len = len
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    // value bytes (file part value is empty here; accounted separately)
    len = len
        .checked_add(part.value.len() as u64)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    // trailing \r\n
    len = len
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
    Ok(len)
}

/// Finalize the plan: validate file bytes, compute the exact encoded length,
/// check overhead/total caps, and return the planned multipart.
fn finalize_plan(
    file_bytes: u64,
    parts: Vec<MultipartPart>,
    boundary: &str,
) -> Result<PlannedMultipart> {
    // Validate file bytes
    if file_bytes < MIN_FILE_BYTES {
        bail!("file_too_small: {file_bytes} bytes is below {MIN_FILE_BYTES}");
    }
    if file_bytes > MAX_FILE_BYTES {
        bail!("file_too_large: {file_bytes} bytes exceeds {MAX_FILE_BYTES}");
    }
    // Validate boundary
    validate_boundary(boundary)?;

    // Compute overhead (everything except file bytes)
    let mut overhead: u64 = 0;
    for part in &parts {
        if part.is_file {
            // file part overhead (excluding the file bytes themselves)
            let file_part = MultipartPart {
                name: part.name.clone(),
                value: vec![], // don't count file bytes here
                is_file: true,
            };
            overhead = overhead
                .checked_add(part_encoded_length(&file_part, boundary)?)
                .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
            // Add file bytes separately
            overhead = overhead
                .checked_add(file_bytes)
                .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
        } else {
            overhead = overhead
                .checked_add(part_encoded_length(part, boundary)?)
                .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;
        }
    }
    // Closing boundary: --<boundary>--\r\n
    let closing = 2 + boundary.len() as u64 + 2 + 2; // "--" + boundary + "--" + "\r\n"
    overhead = overhead
        .checked_add(closing)
        .ok_or_else(|| anyhow::anyhow!("length_overflow"))?;

    // The overhead INCLUDES file bytes in the calculation above; separate them:
    let overhead_excluding_file = overhead
        .checked_sub(file_bytes)
        .ok_or_else(|| anyhow::anyhow!("length_underflow"))?;

    if overhead_excluding_file > MAX_OVERHEAD_BYTES {
        bail!("overhead_too_large: {overhead_excluding_file} bytes exceeds {MAX_OVERHEAD_BYTES}");
    }

    // Total = overhead (which includes file bytes)
    let total = overhead;
    if total > MAX_TOTAL_BYTES {
        bail!("total_too_large: {total} bytes exceeds {MAX_TOTAL_BYTES}");
    }

    Ok(PlannedMultipart {
        boundary: boundary.to_string(),
        parts,
        encoded_length: total,
        file_bytes,
        overhead_bytes: overhead_excluding_file,
    })
}

/// Plan the multipart request for the gpt-transcribe model.
///
/// Multipart parts are exactly `model`, `file`, optional nonempty `prompt`,
/// repeated `keywords[]` in caller order, then repeated `languages[]` in
/// caller order.
pub fn plan_gpt_transcribe(
    file_bytes: u64,
    prompt: Option<&str>,
    keywords: &[String],
    languages: &[RequestedLanguageV1],
    boundary: &str,
) -> Result<PlannedMultipart> {
    let mut parts = vec![
        MultipartPart {
            name: "model".into(),
            value: TranscriptionModel::GptTranscribe
                .as_str()
                .as_bytes()
                .to_vec(),
            is_file: false,
        },
        MultipartPart {
            name: "file".into(),
            value: vec![], // file bytes are accounted separately
            is_file: true,
        },
    ];
    if let Some(p) = prompt {
        if !p.is_empty() {
            parts.push(MultipartPart {
                name: "prompt".into(),
                value: p.as_bytes().to_vec(),
                is_file: false,
            });
        }
    }
    for kw in keywords {
        parts.push(MultipartPart {
            name: "keywords[]".into(),
            value: kw.as_bytes().to_vec(),
            is_file: false,
        });
    }
    for lang in languages {
        parts.push(MultipartPart {
            name: "languages[]".into(),
            value: lang.code.as_bytes().to_vec(),
            is_file: false,
        });
    }
    finalize_plan(file_bytes, parts, boundary)
}

/// Plan the multipart request for the gpt-4o-transcribe-diarize model.
///
/// Multipart parts are exactly `model`, `file`, `response_format=diarized_json`,
/// optional `chunking_strategy=auto` when probed duration is >30,000ms, then
/// optional singular `language` mapped from exactly one requested language.
/// Prompt/keywords/timestamps/multiple languages reject.
pub fn plan_gpt_4o_transcribe_diarize(
    file_bytes: u64,
    probed_duration_ms: Option<u64>,
    language: Option<&RequestedLanguageV1>,
    boundary: &str,
) -> Result<PlannedMultipart> {
    let mut parts = vec![
        MultipartPart {
            name: "model".into(),
            value: TranscriptionModel::Gpt4oTranscribeDiarize
                .as_str()
                .as_bytes()
                .to_vec(),
            is_file: false,
        },
        MultipartPart {
            name: "file".into(),
            value: vec![],
            is_file: true,
        },
        MultipartPart {
            name: "response_format".into(),
            value: b"diarized_json".to_vec(),
            is_file: false,
        },
    ];
    if let Some(dur) = probed_duration_ms {
        if dur > 30_000 {
            parts.push(MultipartPart {
                name: "chunking_strategy".into(),
                value: b"auto".to_vec(),
                is_file: false,
            });
        }
    }
    if let Some(lang) = language {
        parts.push(MultipartPart {
            name: "language".into(),
            value: lang.code.as_bytes().to_vec(),
            is_file: false,
        });
    }
    finalize_plan(file_bytes, parts, boundary)
}

/// Plan the multipart request for the whisper-1 model.
///
/// Multipart parts are exactly `model`, `file`, `response_format=verbose_json`,
/// one `timestamp_granularities[]` matching the requested kind, optional
/// singular `language`, then optional nonempty `prompt`. Keywords/multiple
/// languages reject.
pub fn plan_whisper_1(
    file_bytes: u64,
    timestamps: CallerTimestamps,
    language: Option<&RequestedLanguageV1>,
    prompt: Option<&str>,
    boundary: &str,
) -> Result<PlannedMultipart> {
    let granularity = match timestamps {
        CallerTimestamps::Segment => "segment",
        CallerTimestamps::Word => "word",
        CallerTimestamps::Off => bail!("whisper-1 requires segment or word timestamps"),
    };
    let mut parts = vec![
        MultipartPart {
            name: "model".into(),
            value: TranscriptionModel::Whisper1.as_str().as_bytes().to_vec(),
            is_file: false,
        },
        MultipartPart {
            name: "file".into(),
            value: vec![],
            is_file: true,
        },
        MultipartPart {
            name: "response_format".into(),
            value: b"verbose_json".to_vec(),
            is_file: false,
        },
        MultipartPart {
            name: "timestamp_granularities[]".into(),
            value: granularity.as_bytes().to_vec(),
            is_file: false,
        },
    ];
    if let Some(lang) = language {
        parts.push(MultipartPart {
            name: "language".into(),
            value: lang.code.as_bytes().to_vec(),
            is_file: false,
        });
    }
    if let Some(p) = prompt {
        if !p.is_empty() {
            parts.push(MultipartPart {
                name: "prompt".into(),
                value: p.as_bytes().to_vec(),
                is_file: false,
            });
        }
    }
    finalize_plan(file_bytes, parts, boundary)
}

/// Validate the boundary: `flycockpit-` plus 32 lowercase hex digits.
pub fn validate_boundary(boundary: &str) -> Result<()> {
    let rest = boundary
        .strip_prefix(BOUNDARY_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("boundary must start with {BOUNDARY_PREFIX}"))?;
    if rest.len() != 32 {
        bail!("boundary must be 32 hex digits after prefix");
    }
    if !rest
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("boundary must be 32 lowercase hex digits");
    }
    Ok(())
}

/// Check that the exact `--<boundary>` bytes do not occur in any field or
/// audio. Returns Ok if safe, Err if a collision is found.
pub fn check_boundary_collision(
    boundary: &str,
    parts: &[MultipartPart],
    audio: &[u8],
) -> Result<()> {
    let marker = format!("--{boundary}");
    for part in parts {
        if part.is_file {
            continue; // file bytes checked separately
        }
        if part
            .value
            .windows(marker.len())
            .any(|w| w == marker.as_bytes())
        {
            bail!("boundary_collision: boundary marker found in field value");
        }
    }
    if audio.windows(marker.len()).any(|w| w == marker.as_bytes()) {
        bail!("boundary_collision: boundary marker found in audio bytes");
    }
    Ok(())
}

/// Encode the planned multipart into bytes. The transmitted byte count must
/// equal the precomputed length.
pub fn encode_multipart(plan: &PlannedMultipart, audio: &[u8]) -> Result<Vec<u8>> {
    if audio.len() as u64 != plan.file_bytes {
        bail!(
            "audio length mismatch: expected {}, got {}",
            plan.file_bytes,
            audio.len()
        );
    }
    let capacity = usize::try_from(plan.encoded_length)
        .map_err(|_| anyhow::anyhow!("encoded_length too large for usize"))?;
    let mut buf = Vec::with_capacity(capacity);
    for part in &plan.parts {
        write!(buf, "--{}\r\n", plan.boundary).ok();
        if part.is_file {
            write!(
                buf,
                "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                part.name, AUDIO_PART_FILENAME
            )
            .ok();
            write!(buf, "Content-Type: {}\r\n", AUDIO_PART_CONTENT_TYPE).ok();
        } else {
            write!(
                buf,
                "Content-Disposition: form-data; name=\"{}\"\r\n",
                part.name
            )
            .ok();
        }
        buf.extend_from_slice(b"\r\n");
        if part.is_file {
            buf.extend_from_slice(audio);
        } else {
            buf.extend_from_slice(&part.value);
        }
        buf.extend_from_slice(b"\r\n");
    }
    write!(buf, "--{}--\r\n", plan.boundary).ok();
    // Verify transmitted length equals precomputed length
    if buf.len() as u64 != plan.encoded_length {
        bail!(
            "transmitted length mismatch: expected {}, got {}",
            plan.encoded_length,
            buf.len()
        );
    }
    Ok(buf)
}
