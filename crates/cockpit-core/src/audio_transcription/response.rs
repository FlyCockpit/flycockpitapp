//! Strict response decoding for the three transcription model families.
//!
//! Response decoding is strict and family-selected. The complete HTTP response
//! body is capped at 8 MiB before allocation; root/segment/word strings must be
//! valid UTF-8; provider arrays are capped at 200,000 members; each segment/word
//! text is capped at 16,384 scalars/65,536 bytes; IDs/speaker codes are 1..128
//! UTF-8 bytes; and all integer counts fit `u64`.

use anyhow::{Result, bail};

use super::catalogs::GptTranscribeLanguageCodeV1;
use super::result::{
    DetectedLanguageV1, DiarizedSegmentV1, TranscriptionUsageV1, decimal_seconds_to_microseconds,
    map_provider_speakers,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum HTTP response body: 8 MiB.
pub const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum provider array members.
pub const MAX_PROVIDER_ARRAY_MEMBERS: usize = 200_000;
/// Maximum segment/word text scalars.
pub const MAX_ITEM_TEXT_SCALARS: usize = 16_384;
/// Maximum segment/word text UTF-8 bytes.
pub const MAX_ITEM_TEXT_UTF8_BYTES: usize = 65_536;
/// Maximum ID/speaker code UTF-8 bytes: 1..128.
pub const MIN_ID_BYTES: usize = 1;
pub const MAX_ID_BYTES: usize = 128;
/// Maximum detected languages: 0..64.
pub const MAX_DETECTED_LANGUAGES: usize = 64;
/// Maximum distinct provider speaker codes: 256.
pub const MAX_DISTINCT_SPEAKERS: usize = 256;
/// Maximum segments per response for diarized.
pub const MAX_DIARIZED_ITEMS: usize = 200_000;

// ---------------------------------------------------------------------------
// gpt-transcribe response
// ---------------------------------------------------------------------------

/// The decoded gpt-transcribe response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptTranscribeResponse {
    pub text: String,
    pub detected_languages: Vec<DetectedLanguageV1>,
    pub usage: TranscriptionUsageV1,
}

/// Decode a gpt-transcribe response.
///
/// Requires `text:string` and `languages: Array<{code:string}>` with at most
/// 64 entries; every code must belong to the exact GPT catalog, exact
/// duplicates reject, order is preserved, and the array may be empty. Accepts
/// optional documented token usage.
pub fn decode_gpt_transcribe(body: &[u8]) -> Result<GptTranscribeResponse> {
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        bail!("invalid_output: response body exceeds 8 MiB");
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("invalid_output: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: expected object"))?;

    // text: string (required)
    let text = obj
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid_output: missing text"))?
        .to_string();

    // languages: Array<{code:string}> (required, may be empty)
    let langs_arr = obj
        .get("languages")
        .ok_or_else(|| anyhow::anyhow!("invalid_output: missing languages"))?;
    let langs = langs_arr
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: languages must be array"))?;
    if langs.len() > MAX_DETECTED_LANGUAGES {
        bail!("invalid_output: languages exceeds {MAX_DETECTED_LANGUAGES}");
    }
    let mut detected = Vec::with_capacity(langs.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in langs {
        let entry_obj = entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid_output: language entry must be object"))?;
        // deny_unknown_fields: only "code" allowed
        if entry_obj.len() != 1 || !entry_obj.contains_key("code") {
            bail!("invalid_output: language entry must have only code");
        }
        let code = entry_obj
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("invalid_output: language code must be string"))?;
        if GptTranscribeLanguageCodeV1::new(code).is_none() {
            bail!("invalid_output: language code {code} not in GPT catalog");
        }
        if !seen.insert(code.to_string()) {
            bail!("invalid_output: duplicate language code {code}");
        }
        detected.push(DetectedLanguageV1::new(code.to_string()));
    }

    // usage: optional token usage
    let usage = decode_optional_token_usage(obj)?;

    // Check for unknown root members
    for key in obj.keys() {
        match key.as_str() {
            "text" | "languages" | "usage" => {}
            _ => bail!("invalid_output: unknown root member {key}"),
        }
    }

    Ok(GptTranscribeResponse {
        text,
        detected_languages: detected,
        usage,
    })
}

/// Decode optional token usage for gpt-transcribe:
/// `{type:"tokens",input_tokens,input_token_details:{text_tokens,audio_tokens},output_tokens,total_tokens}`.
fn decode_optional_token_usage(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<TranscriptionUsageV1> {
    match obj.get("usage") {
        None => Ok(TranscriptionUsageV1::NotReported),
        Some(usage) => {
            let usage_obj = usage
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage must be object"))?;
            let type_str = usage_obj
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage type required"))?;
            if type_str != "tokens" {
                bail!("invalid_output: usage type must be tokens for gpt-transcribe");
            }
            // deny_unknown_fields
            let allowed = [
                "type",
                "input_tokens",
                "input_token_details",
                "output_tokens",
                "total_tokens",
            ];
            for key in usage_obj.keys() {
                if !allowed.contains(&key.as_str()) {
                    bail!("invalid_output: unknown usage member {key}");
                }
            }
            let input_tokens = get_u64(usage_obj, "input_tokens")?;
            let output_tokens = get_u64(usage_obj, "output_tokens")?;
            let total_tokens = get_u64(usage_obj, "total_tokens")?;
            let details = usage_obj
                .get("input_token_details")
                .ok_or_else(|| anyhow::anyhow!("invalid_output: input_token_details required"))?;
            let details_obj = details.as_object().ok_or_else(|| {
                anyhow::anyhow!("invalid_output: input_token_details must be object")
            })?;
            let text_tokens = get_u64(details_obj, "text_tokens")?;
            let audio_tokens = get_u64(details_obj, "audio_tokens")?;
            for key in details_obj.keys() {
                if key != "text_tokens" && key != "audio_tokens" {
                    bail!("invalid_output: unknown input_token_details member {key}");
                }
            }
            TranscriptionUsageV1::validate_tokens(
                input_tokens,
                text_tokens,
                audio_tokens,
                output_tokens,
                total_tokens,
            )
            .ok_or_else(|| anyhow::anyhow!("invalid_output: usage token equations do not hold"))
        }
    }
}

fn get_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u64> {
    let v = obj
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: missing {key}"))?;
    let n = v
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: {key} must be nonnegative integer"))?;
    Ok(n)
}

fn get_f64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<f64> {
    let v = obj
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: missing {key}"))?;
    let n = v
        .as_f64()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: {key} must be number"))?;
    Ok(n)
}

fn get_str<'a>(obj: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Result<&'a str> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid_output: {key} must be string"))
}

fn get_array<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a Vec<serde_json::Value>> {
    obj.get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("invalid_output: {key} must be array"))
}

// ---------------------------------------------------------------------------
// Diarized response (gpt-4o-transcribe-diarize)
// ---------------------------------------------------------------------------

/// The decoded diarized response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiarizedResponse {
    pub task: String,
    pub duration_us: u64,
    pub text: String,
    pub segments: Vec<DiarizedProviderSegment>,
    pub usage: TranscriptionUsageV1,
}

/// A provider diarized segment (before local normalization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiarizedProviderSegment {
    pub id: String,
    pub start_us: u64,
    pub end_us: u64,
    pub text: String,
    pub speaker: String,
}

/// Decode a diarized response.
///
/// Requires documented `task:"transcribe"`, finite nonnegative `duration`,
/// every segment's exact `type:"transcript.text.segment"` plus provider `id`,
/// and accepts `usage:{type:"duration",seconds}`.
pub fn decode_diarized(body: &[u8]) -> Result<DiarizedResponse> {
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        bail!("invalid_output: response body exceeds 8 MiB");
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("invalid_output: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: expected object"))?;

    let task = get_str(obj, "task")?;
    if task != "transcribe" {
        bail!("invalid_output: task must be transcribe");
    }
    let duration_secs = get_f64(obj, "duration")?;
    if !duration_secs.is_finite() || duration_secs < 0.0 {
        bail!("invalid_output: duration must be finite nonnegative");
    }
    let duration_us = decimal_seconds_to_microseconds(duration_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: duration overflow"))?;
    let text = get_str(obj, "text")?.to_string();

    let segs = get_array(obj, "segments")?;
    if segs.len() > MAX_DIARIZED_ITEMS {
        bail!("invalid_output: segments exceeds {MAX_DIARIZED_ITEMS}");
    }
    let mut segments = Vec::with_capacity(segs.len());
    let mut distinct_speakers: std::collections::HashSet<String> = std::collections::HashSet::new();
    for seg in segs {
        let seg_obj = seg
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid_output: segment must be object"))?;
        let seg_type = get_str(seg_obj, "type")?;
        if seg_type != "transcript.text.segment" {
            bail!("invalid_output: segment type must be transcript.text.segment");
        }
        let id = get_str(seg_obj, "id")?;
        validate_id_string(id)?;
        let start_secs = get_f64(seg_obj, "start")?;
        let end_secs = get_f64(seg_obj, "end")?;
        if !start_secs.is_finite() || start_secs < 0.0 {
            bail!("invalid_output: start must be finite nonnegative");
        }
        if !end_secs.is_finite() || end_secs < 0.0 {
            bail!("invalid_output: end must be finite nonnegative");
        }
        if start_secs > end_secs {
            bail!("invalid_output: start must be <= end");
        }
        let start_us = decimal_seconds_to_microseconds(start_secs)
            .ok_or_else(|| anyhow::anyhow!("invalid_output: start overflow"))?;
        let end_us = decimal_seconds_to_microseconds(end_secs)
            .ok_or_else(|| anyhow::anyhow!("invalid_output: end overflow"))?;
        let seg_text = get_str(seg_obj, "text")?;
        validate_item_text(seg_text)?;
        let speaker = get_str(seg_obj, "speaker")?;
        validate_id_string(speaker)?;
        distinct_speakers.insert(speaker.to_string());
        if distinct_speakers.len() > MAX_DISTINCT_SPEAKERS {
            bail!("invalid_output: more than {MAX_DISTINCT_SPEAKERS} distinct speakers");
        }
        // deny_unknown_fields for segment
        let allowed = ["type", "id", "start", "end", "text", "speaker"];
        for key in seg_obj.keys() {
            if !allowed.contains(&key.as_str()) {
                bail!("invalid_output: unknown segment member {key}");
            }
        }
        segments.push(DiarizedProviderSegment {
            id: id.to_string(),
            start_us,
            end_us,
            text: seg_text.to_string(),
            speaker: speaker.to_string(),
        });
    }

    // usage: optional duration usage
    let usage = match obj.get("usage") {
        None => TranscriptionUsageV1::NotReported,
        Some(usage) => {
            let usage_obj = usage
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage must be object"))?;
            let type_str = get_str(usage_obj, "type")?;
            if type_str != "duration" {
                bail!("invalid_output: diarized usage type must be duration");
            }
            let seconds = get_f64(usage_obj, "seconds")?;
            if !seconds.is_finite() || seconds < 0.0 {
                bail!("invalid_output: usage seconds must be finite nonnegative");
            }
            let usage_us = decimal_seconds_to_microseconds(seconds)
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage seconds overflow"))?;
            for key in usage_obj.keys() {
                if key != "type" && key != "seconds" {
                    bail!("invalid_output: unknown usage member {key}");
                }
            }
            TranscriptionUsageV1::Duration {
                duration_us: usage_us,
            }
        }
    };

    // Check for unknown root members
    for key in obj.keys() {
        match key.as_str() {
            "task" | "duration" | "text" | "segments" | "usage" => {}
            _ => bail!("invalid_output: unknown root member {key}"),
        }
    }

    Ok(DiarizedResponse {
        task: task.to_string(),
        duration_us,
        text,
        segments,
        usage,
    })
}

/// Normalize a diarized response to local diarized segments: local `id` is the
/// zero-based provider-order ordinal (capped by 50,000-item projection, checked
/// as u32), and local `speaker` is `speaker_1..N` in first-appearance order.
pub fn normalize_diarized_segments(response: &DiarizedResponse) -> Result<Vec<DiarizedSegmentV1>> {
    let speakers: Vec<Option<String>> = response
        .segments
        .iter()
        .map(|s| Some(s.speaker.clone()))
        .collect();
    let mapped = map_provider_speakers(&speakers);
    let mut result = Vec::with_capacity(response.segments.len());
    for (i, seg) in response.segments.iter().enumerate() {
        let local_id = u32::try_from(i)
            .map_err(|_| anyhow::anyhow!("invalid_output: segment ordinal overflow"))?;
        let speaker = mapped[i]
            .clone()
            .ok_or_else(|| anyhow::anyhow!("invalid_output: speaker mapping failed"))?;
        result.push(DiarizedSegmentV1::new(
            local_id,
            seg.start_us,
            seg.end_us,
            seg.text.clone(),
            speaker,
        ));
    }
    Ok(result)
}

fn validate_id_string(s: &str) -> Result<()> {
    let bytes = s.len();
    if bytes < MIN_ID_BYTES || bytes > MAX_ID_BYTES {
        bail!("invalid_output: id/speaker must be {MIN_ID_BYTES}..{MAX_ID_BYTES} UTF-8 bytes");
    }
    Ok(())
}

fn validate_item_text(s: &str) -> Result<()> {
    let scalars = s.chars().count();
    if scalars > MAX_ITEM_TEXT_SCALARS {
        bail!("invalid_output: text exceeds {MAX_ITEM_TEXT_SCALARS} scalars");
    }
    if s.len() > MAX_ITEM_TEXT_UTF8_BYTES {
        bail!("invalid_output: text exceeds {MAX_ITEM_TEXT_UTF8_BYTES} bytes");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Whisper verbose_json response
// ---------------------------------------------------------------------------

/// The decoded whisper-1 verbose_json response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhisperVerboseResponse {
    pub task: String,
    pub language: String,
    pub duration_us: u64,
    pub text: String,
    pub segments: Vec<WhisperSegment>,
    pub words: Vec<WhisperWord>,
    pub usage: TranscriptionUsageV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WhisperSegment {
    pub id: u32,
    pub seek: u32,
    pub start_us: u64,
    pub end_us: u64,
    pub text: String,
    pub tokens: Vec<u32>,
    pub temperature: f64,
    pub avg_logprob: f64,
    pub compression_ratio: f64,
    pub no_speech_prob: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhisperWord {
    pub word: String,
    pub start_us: u64,
    pub end_us: u64,
}

/// Decode a whisper-1 verbose_json response in segment mode.
pub fn decode_whisper_segments(body: &[u8]) -> Result<WhisperVerboseResponse> {
    decode_whisper(body, WhisperMode::Segment)
}

/// Decode a whisper-1 verbose_json response in word mode.
pub fn decode_whisper_words(body: &[u8]) -> Result<WhisperVerboseResponse> {
    decode_whisper(body, WhisperMode::Word)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WhisperMode {
    Segment,
    Word,
}

fn decode_whisper(body: &[u8], mode: WhisperMode) -> Result<WhisperVerboseResponse> {
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        bail!("invalid_output: response body exceeds 8 MiB");
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| anyhow::anyhow!("invalid_output: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: expected object"))?;

    let task = get_str(obj, "task")?;
    if task != "transcribe" {
        bail!("invalid_output: task must be transcribe");
    }
    let language = get_str(obj, "language")?;
    if language.is_empty() || language.len() > 64 {
        bail!("invalid_output: language must be 1..64 UTF-8 bytes");
    }
    let duration_secs = get_f64(obj, "duration")?;
    if !duration_secs.is_finite() || duration_secs < 0.0 {
        bail!("invalid_output: duration must be finite nonnegative");
    }
    let duration_us = decimal_seconds_to_microseconds(duration_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: duration overflow"))?;
    let text = get_str(obj, "text")?.to_string();

    // logprobs is forbidden
    if obj.contains_key("logprobs") {
        bail!("invalid_output: logprobs is forbidden");
    }

    let mut segments = Vec::new();
    let mut words = Vec::new();
    match mode {
        WhisperMode::Segment => {
            if obj.contains_key("words") {
                bail!("invalid_output: segment mode forbids words");
            }
            let segs = get_array(obj, "segments")?;
            if segs.len() > MAX_PROVIDER_ARRAY_MEMBERS {
                bail!("invalid_output: segments exceeds {MAX_PROVIDER_ARRAY_MEMBERS}");
            }
            let mut prev_id: Option<u32> = None;
            let mut prev_seek: Option<u32> = None;
            let mut prev_start: Option<u64> = None;
            let mut total_tokens: u64 = 0;
            for seg in segs {
                let s = decode_whisper_segment(seg, &mut total_tokens)?;
                if let Some(pid) = prev_id {
                    if s.id <= pid {
                        bail!("invalid_output: segment ids must be strictly increasing");
                    }
                }
                if let Some(ps) = prev_seek {
                    if s.seek < ps {
                        bail!("invalid_output: seeks must be nondecreasing");
                    }
                }
                if let Some(pst) = prev_start {
                    if s.start_us < pst {
                        bail!("invalid_output: starts must be nondecreasing");
                    }
                }
                prev_id = Some(s.id);
                prev_seek = Some(s.seek);
                prev_start = Some(s.start_us);
                segments.push(s);
            }
            if total_tokens > 2_000_000 {
                bail!("invalid_output: total tokens exceed 2,000,000");
            }
            // Empty arrays valid only when root text is empty
            if segments.is_empty() && !text.is_empty() {
                bail!("invalid_output: empty segments valid only with empty text");
            }
        }
        WhisperMode::Word => {
            if obj.contains_key("segments") {
                bail!("invalid_output: word mode forbids segments");
            }
            let ws = get_array(obj, "words")?;
            if ws.len() > MAX_PROVIDER_ARRAY_MEMBERS {
                bail!("invalid_output: words exceeds {MAX_PROVIDER_ARRAY_MEMBERS}");
            }
            let mut prev_start: Option<u64> = None;
            for w in ws {
                let wd = decode_whisper_word(w)?;
                if let Some(pst) = prev_start {
                    if wd.start_us < pst {
                        bail!("invalid_output: word starts must be nondecreasing");
                    }
                }
                prev_start = Some(wd.start_us);
                words.push(wd);
            }
            if words.is_empty() && !text.is_empty() {
                bail!("invalid_output: empty words valid only with empty text");
            }
        }
    }

    // usage: optional duration usage
    let usage = match obj.get("usage") {
        None => TranscriptionUsageV1::NotReported,
        Some(usage) => {
            let usage_obj = usage
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage must be object"))?;
            let type_str = get_str(usage_obj, "type")?;
            if type_str != "duration" {
                bail!("invalid_output: whisper usage type must be duration");
            }
            let seconds = get_f64(usage_obj, "seconds")?;
            if !seconds.is_finite() || seconds < 0.0 {
                bail!("invalid_output: usage seconds must be finite nonnegative");
            }
            let usage_us = decimal_seconds_to_microseconds(seconds)
                .ok_or_else(|| anyhow::anyhow!("invalid_output: usage seconds overflow"))?;
            for key in usage_obj.keys() {
                if key != "type" && key != "seconds" {
                    bail!("invalid_output: unknown usage member {key}");
                }
            }
            TranscriptionUsageV1::Duration {
                duration_us: usage_us,
            }
        }
    };

    // Check for unknown root members
    let allowed_root = match mode {
        WhisperMode::Segment => ["task", "language", "duration", "text", "segments", "usage"],
        WhisperMode::Word => ["task", "language", "duration", "text", "words", "usage"],
    };
    for key in obj.keys() {
        if !allowed_root.contains(&key.as_str()) {
            bail!("invalid_output: unknown root member {key}");
        }
    }

    Ok(WhisperVerboseResponse {
        task: task.to_string(),
        language: language.to_string(),
        duration_us,
        text,
        segments,
        words,
        usage,
    })
}

fn decode_whisper_segment(
    value: &serde_json::Value,
    total_tokens: &mut u64,
) -> Result<WhisperSegment> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: segment must be object"))?;
    let allowed = [
        "id",
        "seek",
        "start",
        "end",
        "text",
        "tokens",
        "temperature",
        "avg_logprob",
        "compression_ratio",
        "no_speech_prob",
    ];
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!("invalid_output: unknown segment member {key}");
        }
    }
    let id = get_json_u32(obj, "id")?;
    let seek = get_json_u32(obj, "seek")?;
    let start_secs = get_f64(obj, "start")?;
    let end_secs = get_f64(obj, "end")?;
    if !start_secs.is_finite() || start_secs < 0.0 {
        bail!("invalid_output: start must be finite nonnegative");
    }
    if !end_secs.is_finite() || end_secs < 0.0 {
        bail!("invalid_output: end must be finite nonnegative");
    }
    if start_secs > end_secs {
        bail!("invalid_output: start must be <= end");
    }
    let start_us = decimal_seconds_to_microseconds(start_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: start overflow"))?;
    let end_us = decimal_seconds_to_microseconds(end_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: end overflow"))?;
    let text = get_str(obj, "text")?;
    validate_item_text(text)?;
    let tokens_arr = get_array(obj, "tokens")?;
    if tokens_arr.len() > 65_536 {
        bail!("invalid_output: segment tokens exceed 65,536");
    }
    let mut tokens = Vec::with_capacity(tokens_arr.len());
    for t in tokens_arr {
        let tn = t
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid_output: token must be integer"))?;
        if tn > u32::MAX as u64 {
            bail!("invalid_output: token exceeds u32::MAX");
        }
        *total_tokens = total_tokens
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("invalid_output: token count overflow"))?;
        tokens.push(tn as u32);
    }
    let temperature = get_f64(obj, "temperature")?;
    if !temperature.is_finite() || temperature < 0.0 || temperature > 1.0 {
        bail!("invalid_output: temperature must be finite in [0,1]");
    }
    let avg_logprob = get_f64(obj, "avg_logprob")?;
    if !avg_logprob.is_finite() || avg_logprob < -1_000_000.0 || avg_logprob > 0.0 {
        bail!("invalid_output: avg_logprob must be finite in [-1000000,0]");
    }
    let compression_ratio = get_f64(obj, "compression_ratio")?;
    if !compression_ratio.is_finite() || compression_ratio < 0.0 || compression_ratio > 1_000_000.0
    {
        bail!("invalid_output: compression_ratio must be finite in [0,1000000]");
    }
    let no_speech_prob = get_f64(obj, "no_speech_prob")?;
    if !no_speech_prob.is_finite() || no_speech_prob < 0.0 || no_speech_prob > 1.0 {
        bail!("invalid_output: no_speech_prob must be finite in [0,1]");
    }
    Ok(WhisperSegment {
        id,
        seek,
        start_us,
        end_us,
        text: text.to_string(),
        tokens,
        temperature,
        avg_logprob,
        compression_ratio,
        no_speech_prob,
    })
}

fn decode_whisper_word(value: &serde_json::Value) -> Result<WhisperWord> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid_output: word must be object"))?;
    let allowed = ["word", "start", "end"];
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!("invalid_output: unknown word member {key}");
        }
    }
    let word = get_str(obj, "word")?;
    validate_item_text(word)?;
    let start_secs = get_f64(obj, "start")?;
    let end_secs = get_f64(obj, "end")?;
    if !start_secs.is_finite() || start_secs < 0.0 {
        bail!("invalid_output: start must be finite nonnegative");
    }
    if !end_secs.is_finite() || end_secs < 0.0 {
        bail!("invalid_output: end must be finite nonnegative");
    }
    if start_secs > end_secs {
        bail!("invalid_output: start must be <= end");
    }
    let start_us = decimal_seconds_to_microseconds(start_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: start overflow"))?;
    let end_us = decimal_seconds_to_microseconds(end_secs)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: end overflow"))?;
    Ok(WhisperWord {
        word: word.to_string(),
        start_us,
        end_us,
    })
}

fn get_json_u32(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u32> {
    let v = obj
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: missing {key}"))?;
    // Must be a mathematical JSON integer (not a numeric string)
    if v.is_i64() {
        let n = v.as_i64().unwrap();
        if n < 0 || n > u32::MAX as i64 {
            bail!("invalid_output: {key} out of u32 range");
        }
        return Ok(n as u32);
    }
    if v.is_u64() {
        let n = v.as_u64().unwrap();
        if n > u32::MAX as u64 {
            bail!("invalid_output: {key} out of u32 range");
        }
        return Ok(n as u32);
    }
    bail!("invalid_output: {key} must be integer");
}
