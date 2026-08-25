//! The `transcribe_audio` runtime tool.
//!
//! Transcribes one authorized audio source through the external
//! audio-transcription contract ([`crate::audio_transcription`]): pure caller
//! validation, feature-driven model selection, Whisper prompt preflight, the
//! secret-free `MediaEgress` authorization chokepoint, and multipart egress.
//!
//! Like every other media tool in this repository, source bytes come *only*
//! from typed session normalized derivatives via the attachment authority. That
//! authority is not yet exposed here (see [`crate::tools::audio_video`]), so the
//! tool validates its closed arguments, selects the model, and runs the Whisper
//! preflight gate, then **fails closed** at the attachment-authority boundary
//! with `media_attachment_authority_unavailable` — never opening a
//! model-supplied path itself and never contacting a provider. When the
//! attachment authority lands, the resolved normalized bytes + checksum feed a
//! [`crate::audio_transcription::authorization::MediaEgressTranscriptionRequest`],
//! which routes through [`crate::approval::Approver`] before any egress.

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::audio_transcription::request::{
    CallerTimestamps, TranscriptionModel, validate_diarize_languages, validate_gpt_languages,
    validate_keywords, validate_prompt, validate_whisper_languages,
};
use crate::audio_transcription::result::TimestampsKind;
use crate::audio_transcription::whisper_preflight::{
    WhisperPreflightOutcome, verify_whisper_tokenizer_digest, whisper_prompt_preflight,
};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

/// The nested `source` union shared with the other media tools: exactly one of
/// `{attachment_id} | {path} | {url}` on the first call; later calls reuse
/// `{attachment_id}`.
fn source_schema() -> Value {
    json!({
        "anyOf": [
            {
                "type": "object",
                "properties": { "attachment_id": { "type": "string", "minLength": 1 } },
                "required": ["attachment_id"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": { "path": { "type": "string", "minLength": 1 } },
                "required": ["path"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": { "url": { "type": "string", "pattern": "^https://" } },
                "required": ["url"],
                "additionalProperties": false
            }
        ]
    })
}

/// The closed argument schema. Timestamps and diarization are mutually
/// exclusive at the model-selection layer, not the schema layer, so the
/// unsupported combination returns a precise `invalid_input` error.
fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "source": source_schema(),
            "start": { "type": "number", "minimum": 0, "multipleOf": 0.001 },
            "end": { "type": "number", "exclusiveMinimum": 0, "multipleOf": 0.001 },
            "prompt": { "type": "string" },
            "keywords": {
                "type": "array",
                "items": { "type": "string" },
                "maxItems": 64
            },
            "languages": {
                "type": "array",
                "items": { "type": "string" },
                "maxItems": 16
            },
            "timestamps": { "enum": ["off", "segment", "word"] },
            "diarization": { "type": "boolean" }
        },
        "required": ["source"],
        "additionalProperties": false
    })
}

fn validate_args(args: &Value) -> Result<()> {
    let compiled = schema();
    let validator =
        jsonschema::validator_for(&compiled).map_err(|error| invalid_input(error.to_string()))?;
    validator
        .validate(args)
        .map_err(|error| invalid_input(error.to_string()))
}

/// Parse the requested timestamp mode (defaulting to `off`).
fn parse_timestamps(args: &Value) -> Result<CallerTimestamps> {
    match args.get("timestamps").and_then(|v| v.as_str()) {
        None | Some("off") => Ok(CallerTimestamps::Off),
        Some("segment") => Ok(CallerTimestamps::Segment),
        Some("word") => Ok(CallerTimestamps::Word),
        Some(other) => Err(invalid_input(format!("unknown timestamps mode `{other}`"))),
    }
}

/// Collect a string-array argument into an owned `Vec<String>`. The shape
/// validator has already guaranteed the values are strings; any non-string is
/// skipped defensively rather than silently coerced.
fn collect_string_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn caller_timestamps_to_kind(ts: CallerTimestamps) -> TimestampsKind {
    match ts {
        CallerTimestamps::Off => TimestampsKind::Off,
        CallerTimestamps::Segment => TimestampsKind::Segment,
        CallerTimestamps::Word => TimestampsKind::Word,
    }
}

pub struct TranscribeAudioTool;

#[async_trait]
impl Tool for TranscribeAudioTool {
    fn name(&self) -> &str {
        "transcribe_audio"
    }

    fn description(&self) -> &str {
        "Transcribe one authorized audio source to text via an external transcription provider. First call uses source: {attachment_id|path|url}; later calls reuse source: {attachment_id}. Optional prompt, keywords, languages, timestamps, and diarization select the model."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Transcribe a single authorized audio source with an external transcription provider, returning a normalized transcript. First call uses source: {attachment_id|path|url} and reuses a typed session attachment; later calls reuse source: {attachment_id}. Model selection is feature-driven: plain text uses gpt-transcribe, timestamps use whisper-1, and diarization uses gpt-4o-transcribe-diarize; requesting timestamps and diarization together is rejected. Every dispatch first authorizes an exact secret-free MediaEgress request digest, and the source must be admitted by the session attachment authority — the tool never opens a model-supplied path itself and never sends caller transcript history as the provider prompt."
                .into(),
        )
    }

    fn effect(&self) -> ToolEffect {
        // Egresses audio to a provider and produces a derivative transcript.
        ToolEffect::Mutating
    }

    fn parameters(&self) -> Value {
        schema()
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        validate_args(&args)?;

        // Feature-driven model selection. This surfaces the unsupported
        // timestamps+diarization combination as a precise error before any
        // reservation or provider contact.
        let timestamps = parse_timestamps(&args)?;
        let diarization = args
            .get("diarization")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let model = TranscriptionModel::select(caller_timestamps_to_kind(timestamps), diarization)
            .map_err(|error| invalid_input(error.to_string()))?;

        // Collect the raw caller inputs from the (shape-validated) args.
        let prompt_raw = args.get("prompt").and_then(|v| v.as_str());
        let keywords_raw = collect_string_array(&args, "keywords");
        let languages_raw = collect_string_array(&args, "languages");

        // Run the module's real caller-context validators per selected model,
        // BEFORE any authorization or egress. These reject oversized prompts,
        // forbidden keyword bytes, duplicate/unlisted languages, and
        // model-specific language-count and unsupported-field violations. Every
        // validator message is caller-derived and secret-free.
        match model {
            TranscriptionModel::GptTranscribe => {
                if let Some(prompt) = prompt_raw {
                    validate_prompt(prompt).map_err(|error| invalid_input(error.to_string()))?;
                }
                validate_keywords(&keywords_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                validate_gpt_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
            }
            TranscriptionModel::Whisper1 => {
                if !keywords_raw.is_empty() {
                    return Err(invalid_input(
                        "whisper-1 does not accept keywords".to_string(),
                    ));
                }
                validate_whisper_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                if let Some(prompt) = prompt_raw {
                    validate_prompt(prompt).map_err(|error| invalid_input(error.to_string()))?;
                }
            }
            TranscriptionModel::Gpt4oTranscribeDiarize => {
                if prompt_raw.is_some() {
                    return Err(invalid_input(
                        "diarization does not accept a prompt".to_string(),
                    ));
                }
                if !keywords_raw.is_empty() {
                    return Err(invalid_input(
                        "diarization does not accept keywords".to_string(),
                    ));
                }
                validate_diarize_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
            }
        }

        // Whisper preflight gate. The tokenizer-DATA digest pin ALWAYS runs for
        // a Whisper-model request (gating egress) regardless of whether a prompt
        // is supplied; the 224-token prompt count is only meaningful when a
        // prompt is present. Both fail closed with zero provider contact.
        if model == TranscriptionModel::Whisper1 {
            if verify_whisper_tokenizer_digest().is_err() {
                bail!(
                    "transcription_unavailable: the pinned Whisper tokenizer data did not verify"
                );
            }
            if let Some(prompt) = prompt_raw {
                match whisper_prompt_preflight(prompt) {
                    WhisperPreflightOutcome::Ok { .. } => {}
                    WhisperPreflightOutcome::TooLong { token_count } => {
                        bail!(
                            "transcription_prompt_too_long: prompt is {token_count} Whisper tokens, over the 224-token limit"
                        );
                    }
                    WhisperPreflightOutcome::Unavailable { .. } => {
                        bail!(
                            "transcription_unavailable: the pinned Whisper tokenizer data did not verify"
                        );
                    }
                }
            }
        }

        // Source bytes come only from typed session normalized derivatives via
        // the attachment authority, which this repository does not yet expose.
        // Fail closed here — before any MediaEgress authorization or provider
        // contact — exactly like the sibling media tools.
        bail!(
            "media_attachment_authority_unavailable: this repository does not yet expose the typed session attachment authority required for safe audio-transcription egress"
        )
    }
}
