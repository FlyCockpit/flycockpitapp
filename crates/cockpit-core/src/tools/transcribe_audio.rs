//! The `transcribe_audio` runtime tool.
//!
//! Transcribes one authorized audio source through the external
//! audio-transcription contract ([`crate::audio_transcription`]): pure caller
//! validation, feature-driven model selection, Whisper prompt preflight, the
//! secret-free `MediaEgress` authorization chokepoint, journaled multipart
//! egress, and a normalized result. Source bytes come only from typed session
//! normalized derivatives via [`crate::tool_media_authority::SessionMediaAuthority`].
//! Stripped MCP/Monty/catalog contexts have no authority and fail closed
//! before reservation, journal, authorization, or send.

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest as Sha256Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::audio_transcription::authorization::{
    MediaEgressTranscriptionRequest, TranscriptionPurpose,
};
use crate::audio_transcription::journal::TranscriptionHandoff;
use crate::audio_transcription::request::{
    CallerTimestamps, MAX_FILE_BYTES, MIN_FILE_BYTES, TranscriptionModel,
    plan_gpt_4o_transcribe_diarize, plan_gpt_transcribe, plan_whisper_1,
    validate_diarize_languages, validate_gpt_languages, validate_keywords, validate_prompt,
    validate_whisper_languages,
};
use crate::audio_transcription::response::{
    decode_diarized, decode_gpt_transcribe, decode_whisper_segments, decode_whisper_words,
};
use crate::audio_transcription::result::{
    DiarizationV1, DiarizedSegmentV1, NormalizedTranscriptionResultV1,
    SEGMENT_PROJECTION_MAX_ITEMS, TimestampsKind, TimestampsV1, TranscriptSegmentV1,
    TranscriptWordV1, TranscriptionContentV1, TranscriptionProvenanceV1, TranscriptionUsageV1,
    map_provider_speakers, project_text, requested_to_applied, validate_content_timestamps,
};
use crate::audio_transcription::whisper_preflight::{
    WhisperPreflightOutcome, verify_whisper_tokenizer_digest, whisper_prompt_preflight,
};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::external_journal::projection::{Digest, SafeToken};
use crate::media_reservation::{MediaOwner, ReserveRequest};
use crate::tool_media_authority::AdmittedHandle;
use crate::tool_media_authority::session_authority::AdmissionDenial;

const RESULT_SCHEMA_VERSION: u8 = 1;

/// Transcription currently accepts only a session attachment. This is the only
/// source kind backed by an authoritative normalized derivative and duration.
fn source_schema() -> Value {
    json!({
        "type": "object",
        "properties": { "attachment_id": { "type": "string", "minLength": 1 } },
        "required": ["attachment_id"],
        "additionalProperties": false
    })
}

fn interval_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "start_us": { "type": "integer", "minimum": 0 },
            "end_us": { "type": "integer", "minimum": 1 }
        },
        "required": ["start_us", "end_us"],
        "additionalProperties": false
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
            "interval": interval_schema(),
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

enum SourceArg {
    AttachmentId(String),
}

fn parse_source(args: &Value) -> Result<SourceArg> {
    let source = args
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_input("source is required"))?;
    let attachment_id = source.get("attachment_id").and_then(Value::as_str);
    attachment_id
        .map(|id| SourceArg::AttachmentId(id.to_string()))
        .ok_or_else(|| invalid_input("source must contain attachment_id"))
}

fn parse_interval(args: &Value) -> Result<Option<(u64, u64)>> {
    let Some(interval) = args.get("interval") else {
        return Ok(None);
    };
    let start = interval
        .get("start_us")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_input("interval.start_us must be a non-negative integer"))?;
    let end = interval
        .get("end_us")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_input("interval.end_us must be a positive integer"))?;
    if start >= end {
        return Err(invalid_input(
            "interval.start_us must be less than interval.end_us",
        ));
    }
    Ok(Some((start, end)))
}

fn parse_attachment_id_bytes(raw: &str) -> Result<[u8; 16]> {
    if let Ok(uuid) = Uuid::parse_str(raw) {
        return Ok(*uuid.as_bytes());
    }
    let mut out = [0u8; 16];
    if raw.len() != 32 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_input(
            "attachment_id must be a UUID or 32 lowercase hex characters",
        ));
    }
    for (i, chunk) in raw.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).unwrap_or("00");
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| invalid_input("attachment_id is not valid hex"))?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn admit_source(
    authority: &crate::tool_media_authority::SessionMediaAuthority,
    session_hex: &str,
    source: &SourceArg,
) -> Result<AdmittedHandle> {
    let result = match source {
        SourceArg::AttachmentId(id) => {
            let bytes = parse_attachment_id_bytes(id)?;
            authority
                .resolve_attachment(session_hex, &bytes)
                .map(AdmittedHandle::Attachment)
        }
    };
    result.map_err(|denial| match denial {
        AdmissionDenial::NoAuthority | AdmissionDenial::SubjectMismatch => {
            anyhow::anyhow!(
                "media_attachment_authority_unavailable: the session media authority rejected this source"
            )
        }
        AdmissionDenial::AttachmentNotFound => {
            invalid_input("attachment not found")
        }
        other => anyhow::anyhow!("media_attachment_authority_unavailable: {other}"),
    })
}

fn handle_identity(handle: &AdmittedHandle) -> (String, String, u64) {
    match handle {
        AdmittedHandle::Attachment(att) => (
            Uuid::from_bytes(att.attachment_id())
                .hyphenated()
                .to_string(),
            hex_encode(&att.checksum()),
            att.attachment_version(),
        ),
        AdmittedHandle::Local(_) | AdmittedHandle::RetainedHttps(_) => {
            unreachable!("the closed transcription source schema admits attachments only")
        }
    }
}

fn normalize_body(
    model: TranscriptionModel,
    timestamps: CallerTimestamps,
    diarization: bool,
    languages: &[crate::audio_transcription::result::RequestedLanguageV1],
    body: &[u8],
    provenance: TranscriptionProvenanceV1,
    authorized_duration_us: u64,
) -> Result<NormalizedTranscriptionResultV1> {
    let requested_kind = caller_timestamps_to_kind(timestamps);
    let applied_languages: Vec<_> = languages.iter().map(requested_to_applied).collect();
    let mut provider_duration_us = None;
    let (text, mut content, detected, usage) = match model {
        TranscriptionModel::GptTranscribe => {
            let decoded = decode_gpt_transcribe(body)?;
            (
                decoded.text.clone(),
                TranscriptionContentV1::Plain {
                    text: decoded.text.clone(),
                },
                decoded.detected_languages,
                decoded.usage,
            )
        }
        TranscriptionModel::Whisper1 => match timestamps {
            CallerTimestamps::Segment => {
                let decoded = decode_whisper_segments(body)?;
                provider_duration_us = Some(decoded.duration_us);
                let items = decoded
                    .segments
                    .iter()
                    .map(|seg| TranscriptSegmentV1 {
                        id: seg.id,
                        start_us: seg.start_us,
                        end_us: seg.end_us,
                        text: seg.text.clone(),
                    })
                    .collect();
                (
                    decoded.text.clone(),
                    TranscriptionContentV1::Segments { items },
                    Vec::new(),
                    decoded.usage,
                )
            }
            CallerTimestamps::Word => {
                let decoded = decode_whisper_words(body)?;
                provider_duration_us = Some(decoded.duration_us);
                let items = decoded
                    .words
                    .iter()
                    .map(|word| TranscriptWordV1 {
                        word: word.word.clone(),
                        start_us: word.start_us,
                        end_us: word.end_us,
                    })
                    .collect();
                (
                    decoded.text.clone(),
                    TranscriptionContentV1::Words { items },
                    Vec::new(),
                    decoded.usage,
                )
            }
            CallerTimestamps::Off => {
                bail!("whisper-1 requires segment or word timestamps")
            }
        },
        TranscriptionModel::Gpt4oTranscribeDiarize => {
            let decoded = decode_diarized(body)?;
            provider_duration_us = Some(decoded.duration_us);
            let speaker_codes: Vec<Option<String>> = decoded
                .segments
                .iter()
                .map(|seg| Some(seg.speaker.clone()))
                .collect();
            let mapped = map_provider_speakers(&speaker_codes);
            let items = decoded
                .segments
                .iter()
                .zip(mapped)
                .enumerate()
                .map(|(index, (seg, speaker))| {
                    DiarizedSegmentV1::new(
                        index as u32,
                        seg.start_us,
                        seg.end_us,
                        seg.text.clone(),
                        speaker.unwrap_or_else(|| "speaker_1".to_string()),
                    )
                })
                .collect();
            (
                decoded.text.clone(),
                TranscriptionContentV1::Diarized {
                    duration_us: decoded.duration_us,
                    items,
                },
                Vec::new(),
                decoded.usage,
            )
        }
    };
    let authorized_end_with_tolerance = authorized_duration_us
        .checked_add(1_000)
        .ok_or_else(|| anyhow::anyhow!("invalid_output: authorized interval overflow"))?;
    if provider_duration_us.is_some_and(|duration| duration > authorized_end_with_tolerance) {
        bail!("invalid_output: provider duration exceeds the authorized interval by more than 1ms");
    }
    let validate_interval = |start_us: u64, end_us: u64| -> Result<()> {
        if start_us > authorized_end_with_tolerance || end_us > authorized_end_with_tolerance {
            bail!(
                "invalid_output: provider timestamp exceeds the authorized interval by more than 1ms"
            );
        }
        Ok(())
    };
    match &content {
        TranscriptionContentV1::Segments { items } => {
            for item in items {
                validate_interval(item.start_us, item.end_us)?;
            }
        }
        TranscriptionContentV1::Words { items } => {
            for item in items {
                validate_interval(item.start_us, item.end_us)?;
            }
        }
        TranscriptionContentV1::Diarized { duration_us, items } => {
            if *duration_us > authorized_end_with_tolerance {
                bail!(
                    "invalid_output: provider duration exceeds the authorized interval by more than 1ms"
                );
            }
            for item in items {
                validate_interval(item.start_us, item.end_us)?;
            }
        }
        TranscriptionContentV1::Plain { .. } => {}
    }
    if let TranscriptionUsageV1::Duration { duration_us } = &usage
        && *duration_us > authorized_end_with_tolerance
    {
        bail!(
            "invalid_output: provider usage duration exceeds the authorized interval by more than 1ms"
        );
    }

    let mut projected = project_text(&text);
    match &mut content {
        TranscriptionContentV1::Segments { items } => {
            projected.omitted_segments =
                items.len().saturating_sub(SEGMENT_PROJECTION_MAX_ITEMS) as u64;
            items.truncate(SEGMENT_PROJECTION_MAX_ITEMS);
        }
        TranscriptionContentV1::Words { items } => {
            projected.omitted_words =
                items.len().saturating_sub(SEGMENT_PROJECTION_MAX_ITEMS) as u64;
            items.truncate(SEGMENT_PROJECTION_MAX_ITEMS);
        }
        TranscriptionContentV1::Diarized { items, .. } => {
            projected.omitted_segments =
                items.len().saturating_sub(SEGMENT_PROJECTION_MAX_ITEMS) as u64;
            items.truncate(SEGMENT_PROJECTION_MAX_ITEMS);
        }
        TranscriptionContentV1::Plain { .. } => {}
    }
    projected.complete &= projected.omitted_segments == 0 && projected.omitted_words == 0;
    let timestamps_pair = TimestampsV1 {
        requested: requested_kind,
        applied: requested_kind,
    };
    let diarization_pair = DiarizationV1 {
        requested: diarization,
        applied: diarization,
    };
    validate_content_timestamps(&content, &timestamps_pair, &diarization_pair)
        .map_err(|error| anyhow::anyhow!("invalid_output: {error}"))?;
    Ok(NormalizedTranscriptionResultV1 {
        schema_version: RESULT_SCHEMA_VERSION,
        text: projected.text,
        content,
        requested_languages: languages.to_vec(),
        applied_languages,
        detected_languages: detected,
        timestamps: timestamps_pair,
        diarization: diarization_pair,
        usage,
        provenance,
        complete: projected.complete,
        omitted_text_scalars: projected.omitted_text_scalars,
        omitted_text_utf8_bytes: projected.omitted_text_utf8_bytes,
        omitted_segments: projected.omitted_segments,
        omitted_words: projected.omitted_words,
    })
}

pub struct TranscribeAudioTool;

#[async_trait]
impl Tool for TranscribeAudioTool {
    fn name(&self) -> &str {
        "transcribe_audio"
    }

    fn description(&self) -> &str {
        "Transcribe one authorized audio session attachment via an external provider."
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Transcribe a single authorized audio session attachment with an external transcription provider, returning a normalized transcript. The closed source shape is {attachment_id}; path and URL sources are not supported until they have authoritative normalized derivatives and durations. Model selection is feature-driven: plain text uses gpt-transcribe, timestamps use whisper-1, and diarization uses gpt-4o-transcribe-diarize; requesting timestamps and diarization together is rejected. Every dispatch first authorizes an exact secret-free MediaEgress request digest, and the source must be admitted by the session attachment authority — the tool never opens a model-supplied path itself and never sends caller transcript history as the provider prompt."
                .into(),
        )
    }

    fn effect(&self) -> ToolEffect {
        // Egresses audio to a provider and produces a derivative transcript.
        ToolEffect::Mutating
    }

    fn honors_dispatch_cancel(&self) -> bool {
        true
    }

    fn parameters(&self) -> Value {
        schema()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        validate_args(&args)?;

        let timestamps = parse_timestamps(&args)?;
        let diarization = args
            .get("diarization")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let model = TranscriptionModel::select(caller_timestamps_to_kind(timestamps), diarization)
            .map_err(|error| invalid_input(error.to_string()))?;

        let prompt_raw = args.get("prompt").and_then(|v| v.as_str());
        let keywords_raw = collect_string_array(&args, "keywords");
        let languages_raw = collect_string_array(&args, "languages");

        let (prompt, keywords, languages) = match model {
            TranscriptionModel::GptTranscribe => {
                let prompt = if let Some(prompt) = prompt_raw {
                    validate_prompt(prompt).map_err(|error| invalid_input(error.to_string()))?
                } else {
                    None
                };
                let keywords = validate_keywords(&keywords_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                let languages = validate_gpt_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                (prompt, keywords, languages)
            }
            TranscriptionModel::Whisper1 => {
                if !keywords_raw.is_empty() {
                    return Err(invalid_input(
                        "whisper-1 does not accept keywords".to_string(),
                    ));
                }
                let languages = validate_whisper_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                let prompt = if let Some(prompt) = prompt_raw {
                    validate_prompt(prompt).map_err(|error| invalid_input(error.to_string()))?
                } else {
                    None
                };
                (prompt, Vec::new(), languages)
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
                let languages = validate_diarize_languages(&languages_raw)
                    .map_err(|error| invalid_input(error.to_string()))?;
                (None, Vec::new(), languages)
            }
        };

        if model == TranscriptionModel::Whisper1 {
            if verify_whisper_tokenizer_digest().is_err() {
                bail!(
                    "transcription_unavailable: the pinned Whisper tokenizer data did not verify"
                );
            }
            if let Some(prompt) = prompt.as_deref() {
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

        let Some(authority) = ctx.media_authority() else {
            bail!(
                "media_attachment_authority_unavailable: stripped MCP/Monty/catalog contexts cannot transcribe audio"
            );
        };

        // SessionMediaAuthority compares this against the receipt's UUID using
        // UUID's canonical, hyphenated spelling. Do not invent a second token
        // representation here: that would make every live admission fail.
        let session_id = ctx.session.id.hyphenated().to_string();
        let source = parse_source(&args)?;
        let requested_interval = parse_interval(&args)?;
        let handle = admit_source(authority, &session_id, &source)?;
        let AdmittedHandle::Attachment(attachment) = &handle else {
            unreachable!("the closed transcription source schema admits attachments only");
        };
        if attachment.kind() != cockpit_db::media_attachments::MediaKind::Audio.code() {
            return Err(invalid_input("attachment is not audio"));
        }
        let admitted = authority
            .read_media_interval(&handle, requested_interval, MAX_FILE_BYTES)
            .await
            .map_err(|error| anyhow::anyhow!("media_attachment_authority_unavailable: {error}"))?;
        let audio = &admitted.bytes;
        let derivative_duration_us = admitted.duration_us.ok_or_else(|| anyhow::anyhow!(
            "media_attachment_authority_unavailable: source has no authoritative normalized-derivative duration"
        ))?;
        let (interval_start_us, interval_end_us) =
            requested_interval.unwrap_or((0, derivative_duration_us));
        let file_bytes = audio.len() as u64;
        if file_bytes < MIN_FILE_BYTES {
            return Err(invalid_input("audio source is empty"));
        }
        if file_bytes > MAX_FILE_BYTES {
            return Err(invalid_input("audio source exceeds the 25 MiB file cap"));
        }

        let (attachment_id, attachment_checksum, attachment_version) = handle_identity(&handle);
        // The authority verifies the retained normalized component against the
        // attachment checksum before minting this (possibly sliced)
        // derivative. A slice intentionally does not equal the source digest.

        let Some(dispatch) = ctx.transcription_dispatch.clone() else {
            bail!(
                "transcription_egress_unavailable: no journaled transcription transport is wired for this session"
            );
        };
        let Some(approver) = ctx.approver.as_ref() else {
            bail!("transcription_unavailable: authorization is unavailable in this session");
        };

        let identity = dispatch.identity();
        let provider_id = identity.provider_id.clone();
        let origin = identity.origin.clone();
        let resolved_location = identity.resolved_location.clone();
        let credential_fingerprint = identity.credential_fingerprint.clone();
        let endpoint_config_generation = identity.endpoint_config_generation;
        let request = MediaEgressTranscriptionRequest {
            provider_id: provider_id.clone(),
            model_id: model.as_str().to_string(),
            credential_fingerprint_digest: credential_fingerprint.clone(),
            origin: origin.clone(),
            resolved_location,
            project_digest: sha256_hex(ctx.session.project_id.as_bytes()),
            session_id: ctx.session.id.hyphenated().to_string(),
            attachment_id: attachment_id.clone(),
            attachment_checksum: attachment_checksum.clone(),
            interval_start_us,
            interval_end_us,
            prompt_bytes: prompt.as_deref().unwrap_or("").as_bytes().to_vec(),
            keywords: keywords.clone(),
            languages: languages.clone(),
            timestamps: caller_timestamps_to_kind(timestamps),
            diarization,
            purpose: TranscriptionPurpose::Transcription,
        };
        let request_digest = request.digest();
        match request.authorize(approver).await? {
            crate::approval::Decision::Allow { .. } => {}
            crate::approval::Decision::Deny
            | crate::approval::Decision::StandingReject { .. }
            | crate::approval::Decision::NoninteractiveDeny => {
                bail!("transcription_denied: media egress was not authorized");
            }
        }

        let duration_ms = interval_end_us
            .checked_sub(interval_start_us)
            .and_then(|duration| duration.checked_add(999))
            .and_then(|duration| duration.checked_div(1_000))
            .filter(|duration| *duration > 0)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "media_attachment_authority_unavailable: invalid derivative duration"
                )
            })?;
        let Some(media_ledger) = ctx.session.media_reservation_ledger() else {
            bail!(
                "media_reservation_unavailable: transcription requires the daemon media reservation ledger"
            );
        };
        let media_policy = &ctx.config.extended().media_resources;
        let evaluated = |dimension, requested| {
            media_policy
                .evaluate(
                    cockpit_config::config::media_budget::MediaEvaluationRequest {
                        dimension,
                        requested: Some(requested),
                        current_scope: 0,
                        profile: None,
                        adapter_limit: None,
                        request_limit: None,
                    },
                )
                .map_err(|denial| anyhow::anyhow!("media_reservation_denied: {denial:?}"))
        };
        use cockpit_config::config::media_budget::MediaDimension;
        let outbound_plan = evaluated(MediaDimension::OutboundSubmissionsGlobal, 1)?;
        let invocation_plan = evaluated(MediaDimension::TranscriptionInvocationsPerSession, 1)?;
        let configured_deadline =
            media_policy.configured_limit(MediaDimension::OperationDeadlineSeconds);
        let deadline_plan = evaluated(
            MediaDimension::OperationDeadlineSeconds,
            configured_deadline,
        )?;
        // Unique per attempt: a digest-keyed Released row cannot be recycled,
        // so cancel-before-ticket and failed-handoff cleanup of this call must
        // not occupy the identity that a later uncancelled retry will reserve.
        let reservation_id = format!(
            "transcription-{}:{}",
            request_digest.as_str(),
            Uuid::new_v4().hyphenated()
        );
        let reserve_request = ReserveRequest {
            reservation_id: reservation_id.clone(),
            recovery_id: format!("recovery-{reservation_id}"),
            owner: MediaOwner {
                project_id: ctx.session.project_id.clone(),
                session_id: ctx.session.id.hyphenated().to_string(),
            },
            operation: "transcribe_audio".to_string(),
            purpose: "transcription".to_string(),
            plans: vec![
                outbound_plan.clone(),
                invocation_plan.clone(),
                deadline_plan,
            ],
            wall_ms: u64::try_from(chrono::Utc::now().timestamp_millis())?,
        };
        let owner = SafeToken::for_session(ctx.session.id);
        let idempotency_key = SafeToken::parse(request_digest.as_str()).map_err(|error| {
            anyhow::anyhow!("transcription_unavailable: idempotency key: {error}")
        })?;
        let source_digest = Digest::of(audio);
        let prompt_ref = prompt.clone();
        let keywords_ref = keywords.clone();
        let languages_ref = languages.clone();
        let build = move |boundary: &str| match model {
            TranscriptionModel::GptTranscribe => plan_gpt_transcribe(
                file_bytes,
                prompt_ref.as_deref(),
                &keywords_ref,
                &languages_ref,
                boundary,
            ),
            TranscriptionModel::Whisper1 => plan_whisper_1(
                file_bytes,
                timestamps,
                languages_ref.first(),
                prompt_ref.as_deref(),
                boundary,
            ),
            TranscriptionModel::Gpt4oTranscribeDiarize => plan_gpt_4o_transcribe_diarize(
                file_bytes,
                Some(duration_ms),
                languages_ref.first(),
                boundary,
            ),
        };
        let now_wall_ms = chrono::Utc::now().timestamp_millis();
        // Child of the turn token: user cancel still fires it, but dispatcher
        // timeout must not cancel the whole turn. Drop of this tool future
        // (timeout/abandon) cancels the child so a detached send cannot record
        // `succeeded` after the caller has been told the tool was abandoned.
        let dispatch_cancel = ctx.cancel.child_token();
        struct CancelOnAbandon(CancellationToken);
        impl Drop for CancelOnAbandon {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let _abandon = CancelOnAbandon(dispatch_cancel.clone());
        let cancel = dispatch_cancel;
        // The owned task is the durable outcome recorder. If the outer tool
        // dispatcher reaches its cancellation/timeout grace and drops this
        // await, Tokio detaches the task; it continues the journal terminal
        // transition instead of stranding a possibly submitted operation.
        let handoff = tokio::spawn(async move {
            let mut boundaries = std::iter::from_fn(|| Some(Uuid::new_v4().as_u128()));
            let handoff = dispatch
                .dispatch_reserved(
                    &media_ledger,
                    reserve_request,
                    vec![outbound_plan, invocation_plan],
                    &owner,
                    &idempotency_key,
                    source_digest,
                    duration_ms,
                    now_wall_ms,
                    admitted.bytes.as_slice(),
                    &mut boundaries,
                    build,
                    &cancel,
                )
                .await;
            // The lease covers the whole authorization-to-terminal handoff.
            // This owned task remains alive if the outer tool future is
            // cancelled, so a durable dispatch cannot strand the retained
            // component lease.
            let release = admitted
                .release_retained(chrono::Utc::now().timestamp_millis())
                .await;
            match (handoff, release) {
                (Ok(handoff), Ok(())) => Ok(handoff),
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(anyhow::anyhow!(
                    "releasing retained transcription media lease failed: {error}"
                )),
            }
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!("transcription_unavailable: dispatch task failed: {error}")
        })?
        .map_err(|error| anyhow::anyhow!("transcription_unavailable: {error}"))?;

        match handoff {
            TranscriptionHandoff::Succeeded { operation_id, body } => {
                let provenance = TranscriptionProvenanceV1 {
                    attachment_id,
                    attachment_version,
                    attachment_checksum,
                    interval_start_us,
                    interval_end_us,
                    session_id: ctx.session.id.hyphenated().to_string(),
                    canonical_project_digest: sha256_hex(ctx.session.project_id.as_bytes()),
                    provider_id,
                    endpoint_identity_digest: sha256_hex(origin.as_bytes()),
                    endpoint_config_generation,
                    model_id: model.as_str().to_string(),
                    credential_fingerprint_digest: credential_fingerprint.as_str().to_string(),
                    transcription_request_digest: request_digest.as_str().to_string(),
                    external_operation_id: operation_id.hyphenated().to_string(),
                    external_attempt_number: 1,
                };
                let result = normalize_body(
                    model,
                    timestamps,
                    diarization,
                    &languages,
                    &body,
                    provenance,
                    interval_end_us - interval_start_us,
                )?;
                let json = serde_json::to_string(&result)?;
                Ok(ToolOutput::text(json))
            }
            TranscriptionHandoff::Cancelled { .. } => {
                bail!("transcription_cancelled: the operation was cancelled before dispatch")
            }
            TranscriptionHandoff::CompletedAfterCancel { .. } => {
                bail!(
                    "transcription_cancelled: the provider completed after cancel; content was discarded"
                )
            }
            TranscriptionHandoff::AlreadyCompleted { .. } => {
                bail!("transcription_already_completed: provider content is not replayable")
            }
            TranscriptionHandoff::Failed { reason, .. } => {
                bail!("{reason}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio_transcription::authorization::CredentialFingerprintDigest;
    use crate::audio_transcription::dispatch::{
        TranscriptionEgressError, TranscriptionEgressTransport, TranscriptionHttpResponse,
    };
    use crate::audio_transcription::journal::{
        TranscriptionDestinationIdentity, TranscriptionDispatchService,
    };
    use crate::external_journal::ExternalJournal;
    use crate::tool_media_authority::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
    use crate::tool_media_authority::revalidator::RevalidatedSubject;
    use crate::tool_media_authority::session_authority::{
        AdmittedAttachment, AdmittedRetainedSource, AttachmentResolver, HandleEvidence,
        LocalPathPolicy, RetainedHttpsPolicy, SessionMediaAuthority, SubjectLiveness,
    };
    use crate::tools::common::test_ctx;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FIXTURE_AUDIO: &[u8] = b"RIFF(\0\0\0WAVEfmt \x10\0\0\0\x01\0\x01\0\xe8\x03\0\0\xd0\x07\0\0\x02\0\x10\0data\x04\0\0\0\0\0\0\0";
    const OK_BODY: &[u8] = br#"{"text":"hello from fixture","languages":[]}"#;

    struct AlwaysLive(RevalidatedSubject);

    impl SubjectLiveness for AlwaysLive {
        fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
            Ok(self.0.clone())
        }
    }

    struct BytesResolver {
        attachments: HashMap<[u8; 16], (AdmittedAttachment, Vec<u8>)>,
    }

    #[async_trait]
    impl AttachmentResolver for BytesResolver {
        fn resolve(
            &self,
            _session_id: &str,
            attachment_id: &[u8; 16],
            max_bytes: usize,
        ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
            Ok(self
                .attachments
                .get(attachment_id)
                .filter(|(_, bytes)| bytes.len() <= max_bytes)
                .map(|(att, _)| att.clone()))
        }

        fn read_bytes(
            &self,
            attachment: &AdmittedAttachment,
            max_bytes: u64,
        ) -> Result<Vec<u8>, AdmissionDenial> {
            let bytes = self
                .attachments
                .get(&attachment.attachment_id())
                .map(|(_, bytes)| bytes.clone())
                .ok_or(AdmissionDenial::AttachmentNotFound)?;
            if bytes.len() as u64 > max_bytes {
                return Err(AdmissionDenial::Internal(
                    "media source exceeds byte limit".into(),
                ));
            }
            Ok(bytes)
        }

        async fn read_media(
            &self,
            attachment: &AdmittedAttachment,
            max_bytes: u64,
        ) -> Result<
            crate::tool_media_authority::session_authority::AdmittedMediaBytes,
            AdmissionDenial,
        > {
            Ok(
                crate::tool_media_authority::session_authority::AdmittedMediaBytes {
                    bytes: self.read_bytes(attachment, max_bytes)?,
                    duration_us: Some(2_000),
                    retained_lease: None,
                },
            )
        }
    }

    struct AllowAllPaths;
    impl LocalPathPolicy for AllowAllPaths {
        fn admit(
            &self,
            _session_id: &str,
            path: &str,
            max_bytes: usize,
        ) -> Result<
            crate::tool_media_authority::session_authority::AdmittedLocalHandle,
            AdmissionDenial,
        > {
            let content = std::fs::read(path).unwrap_or_default();
            if content.len() > max_bytes {
                return Err(AdmissionDenial::Internal("input too large".into()));
            }
            Ok(
                crate::tool_media_authority::session_authority::AdmittedLocalHandle::from_held_bytes(
                    PathBuf::from(path),
                    HandleEvidence {
                        metadata_fingerprint: [0x11; 32],
                    },
                    content,
                ),
            )
        }
    }

    struct HttpsFixture {
        content: Vec<u8>,
    }
    impl RetainedHttpsPolicy for HttpsFixture {
        fn admit(
            &self,
            _session_id: &str,
            url: &str,
            max_bytes: usize,
        ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
            if self.content.len() > max_bytes {
                return Err(AdmissionDenial::Internal("input too large".into()));
            }
            Ok(AdmittedRetainedSource {
                canonical_url: url.to_string(),
                content: self.content.clone(),
                content_type: "audio/wav".to_string(),
            })
        }
    }

    fn authority_with_attachment(
        session_id: [u8; 16],
        attachment_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> SessionMediaAuthority {
        let subject = RevalidatedSubject {
            receipt: ToolMediaSubjectReceiptV1 {
                issuer_kind: IssuerKind::LocalOwner,
                principal_digest: [0x11; 32],
                project_digest: [0x22; 32],
                session_id,
                authorization_epoch: 0,
                subject_digest: [0x33; 32],
            },
            issuer_kind: IssuerKind::LocalOwner,
            principal_digest: [0x11; 32],
            project_digest: [0x22; 32],
            session_id,
            authorization_epoch: 0,
        };
        let mut attachments = HashMap::new();
        attachments.insert(
            attachment_id,
            (
                AdmittedAttachment {
                    attachment_id,
                    attachment_version: 1,
                    checksum: {
                        let digest = Sha256::digest(&bytes);
                        let mut checksum = [0u8; 32];
                        checksum.copy_from_slice(&digest);
                        checksum
                    },
                    kind: 2,
                    content: bytes.clone(),
                },
                bytes.clone(),
            ),
        );
        SessionMediaAuthority::new(
            subject.clone(),
            Arc::new(AlwaysLive(subject)),
            Arc::new(BytesResolver { attachments }),
            Arc::new(AllowAllPaths),
            Arc::new(HttpsFixture { content: bytes }),
        )
    }

    struct OkTransport {
        sends: AtomicUsize,
    }
    impl OkTransport {
        fn new() -> Self {
            Self {
                sends: AtomicUsize::new(0),
            }
        }
    }
    #[async_trait]
    impl TranscriptionEgressTransport for OkTransport {
        async fn post_multipart(
            &self,
            _boundary: &str,
            _body: Vec<u8>,
        ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(TranscriptionHttpResponse {
                status: 200,
                body: OK_BODY.to_vec(),
            })
        }
    }

    struct TestClock;
    impl crate::media_reservation::MonotonicClock for TestClock {
        fn now_ms(&self) -> u64 {
            1
        }
    }

    fn dispatch_service(
        tmp: &tempfile::TempDir,
        transport: Arc<dyn TranscriptionEgressTransport>,
    ) -> (
        TranscriptionDispatchService,
        crate::media_reservation::MediaReservationLedger,
        cockpit_db::Db,
    ) {
        let db = cockpit_db::Db::open(&tmp.path().join("journal.db")).unwrap();
        let journal = ExternalJournal::for_test_at(db.clone(), &tmp.path().join("spool"));
        let ledger =
            crate::media_reservation::MediaReservationLedger::new(db.clone(), Arc::new(TestClock));
        (
            TranscriptionDispatchService::new(
                Arc::new(journal),
                transport,
                TranscriptionDestinationIdentity {
                    provider_id: "openai".into(),
                    origin: "https://api.openai.com".into(),
                    resolved_location: "public_network".into(),
                    credential_fingerprint: CredentialFingerprintDigest::from_raw_for_test(
                        "aa".repeat(32),
                    ),
                    endpoint_config_generation: 1,
                },
            ),
            ledger,
            db,
        )
    }

    #[tokio::test]
    async fn transcribe_audio_fails_closed_without_media_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let err = TranscribeAudioTool
            .call(
                json!({"source": {"attachment_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("media_attachment_authority_unavailable")
        );
    }

    #[tokio::test]
    async fn transcribe_audio_tool_call_with_fake_egress_and_fixture_attachment() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let attachment_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let authority = authority_with_attachment(
            *ctx.session.id.as_bytes(),
            *attachment_id.as_bytes(),
            FIXTURE_AUDIO.to_vec(),
        );
        ctx = ctx.with_media_authority(Arc::new(authority));
        let transport = Arc::new(OkTransport::new());
        let journal_tmp = tempfile::tempdir().unwrap();
        let (dispatch, ledger, accounting_db) = dispatch_service(&journal_tmp, transport.clone());
        ctx.session.set_test_media_reservation_ledger(ledger);
        ctx.transcription_dispatch = Some(Arc::new(dispatch));

        let output = TranscribeAudioTool
            .call(
                json!({"source": {"attachment_id": attachment_id.to_string()}}),
                &ctx,
            )
            .await
            .expect("tool call");
        assert!(output.content.contains("hello from fixture"));
        assert!(output.content.contains("\"kind\":\"plain\""));
        assert_eq!(transport.sends.load(Ordering::SeqCst), 1);
        let (invocations, outbound) = accounting_db
            .read(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COALESCE(SUM(charged),0) FROM media_resource_counters WHERE dimension='transcription_invocations_per_session'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    connection.query_row(
                        "SELECT COALESCE(SUM(charged),0) FROM media_resource_counters WHERE dimension='outbound_submissions_global'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            invocations, 1,
            "the per-session invocation charge is durable"
        );
        assert_eq!(
            outbound, 0,
            "terminal reconciliation releases the global slot"
        );
    }

    #[tokio::test]
    async fn transcribe_audio_rejects_https_source() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let authority = authority_with_attachment(
            *ctx.session.id.as_bytes(),
            [0x44; 16],
            FIXTURE_AUDIO.to_vec(),
        );
        ctx = ctx.with_media_authority(Arc::new(authority));
        let transport = Arc::new(OkTransport::new());
        let journal_tmp = tempfile::tempdir().unwrap();
        let (dispatch, ledger, _accounting_db) = dispatch_service(&journal_tmp, transport);
        ctx.session.set_test_media_reservation_ledger(ledger);
        ctx.transcription_dispatch = Some(Arc::new(dispatch));

        let error = TranscribeAudioTool
            .call(
                json!({"source": {"url": "https://example.test/a.wav"}}),
                &ctx,
            )
            .await
            .expect_err("HTTPS is not in the closed transcription source schema");
        assert!(error.to_string().contains("invalid input"));
    }
}
