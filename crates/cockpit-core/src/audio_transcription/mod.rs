//! Provider-specific audio transcription registry and media-egress authorization.
//!
//! This module implements the pure, injectable core of the
//! `external-model-audio-transcription` contract:
//!
//! * Two independent, SHA-256-pinned language catalogs
//!   ([`catalogs::GptTranscribeLanguageCodeV1`],
//!   [`catalogs::WhisperLanguageCodeV1`]) with disjoint catalog-version
//!   identifiers and checked-in source/date/digest records.
//! * Three noninterchangeable closed language codecs
//!   ([`result::RequestedLanguageV1`], [`result::AppliedLanguageV1`],
//!   [`result::DetectedLanguageV1`]).
//! * Feature-driven model selection ([`request::TranscriptionModel`],
//!   [`request::select_model`]) for `gpt-transcribe`,
//!   `gpt-4o-transcribe-diarize`, and `whisper-1`.
//! * Caller-context validation and exact SP/TAB trimming for `prompt`,
//!   `keywords[]`, and `languages[]` ([`request::CallerContext`],
//!   [`request::validate_context`]).
//! * Overflow-safe multipart length planning
//!   ([`request::MultipartLengthPlan`], [`request::plan_multipart_length`])
//!   with checked `u64` additions and checked conversion to platform/client
//!   length types.
//! * Strict, family-selected response decoding ([`response`]).
//! * The closed `NormalizedTranscriptionResultV1` product ([`result`]).
//! * Media-egress authorization for purpose `transcription`
//!   ([`authorization::MediaEgressTranscriptionRequest`],
//!   [`authorization::transcription_request_digest`]) bound to provider,
//!   model, credential fingerprint, origin, resolved location, project,
//!   session, attachment checksum, exact media interval, prompt bytes,
//!   ordered keywords, ordered languages, timestamp/diarization options,
//!   and purpose through a versioned canonical digest.
//! * Whisper prompt token preflight ([`whisper_preflight`]).
//!
//! The HTTP/credential/journal/reservation/cancellation runtime is owned by
//! the external-runtime and external-journal layers; this module supplies the
//! closed contracts those layers consume. No real network, sleeps, or global
//! environment mutation occurs here.

pub mod authorization;
pub mod catalogs;
pub(crate) mod dispatch;
pub mod journal;
pub mod request;
pub mod response;
pub mod result;
pub mod transport;
pub mod whisper_preflight;

#[cfg(test)]
mod tests;
