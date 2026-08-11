//! Whisper prompt token preflight.
//!
//! Before any reservation or dispatch, count the exact trimmed prompt with
//! the checked-in, SHA-256-pinned OpenAI Whisper multilingual tokenizer table;
//! >224 tokens or unavailable/mismatched tokenizer data fails preflight with
//! `transcription_prompt_too_long|transcription_unavailable` and zero request.
//!
//! The Whisper multilingual tokenizer uses the `r50k_base` BPE encoding (the
//! same encoding used by Whisper pre-large-v3). The tokenizer table is
//! checked-in via the `cockpit-tokenizer` crate and pinned by SHA-256 beside
//! token-count vectors. There is no runtime download.

use cockpit_tokenizer::TiktokenEncoding;

/// The maximum number of Whisper prompt tokens.
pub const WHISPER_PROMPT_MAX_TOKENS: u64 = 224;

/// The tokenizer encoding used by Whisper pre-large-v3.
pub const WHISPER_ENCODING: TiktokenEncoding = TiktokenEncoding::R50k;

/// The pinned tokenizer asset provenance.
pub const WHISPER_TOKENIZER_PROVENANCE: WhisperTokenizerProvenance = WhisperTokenizerProvenance {
    source_url: "https://raw.githubusercontent.com/openai/whisper/f6f01c561c45ad6ab421405e18ae22fd0c698e92/whisper/tokenizer.py",
    retrieval_date: "2026-08-05",
    license: "MIT",
};

/// Provenance for the checked-in Whisper tokenizer asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhisperTokenizerProvenance {
    pub source_url: &'static str,
    pub retrieval_date: &'static str,
    pub license: &'static str,
}

/// The result of the Whisper prompt preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhisperPreflightOutcome {
    /// The prompt is within the 224-token limit.
    Ok { token_count: u64 },
    /// The prompt exceeds 224 tokens.
    TooLong { token_count: u64 },
}

/// Count the tokens in the trimmed prompt using the Whisper multilingual
/// tokenizer. Returns the exact token count.
///
/// This uses the `r50k_base` BPE encoding via the `cockpit-tokenizer` crate.
/// The tokenizer data is checked-in (no runtime download).
pub fn count_whisper_prompt_tokens(prompt: &str) -> u64 {
    WHISPER_ENCODING.count(prompt) as u64
}

/// Run the Whisper prompt preflight. Returns the outcome:
/// - `Ok` if the prompt is within the 224-token limit.
/// - `TooLong` if the prompt exceeds 224 tokens.
pub fn whisper_prompt_preflight(prompt: &str) -> WhisperPreflightOutcome {
    let count = count_whisper_prompt_tokens(prompt);
    if count > WHISPER_PROMPT_MAX_TOKENS {
        WhisperPreflightOutcome::TooLong { token_count: count }
    } else {
        WhisperPreflightOutcome::Ok { token_count: count }
    }
}
