//! Whisper prompt token preflight.
//!
//! Before any reservation or dispatch, count the exact trimmed prompt with
//! the checked-in, SHA-256-pinned OpenAI Whisper multilingual tokenizer table;
//! >224 tokens or unavailable/mismatched tokenizer data fails preflight with
//! > `transcription_prompt_too_long|transcription_unavailable` and zero request.
//!
//! The Whisper multilingual tokenizer uses the `r50k_base` BPE encoding (the
//! same encoding used by Whisper pre-large-v3). The tokenizer table is
//! checked-in via the `cockpit-tokenizer` crate and pinned by SHA-256 beside
//! token-count vectors. There is no runtime download.

use sha2::{Digest, Sha256};

use cockpit_tokenizer::TiktokenEncoding;

/// The maximum number of Whisper prompt tokens.
pub const WHISPER_PROMPT_MAX_TOKENS: u64 = 224;

/// The tokenizer encoding used by Whisper pre-large-v3.
pub const WHISPER_ENCODING: TiktokenEncoding = TiktokenEncoding::R50k;

/// The canonical-encoding version prefix for the tokenizer DATA digest. Bump it
/// only alongside an intentional re-pin.
const WHISPER_TOKENIZER_DIGEST_VERSION: &[u8] = b"whisper-tokenizer-data-v1\n";

/// The SHA-256 the pinned Whisper tokenizer DATA must hash to before any
/// reservation or dispatch for a Whisper-model request. Any mismatch (a
/// corrupted, swapped, or otherwise altered BPE table) fails preflight
/// `Unavailable` with **zero** provider request.
///
/// What is pinned: `cockpit_tokenizer` (backing `tiktoken-rs` 0.12) does not
/// expose the raw r50k_base vocab/merges bytes — its `encoder` map is
/// crate-private. The authoritative tokenizer DATA reachable through the public
/// API is the exact token-id sequence the real BPE table produces. This digest
/// is therefore a behavioral fingerprint of the actual table: the SHA-256 over
/// the version prefix, the encoding name, and the length-prefixed r50k_base
/// token-id sequences of [`WHISPER_TOKENIZER_PROBE_CORPUS`]. It pins tokenizer
/// DATA behavior, not a language-code list; any change to the merges/vocab
/// bytes changes the encoded ids and thus this digest. Recompute with
/// [`whisper_tokenizer_data_digest`] only for an intentional re-pin.
pub const WHISPER_TOKENIZER_DIGEST: &str =
    "0ed0163d5c6b493d8b8a0a8323e85641771619aa67b23ba25e9e6633be2bce47";

/// The fixed probe corpus whose r50k_base encoding fingerprints the tokenizer
/// DATA. It exercises ASCII words, punctuation, digits, whitespace/tabs,
/// mixed case, multi-byte UTF-8 (Latin diacritics, CJK), emoji + combining
/// marks, newlines, and repeats so that any alteration of the BPE table changes
/// the encoded ids. It MUST stay byte-identical to the value the pinned digest
/// was computed over.
pub const WHISPER_TOKENIZER_PROBE_CORPUS: &[&str] = &[
    "the quick brown fox jumps over the lazy dog",
    "Transcription preflight tokenizer fingerprint.",
    "0123456789 !@#$%^&*()_+-=[]{};:'\",.<>/?\\|`~",
    "   leading and   internal    spaces\tand\ttabs   ",
    "MixedCASE Words With CamelCase and snake_case_ident",
    "Café naïve façade — coöperate résumé Zürich",
    "日本語のテキスト 中文文本 한국어 텍스트",
    "emoji test 😀🚀🎧🔥 and combining e\u{0301}",
    "newlines\nare\npart\nof\nthe\nprobe",
    "repeated repeated repeated tokens tokens tokens",
];

/// Compute the canonical SHA-256 fingerprint of the checked-in Whisper
/// tokenizer DATA: the version prefix, the encoding name, then, for each probe
/// in [`WHISPER_TOKENIZER_PROBE_CORPUS`], the length-prefixed little-endian
/// `u32` token-id sequence the real r50k_base table encodes it to. This must
/// match [`WHISPER_TOKENIZER_DIGEST`].
pub fn whisper_tokenizer_data_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(WHISPER_TOKENIZER_DIGEST_VERSION);
    hasher.update(WHISPER_ENCODING.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update((WHISPER_TOKENIZER_PROBE_CORPUS.len() as u64).to_le_bytes());
    for probe in WHISPER_TOKENIZER_PROBE_CORPUS {
        let ids = WHISPER_ENCODING.encode_ids(probe);
        hasher.update((ids.len() as u64).to_le_bytes());
        for id in ids {
            hasher.update(id.to_le_bytes());
        }
    }
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

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
    /// The prompt exceeds 224 tokens (`transcription_prompt_too_long`).
    TooLong { token_count: u64 },
    /// The pinned tokenizer data did not match [`WHISPER_TOKENIZER_DIGEST`], so
    /// no token count is trustworthy (`transcription_unavailable`). The caller
    /// must make **zero** provider request. `expected`/`actual` carry the
    /// digests for diagnostics; they are catalog hashes, never secrets.
    Unavailable { expected: String, actual: String },
}

impl WhisperPreflightOutcome {
    /// Whether the preflight permits a provider request. Only `Ok` does; both
    /// `TooLong` and `Unavailable` are terminal fail-closed outcomes with zero
    /// egress.
    pub fn allows_dispatch(&self) -> bool {
        matches!(self, WhisperPreflightOutcome::Ok { .. })
    }
}

/// Verify the pinned Whisper tokenizer DATA digest before any token count or
/// dispatch. Returns `Ok(())` on a match; on mismatch returns the
/// expected/actual digests so the caller can fail closed with
/// `transcription_unavailable` and zero egress. Never panics — a divergence is
/// a fail-closed outcome, not an assertion.
pub fn verify_whisper_tokenizer_digest() -> Result<(), (String, String)> {
    let actual = whisper_tokenizer_data_digest();
    if actual == WHISPER_TOKENIZER_DIGEST {
        Ok(())
    } else {
        Err((WHISPER_TOKENIZER_DIGEST.to_string(), actual))
    }
}

/// Count the tokens in the trimmed prompt using the Whisper multilingual
/// tokenizer. Returns the exact token count.
///
/// This uses the `r50k_base` BPE encoding via the `cockpit-tokenizer` crate.
/// The tokenizer data is checked-in (no runtime download).
pub fn count_whisper_prompt_tokens(prompt: &str) -> u64 {
    WHISPER_ENCODING.count(prompt) as u64
}

/// Run the Whisper prompt preflight as a production gate. Returns the outcome:
/// - `Unavailable` if the pinned tokenizer data digest does not verify — no
///   token counting occurs and the caller must make zero provider request.
/// - `TooLong` if the prompt exceeds 224 tokens.
/// - `Ok` if the prompt is within the 224-token limit.
pub fn whisper_prompt_preflight(prompt: &str) -> WhisperPreflightOutcome {
    // Gate: verify the pinned tokenizer/language data BEFORE counting tokens.
    // Mismatch or missing data fails closed with zero egress.
    if let Err((expected, actual)) = verify_whisper_tokenizer_digest() {
        return WhisperPreflightOutcome::Unavailable { expected, actual };
    }
    let count = count_whisper_prompt_tokens(prompt);
    if count > WHISPER_PROMPT_MAX_TOKENS {
        WhisperPreflightOutcome::TooLong { token_count: count }
    } else {
        WhisperPreflightOutcome::Ok { token_count: count }
    }
}
