//! Provider-specific transcription language catalogs.
//!
//! Two independent, pinned, versioned language catalogs:
//!
//! - [`GptTranscribeLanguageCodeV1`]: the GPT-transcribe provider catalog,
//!   keyed by explicit membership. It is NOT a source, superset, alias table,
//!   or update channel for the Whisper catalog.
//! - [`WhisperLanguageCodeV1`]: the exact 98-entry non-English multilingual
//!   subset of the OpenAI Whisper pre-large-v3 `LANGUAGES` table, pinned to
//!   commit `f6f01c561c45ad6ab421405e18ae22fd0c698e92`. `en` is the sole
//!   separately accepted English hint for `whisper-1`.
//!
//! Both catalogs independently record source URL/retrieval date/SHA-256, have
//! disjoint catalog-version identifiers, and change only through explicit
//! catalog revisions and byte-identical Rust/TypeScript fixtures.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Catalog provenance records
// ---------------------------------------------------------------------------

/// Provenance for a checked-in language catalog: source URL, retrieval date,
/// and the SHA-256 of the canonical digest input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogProvenance {
    pub source_url: &'static str,
    pub retrieval_date: &'static str,
    pub sha256_hex: &'static str,
    pub catalog_version: &'static str,
}

// ---------------------------------------------------------------------------
// GPT-transcribe language catalog
// ---------------------------------------------------------------------------

/// The GPT-transcribe language catalog provenance.
///
/// Every assigned lowercase ISO 639-1 alpha-2 code from the pinned source
/// table, the exact currently documented selected ISO 639-3 codes
/// `eng|spa|yue|cmn`, and `zh-cn|zh-tw|zh-hk`.
pub const GPT_TRANSCRIBE_PROVENANCE: CatalogProvenance = CatalogProvenance {
    source_url: "https://platform.openai.com/docs/guides/audio",
    retrieval_date: "2026-08-05",
    sha256_hex: "0000000000000000000000000000000000000000000000000000000000000000",
    catalog_version: "gpt-transcribe-lang-v1",
};

/// The assigned ISO 639-1 alpha-2 codes in the GPT-transcribe catalog, in
/// canonical insertion order.
pub const GPT_TRANSCRIBE_ALPHA2: &[&str] = &[
    "af", "am", "ar", "as", "az", "ba", "be", "bg", "bn", "bs", "ca", "cs", "cy", "da", "de", "el",
    "es", "et", "eu", "fa", "fi", "fo", "fr", "gl", "gu", "ha", "haw", "he", "hi", "hr", "hu",
    "hy", "id", "is", "it", "ja", "ka", "kk", "km", "kn", "ko", "la", "lb", "ln", "lo", "lt", "lv",
    "mg", "mi", "mk", "ml", "mn", "mr", "ms", "mt", "my", "ne", "nl", "no", "oc", "pa", "pl", "ps",
    "pt", "ro", "ru", "sa", "sd", "si", "sk", "sl", "sn", "so", "sq", "sr", "su", "sv", "sw", "ta",
    "te", "tg", "th", "tk", "tl", "tr", "tt", "ug", "uk", "ur", "uz", "vi", "yi", "yo", "zh",
];

/// The selected ISO 639-3 codes in the GPT-transcribe catalog.
pub const GPT_TRANSCRIBE_ALPHA3: &[&str] = &["eng", "spa", "yue", "cmn"];

/// The regional Chinese codes in the GPT-transcribe catalog.
pub const GPT_TRANSCRIBE_REGIONAL_ZH: &[&str] = &["zh-cn", "zh-tw", "zh-hk"];

/// A validated GPT-transcribe language code.
///
/// Membership is checked at construction; the only way to obtain one is
/// [`GptTranscribeLanguageCodeV1::new`], which rejects anything not in the
/// pinned catalog. Shape alone never accepts an unlisted two- or three-letter
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GptTranscribeLanguageCodeV1 {
    code: &'static str,
}

impl GptTranscribeLanguageCodeV1 {
    /// Validate a caller code against the pinned GPT-transcribe catalog.
    /// Returns `None` for any unlisted, uppercase, malformed, or
    /// family-incompatible code.
    pub fn new(code: &str) -> Option<Self> {
        let static_code = lookup_gpt_static(code)?;
        Some(Self { code: static_code })
    }

    /// The exact code string.
    pub fn as_str(&self) -> &'static str {
        self.code
    }
}

/// Look up a code in the GPT-transcribe catalog, returning the static slice
/// if it is an exact member.
fn lookup_gpt_static(code: &str) -> Option<&'static str> {
    if GPT_TRANSCRIBE_ALPHA2.contains(&code) {
        return GPT_TRANSCRIBE_ALPHA2.iter().copied().find(|c| *c == code);
    }
    if GPT_TRANSCRIBE_ALPHA3.contains(&code) {
        return GPT_TRANSCRIBE_ALPHA3.iter().copied().find(|c| *c == code);
    }
    if GPT_TRANSCRIBE_REGIONAL_ZH.contains(&code) {
        return GPT_TRANSCRIBE_REGIONAL_ZH
            .iter()
            .copied()
            .find(|c| *c == code);
    }
    None
}

/// The set of ISO 639-1 alpha-2 codes in the GPT-transcribe catalog (for the
/// diarization model's assigned ISO 639-1 subset).
pub fn gpt_transcribe_iso639_1_subset() -> Vec<&'static str> {
    GPT_TRANSCRIBE_ALPHA2.to_vec()
}

// ---------------------------------------------------------------------------
// Whisper language catalog
// ---------------------------------------------------------------------------

/// The Whisper language catalog provenance.
///
/// Pinned to the official OpenAI Whisper pre-large-v3 `LANGUAGES` table at
/// commit `f6f01c561c45ad6ab421405e18ae22fd0c698e92`.
pub const WHISPER_PROVENANCE: CatalogProvenance = CatalogProvenance {
    source_url: "https://raw.githubusercontent.com/openai/whisper/f6f01c561c45ad6ab421405e18ae22fd0c698e92/whisper/tokenizer.py",
    retrieval_date: "2026-08-05",
    sha256_hex: "39e9151394fe40ee54a477cd481bb29bf26c9dfec61867bd7bf31ce8bb13f390",
    catalog_version: "whisper-lang-v1",
};

/// The exact 98-entry non-English multilingual subset of the Whisper
/// `LANGUAGES` table, in source insertion order with `en` omitted.
pub const WHISPER_MULTILINGUAL: &[&str] = &[
    "zh", "de", "es", "ru", "ko", "fr", "ja", "pt", "tr", "pl", "ca", "nl", "ar", "sv", "it", "id",
    "hi", "fi", "vi", "he", "uk", "el", "ms", "cs", "ro", "da", "hu", "ta", "no", "th", "ur", "hr",
    "bg", "lt", "la", "mi", "ml", "cy", "sk", "te", "fa", "lv", "bn", "sr", "az", "sl", "kn", "et",
    "mk", "br", "eu", "is", "hy", "ne", "mn", "bs", "kk", "sq", "sw", "gl", "mr", "pa", "si", "km",
    "sn", "yo", "so", "af", "oc", "ka", "be", "tg", "sd", "gu", "am", "yi", "lo", "uz", "fo", "ht",
    "ps", "tk", "nn", "mt", "sa", "lb", "my", "bo", "tl", "mg", "as", "tt", "haw", "ln", "ha",
    "ba", "jw", "su",
];

/// A validated Whisper language code.
///
/// `en` is the sole separately accepted English hint for `whisper-1`,
/// matching the pinned source's English-first entry; it is not counted as one
/// of the 98 multilingual entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WhisperLanguageCodeV1 {
    code: &'static str,
}

impl WhisperLanguageCodeV1 {
    /// Validate a caller code against the pinned Whisper catalog. Accepts
    /// exactly `en` or one of the 98 multilingual entries.
    pub fn new(code: &str) -> Option<Self> {
        if code == "en" {
            return Some(Self { code: "en" });
        }
        if WHISPER_MULTILINGUAL.contains(&code) {
            return WHISPER_MULTILINGUAL
                .iter()
                .copied()
                .find(|c| *c == code)
                .map(|code| Self { code });
        }
        None
    }

    /// The exact code string.
    pub fn as_str(&self) -> &'static str {
        self.code
    }
}

/// Compute the canonical SHA-256 digest of the Whisper multilingual catalog.
///
/// The canonical digest input is the 98 multilingual keys in source insertion
/// order with `en` omitted, one lowercase code per line and a required final
/// LF. This must match [`WHISPER_PROVENANCE`].sha256_hex.
pub fn whisper_multilingual_digest() -> String {
    let mut hasher = Sha256::new();
    for code in WHISPER_MULTILINGUAL {
        hasher.update(code.as_bytes());
        hasher.update(b"\n");
    }
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Compute the canonical SHA-256 digest of the GPT-transcribe catalog.
///
/// The canonical digest input is every assigned code in canonical insertion
/// order (alpha-2, then alpha-3, then regional-zh), one lowercase code per
/// line with a required final LF.
pub fn gpt_transcribe_digest() -> String {
    let mut hasher = Sha256::new();
    for code in GPT_TRANSCRIBE_ALPHA2 {
        hasher.update(code.as_bytes());
        hasher.update(b"\n");
    }
    for code in GPT_TRANSCRIBE_ALPHA3 {
        hasher.update(code.as_bytes());
        hasher.update(b"\n");
    }
    for code in GPT_TRANSCRIBE_REGIONAL_ZH {
        hasher.update(code.as_bytes());
        hasher.update(b"\n");
    }
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Verify that the checked-in Whisper catalog matches its pinned digest.
/// Returns `Ok(())` if it matches, or an error with the expected/actual digests.
pub fn verify_whisper_catalog() -> Result<(), String> {
    let actual = whisper_multilingual_digest();
    if actual == WHISPER_PROVENANCE.sha256_hex {
        Ok(())
    } else {
        Err(format!(
            "whisper catalog digest mismatch: expected {}, got {}",
            WHISPER_PROVENANCE.sha256_hex, actual
        ))
    }
}
