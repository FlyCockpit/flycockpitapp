//! Shared, strict tiktoken encoding contract and local token counting.

use serde::{Deserialize, Serialize};
use tiktoken_rs::{
    cl100k_base_singleton, o200k_base_singleton, p50k_base_singleton, p50k_edit_singleton,
    r50k_base_singleton,
};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static COUNT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn count(text: &str) -> usize {
    #[cfg(any(test, feature = "test-support"))]
    COUNT_CALLS.with(|calls| calls.set(calls.get() + 1));
    TiktokenEncoding::Cl100k.count(text)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_count_call_count() {
    COUNT_CALLS.with(|calls| calls.set(0));
}

#[cfg(any(test, feature = "test-support"))]
pub fn count_call_count() -> usize {
    COUNT_CALLS.with(std::cell::Cell::get)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokenEncoding {
    #[serde(rename = "r50k_base")]
    R50k,
    #[serde(rename = "p50k_base")]
    P50k,
    #[serde(rename = "p50k_edit")]
    P50kEdit,
    #[default]
    #[serde(rename = "cl100k_base")]
    Cl100k,
    #[serde(rename = "o200k_base")]
    O200k,
}

impl TiktokenEncoding {
    pub const ALL: [Self; 5] = [
        Self::R50k,
        Self::P50k,
        Self::P50kEdit,
        Self::Cl100k,
        Self::O200k,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R50k => "r50k_base",
            Self::P50k => "p50k_base",
            Self::P50kEdit => "p50k_edit",
            Self::Cl100k => "cl100k_base",
            Self::O200k => "o200k_base",
        }
    }

    /// Parse an encoding from its canonical string name (the inverse of
    /// [`as_str`](Self::as_str)). Returns `None` for an unknown name.
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "r50k_base" => Some(Self::R50k),
            "p50k_base" => Some(Self::P50k),
            "p50k_edit" => Some(Self::P50kEdit),
            "cl100k_base" => Some(Self::Cl100k),
            "o200k_base" => Some(Self::O200k),
            _ => None,
        }
    }

    pub fn count(self, text: &str) -> usize {
        self.encode_ids(text).len()
    }

    /// Encode `text` into its exact token-id sequence using the pinned BPE
    /// table (special tokens included). This exposes the token ids — not just
    /// the count — so callers can fingerprint the actual tokenizer DATA
    /// (vocab/merges behavior), since a corrupt table changes the ids a fixed
    /// corpus encodes to. The empty string encodes to no tokens.
    pub fn encode_ids(self, text: &str) -> Vec<u32> {
        if text.is_empty() {
            return Vec::new();
        }
        let bpe = match self {
            Self::R50k => r50k_base_singleton(),
            Self::P50k => p50k_base_singleton(),
            Self::P50kEdit => p50k_edit_singleton(),
            Self::Cl100k => cl100k_base_singleton(),
            Self::O200k => o200k_base_singleton(),
        };
        // Already `Vec<u32>`; the old `.map(|id| id as u32)` was a no-op cast
        // that `clippy::unnecessary_cast` rejects under `-D warnings`.
        bpe.encode_with_special_tokens(text)
    }

    pub fn warm(self) {
        let _ = match self {
            Self::R50k => r50k_base_singleton(),
            Self::P50k => p50k_base_singleton(),
            Self::P50kEdit => p50k_edit_singleton(),
            Self::Cl100k => cl100k_base_singleton(),
            Self::O200k => o200k_base_singleton(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiktoken_encoding_rejects_unknown_serde() {
        let values = [
            "r50k_base",
            "p50k_base",
            "p50k_edit",
            "cl100k_base",
            "o200k_base",
        ];
        for (encoding, value) in TiktokenEncoding::ALL.into_iter().zip(values) {
            assert_eq!(
                serde_json::to_string(&encoding).unwrap(),
                format!("\"{value}\"")
            );
            assert_eq!(
                serde_json::from_str::<TiktokenEncoding>(&format!("\"{value}\"")).unwrap(),
                encoding
            );
        }
        assert!(serde_json::from_str::<TiktokenEncoding>("\"unknown\"").is_err());
    }

    #[test]
    fn tiktoken_encoding_counts_each_strategy() {
        let text = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(
            TiktokenEncoding::R50k.count(text),
            r50k_base_singleton().encode_with_special_tokens(text).len()
        );
        assert_eq!(
            TiktokenEncoding::P50k.count(text),
            p50k_base_singleton().encode_with_special_tokens(text).len()
        );
        assert_eq!(
            TiktokenEncoding::P50kEdit.count(text),
            p50k_edit_singleton().encode_with_special_tokens(text).len()
        );
        assert_eq!(
            TiktokenEncoding::Cl100k.count(text),
            cl100k_base_singleton()
                .encode_with_special_tokens(text)
                .len()
        );
        assert_eq!(
            TiktokenEncoding::O200k.count(text),
            o200k_base_singleton()
                .encode_with_special_tokens(text)
                .len()
        );
    }
}
