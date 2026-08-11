//! Shared, strict tiktoken encoding contract and local token counting.

use serde::{Deserialize, Serialize};
use tiktoken_rs::{
    cl100k_base_singleton, o200k_base_singleton, p50k_base_singleton, p50k_edit_singleton,
    r50k_base_singleton,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        if text.is_empty() {
            return 0;
        }
        let bpe = match self {
            Self::R50k => r50k_base_singleton(),
            Self::P50k => p50k_base_singleton(),
            Self::P50kEdit => p50k_edit_singleton(),
            Self::Cl100k => cl100k_base_singleton(),
            Self::O200k => o200k_base_singleton(),
        };
        bpe.encode_with_special_tokens(text).len()
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
