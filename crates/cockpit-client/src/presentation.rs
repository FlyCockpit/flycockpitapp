//! Client-facing identities for live presentation streams.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AssistantAttemptId(u64);

impl AssistantAttemptId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for AssistantAttemptId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "attempt-{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayErrorKind {
    Cancelled,
    Failed,
}

/// Provider-reported token usage attached to a presented inference result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

impl TokenUsage {
    /// Freshly processed input plus output, excluding cached input reads.
    pub fn blended_total(&self) -> u64 {
        self.input_tokens
            .saturating_sub(self.cached_input_tokens)
            .saturating_add(self.output_tokens)
    }

    pub fn hit_rate(&self) -> Option<f64> {
        if self.input_tokens == 0 {
            None
        } else {
            Some(self.cached_input_tokens as f64 / self.input_tokens as f64)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cached_input_tokens == 0
            && self.cache_creation_input_tokens == 0
    }
}
