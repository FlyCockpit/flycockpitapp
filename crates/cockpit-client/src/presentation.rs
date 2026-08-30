//! Client-facing identities for live presentation streams.

mod turn_event;

pub use turn_event::TurnEvent;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControlRequestId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequestNotDelivered {
    NoRunner,
    ChannelFull,
    ChannelClosed,
    RunnerTeardown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequestOutcome {
    NotDelivered(ControlRequestNotDelivered),
    Rejected(String),
    Applied,
    ConfigRefreshed {
        applied_generation: u64,
        changed: bool,
    },
    HostCapabilities {
        snapshot: Box<cockpit_proto::HostCapabilitySnapshot>,
    },
    ExitGuardStatus {
        ephemeral_owner: bool,
        has_live_work: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolProgress {
    pub call_id: String,
    pub done: u64,
    pub total: u64,
    pub unit: String,
}

/// Provider-reported token usage attached to a presented inference result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

/// Immutable response timing snapshot presented by daemon clients.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ResponsePerformance {
    pub ttft_ms: u64,
    pub generation_ms: u64,
    pub displayed_tokens: u64,
    pub encoding: String,
}

impl ResponsePerformance {
    pub fn tps(&self) -> Option<f64> {
        if self.generation_ms == 0 {
            None
        } else {
            Some(self.displayed_tokens as f64 * 1000.0 / self.generation_ms as f64)
        }
    }

    pub fn from_proto(snapshot: cockpit_proto::ResponsePerformance) -> Option<Self> {
        if !matches!(
            snapshot.encoding.as_str(),
            "r50k_base" | "p50k_base" | "p50k_edit" | "cl100k_base" | "o200k_base"
        ) {
            return None;
        }
        Some(Self {
            ttft_ms: snapshot.ttft_ms,
            generation_ms: snapshot.generation_ms,
            displayed_tokens: snapshot.displayed_tokens,
            encoding: snapshot.encoding,
        })
    }
}

/// Durable assistant body and its exact client presentation snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AssistantTextPayload {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_text: Option<String>,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_performance: Option<ResponsePerformance>,
}

impl AssistantTextPayload {
    pub fn display_text(&self) -> &str {
        self.presentation_text.as_deref().unwrap_or(&self.text)
    }
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
