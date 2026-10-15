//! Typed, content-free reasons a daemon could not establish redaction
//! coverage. They cross the wire so a client can explain a fail-closed state
//! (withheld text, a failed first-run construction) instead of pointing at
//! `daemon.log`. A reason never carries a path, value, count or message from
//! the redaction sources.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionCoverageFailure {
    /// A redaction source could not be read or captured completely.
    CaptureFailed,
    /// The coverage workers or queues are momentarily full.
    Busy,
    /// A redaction source changed while coverage was being built.
    SourcesChanged,
    /// An env file is larger than the daemon reads for redaction.
    SourceFileOverLimit,
    /// Private SSH key material exceeds the per-generation memory budget.
    SshKeysOverBudget,
    /// The other redaction sources exceed the per-generation memory budget.
    SourcesOverBudget,
    /// Coverage memory is fully held by open sessions.
    HeldByOpenSessions,
}

impl RedactionCoverageFailure {
    /// One user-facing sentence naming the cause and its remedy.
    pub fn message(self) -> &'static str {
        match self {
            Self::CaptureFailed => {
                "a redaction source (env file, SSH key or stored secret) could not be read; details are in daemon.log"
            }
            Self::Busy => "redaction coverage is busy; retry in a moment",
            Self::SourcesChanged => {
                "a redaction source changed while coverage was being built; retry"
            }
            Self::SourceFileOverLimit => {
                "an env file is larger than the daemon reads for redaction; shrink it or exclude it from `redact`"
            }
            Self::SshKeysOverBudget => {
                "private SSH key material exceeds the redaction coverage memory budget; point `redact.ssh_key_dir` at a directory holding only the keys to protect, or set `redact.scan_ssh_keys` to false"
            }
            Self::SourcesOverBudget => {
                "redaction sources exceed the redaction coverage memory budget"
            }
            Self::HeldByOpenSessions => {
                "redaction coverage memory is fully held by open sessions; close idle sessions and retry"
            }
        }
    }
}

/// Why a locked owner's ready construction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadyConstructionFailure {
    /// Daemon-global redaction coverage could not be built.
    RedactionCoverage(RedactionCoverageFailure),
    /// Construction exceeded its deadline.
    TimedOut,
    /// No typed cause is known (or construction never ran for the committed
    /// choice); details are in daemon.log.
    Unclassified,
}

impl ReadyConstructionFailure {
    /// One user-facing sentence for the onboarding screen and CLI status.
    pub fn message(self) -> String {
        match self {
            Self::RedactionCoverage(reason) => {
                format!(
                    "redaction coverage could not be built: {}",
                    reason.message()
                )
            }
            Self::TimedOut => "preparing services took too long; details are in daemon.log".into(),
            Self::Unclassified => "details are in daemon.log".into(),
        }
    }
}
