use chrono::{DateTime, Local};

/// In-flight assistant turn. Lives in `App.pending` from
/// `ThinkingStarted` to `AssistantText`; once finalized it gets pushed
/// to `App.history` as [`HistoryEntry::Agent`].
#[derive(Debug, Clone)]
pub struct PendingMsg {
    pub name: String,
    /// Accumulated streaming text **with `<think>` blocks stripped**.
    /// Empty while we're still in the "Thinking…" phase.
    pub text: String,
    /// Accumulated reasoning content. Hidden by default; surfaced when
    /// the user expands the eventual history entry. Populated from
    /// both rig's `ReasoningDelta` events *and* inline `<think>…
    /// </think>` blocks in the text stream.
    pub reasoning: String,
    pub timestamp: DateTime<Local>,
    /// `Instant` the turn started — used for the `think_duration`
    /// stamp on the finalized [`HistoryEntry::Agent`]. Wall-clock
    /// `timestamp` above is for the right-aligned `HH:MM` chip.
    pub started_at: std::time::Instant,
    /// Set to `Some(_)` the first time a *non-thinking* text delta
    /// (i.e., text outside any `<think>` block) arrives. Until then
    /// the agent is considered "still thinking."
    pub text_started_at: Option<std::time::Instant>,
    /// True if we're currently inside a `<think>...</think>` block
    /// straddling delta boundaries.
    pub inside_think: bool,
    /// True once real (non-whitespace) body text has been emitted. Latches
    /// permanently: thereafter `<think>` tags are literal body content, not
    /// reasoning (tags are recognized only at the start of a message).
    pub body_started: bool,
    /// Buffered tail of the latest delta that *might* be the start of
    /// a `<think>` or `</think>` tag — held until the next delta lets
    /// us disambiguate.
    pub tag_partial: String,
    /// `session_events.seq` of this assistant message, set from the
    /// finalizing `AssistantText` event and stamped onto the frozen
    /// [`HistoryEntry::Agent`] (the stable id a pin references —
    /// `pinned-messages`).
    pub seq: Option<i64>,
    /// Whether inline `<think>` stripping runs for this turn's model,
    /// resolved once at turn start from the three-tier toggle (model →
    /// provider → global, implementation note).
    /// `false` bypasses the `ThinkSplitter` entirely: content streams through
    /// verbatim as body and reasoning rides only the provider's
    /// `reasoning_content` channel — no partial-tag buffering is initialized.
    pub strip_think: bool,
}
