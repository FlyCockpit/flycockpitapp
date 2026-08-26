//! Engine-owned user-visible response timing and durable telemetry.
//!
//! Provides one durable per-assistant-message [`ResponsePerformance`]
//! snapshot for the exact text users experience: local TTFT,
//! post-first-visible-token duration, selected-tiktoken count, and
//! encoding. It reaches live TUI events, session data, exports, daemon
//! history, and rehydration without trusting provider numbers.
//!
//! ## Design
//!
//! - [`DisplayStreamClassifier`] is constructed at exact successful-attempt
//!   dispatch with an injected `attempt_dispatched_at` instant. TTFT is
//!   the first non-whitespace presentation emission minus that instant.
//!   It owns accumulated raw body, incremental think state, Harmony
//!   stripping, and whitespace. It emits typed display deltas and a
//!   final [`DisplayComplete`] carrying the durable [`AssistantTextPayload`].
//! - Only the classifier starts time. Production must not read a second
//!   real clock at finish — the injected clock supplies every timestamp.
//! - `ResponsePerformance` persists `ttft_ms`, `generation_ms`, the
//!   displayed-body token count, and an encoding snapshot. It is absent
//!   for empty/think-only/no-visible-body/zero-duration responses.
//! - A persistence or tokenizer failure never drops the reply.
//!
//! See `response-performance-display-telemetry-foundation.md` for the
//! full specification.

use crate::engine::think::ThinkSplitter;
use cockpit_tokenizer::TiktokenEncoding;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use cockpit_client::presentation::AssistantAttemptId;

/// Durable per-assistant-message response performance snapshot.
///
/// Persists durations (not wall-clock instants): `ttft_ms` is
/// `first_non_whitespace_presentation_at - attempt_dispatched_at`, and
/// `generation_ms` is exactly `finish_at -
/// first_non_whitespace_presentation_at`. TPS is the final canonical
/// `presentation_text`'s complete shared-tokenizer count (including the
/// token containing the first visible text) divided by `generation_ms`.
/// A zero `generation_ms` has no TPS snapshot.
///
/// The snapshot is immutable: later tokenizer changes never recompute
/// history. Counting happens only after all classified/translated/fallback
/// presentation text is final, so BPE tokens split across stream chunks
/// have the same result as unsplit text.
///
/// No provider usage or model tokenizer participates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResponsePerformance {
    /// Time-to-first-token: milliseconds from attempt dispatch to the
    /// first non-whitespace presentation emission.
    pub ttft_ms: u64,
    /// Generation duration: milliseconds from first non-whitespace
    /// presentation emission to finish.
    pub generation_ms: u64,
    /// Token count of the final canonical `presentation_text` as counted
    /// by the shared tokenizer (including the token containing the first
    /// visible text).
    pub displayed_tokens: u64,
    /// The tiktoken encoding used to count `displayed_tokens`. Frozen at
    /// snapshot time so later tokenizer changes never recompute history.
    pub encoding: TiktokenEncoding,
}

impl ResponsePerformance {
    /// Tokens-per-second for this snapshot. Returns `None` when
    /// `generation_ms` is zero (all-at-once translated output has zero
    /// post-first duration and therefore no TPS).
    pub fn tps(&self) -> Option<f64> {
        if self.generation_ms == 0 {
            return None;
        }
        Some(self.displayed_tokens as f64 * 1000.0 / self.generation_ms as f64)
    }

    /// Build a snapshot from the classifier's measured instants and the
    /// final presentation text. Returns `None` when the response has no
    /// visible body, no first-presentation instant, or zero duration with
    /// no tokens — the cases the spec says omit the snapshot.
    ///
    /// A tokenizer failure emits `None` and is logged by the caller — the
    /// reply is never dropped.
    pub fn from_measurements(
        attempt_dispatched_at: Instant,
        first_non_whitespace_presentation_at: Option<Instant>,
        finish_at: Instant,
        presentation_text: &str,
        encoding: TiktokenEncoding,
    ) -> Option<Self> {
        let first = first_non_whitespace_presentation_at?;
        if presentation_text.trim().is_empty() {
            return None;
        }
        let ttft_ms = first
            .checked_duration_since(attempt_dispatched_at)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let generation_ms = finish_at
            .checked_duration_since(first)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Empty/think-only/no-visible-body/zero-duration responses omit it.
        // A zero generation_ms with a non-empty body is the all-at-once
        // translated case: it still carries TTFT + token count but no TPS.
        let displayed_tokens = encoding.count(presentation_text) as u64;
        if displayed_tokens == 0 {
            return None;
        }
        Some(Self {
            ttft_ms,
            generation_ms,
            displayed_tokens,
            encoding,
        })
    }

    /// Reconstruct from the wire-protocol form (string encoding name).
    /// Returns `None` when the encoding name is unknown — the snapshot is
    /// then omitted (legacy/unknown encoding).
    pub fn from_proto(proto: &crate::daemon::proto::ResponsePerformance) -> Option<Self> {
        let encoding = TiktokenEncoding::from_str_name(&proto.encoding)?;
        Some(Self {
            ttft_ms: proto.ttft_ms,
            generation_ms: proto.generation_ms,
            displayed_tokens: proto.displayed_tokens,
            encoding,
        })
    }
}

/// A clock instant used by the classifier. This is a thin newtype over
/// `std::time::Instant` so tests can inject a deterministic clock while
/// production uses the real one. The classifier never reads a second real
/// clock at finish — every timestamp comes from the injected clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instant(std::time::Instant);

impl Default for Instant {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}

impl Instant {
    /// The current real-time instant (production clock).
    pub fn now() -> Self {
        Self(std::time::Instant::now())
    }

    /// Wrap a specific `std::time::Instant` (test/injected clock).
    pub const fn from_std(instant: std::time::Instant) -> Self {
        Self(instant)
    }

    /// The underlying `std::time::Instant`.
    pub const fn as_std(self) -> std::time::Instant {
        self.0
    }

    /// Duration since an earlier instant. Returns zero if `self` is
    /// somehow before `earlier` (defensive; should not happen with a
    /// monotonic injected clock).
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0)
    }
}

/// The durable assistant text payload carried by `AssistantDisplayComplete`
/// and persisted as the assistant message.
///
/// `text` is the model-context/wire body. `presentation_text` is the exact
/// final text shown to users when it differs (translation success);
/// `None` means `text` is also the display form (legacy/fallback/identical).
/// `reasoning` is the finalized (channel + inline) reasoning. `seq` is the
/// `session_events` row id. `performance` is the optional
/// [`ResponsePerformance`] snapshot.
///
/// `AssistantText` remains the durable assistant payload and does **not**
/// carry `attempt_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistantTextPayload {
    /// Model-context/wire body.
    pub text: String,
    /// The exact final text shown to users when it differs from `text`
    /// (translation success). `None` for legacy/fallback/identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_text: Option<String>,
    /// Finalized (channel + inline) reasoning.
    #[serde(default)]
    pub reasoning: String,
    /// `session_events` row id; `None` when the timeline write failed.
    #[serde(default)]
    pub seq: Option<i64>,
    /// Optional durable response-performance snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_performance: Option<ResponsePerformance>,
}

impl AssistantTextPayload {
    /// The text to display to users: `presentation_text.unwrap_or(text)`.
    /// Live events, daemon history, TUI rehydration, and export all use
    /// this. Model context continues to use `text` only.
    pub fn display_text(&self) -> &str {
        self.presentation_text.as_deref().unwrap_or(&self.text)
    }
}

/// The complete display event emitted by [`DisplayStreamClassifier`].
/// Owns its durable [`AssistantTextPayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayComplete {
    /// The attempt id this complete event belongs to.
    pub attempt_id: AssistantAttemptId,
    /// The durable assistant text payload.
    pub assistant: AssistantTextPayload,
}

/// One classified visible text delta emitted by the classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayTextDelta {
    /// The attempt id this delta belongs to.
    pub attempt_id: AssistantAttemptId,
    /// The classified, Harmony-stripped, whitespace-trimmed visible text.
    pub delta: String,
}

/// One classified reasoning delta emitted by the classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayReasoningDelta {
    /// The attempt id this delta belongs to.
    pub attempt_id: AssistantAttemptId,
    /// The classified reasoning text.
    pub delta: String,
}

/// A display-only (non-durable) reset signal emitted when an attempt fails
/// after visible text. All consumers atomically remove the failed
/// attempt's provisional display; the replacement begins fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayAttemptReset {
    /// The failed attempt whose provisional display must be removed.
    pub failed_attempt_id: AssistantAttemptId,
    /// The replacement attempt that begins fresh.
    pub replacement_attempt_id: AssistantAttemptId,
    /// Why the failed attempt was reset (diagnostics only).
    pub reason: String,
}

/// Why a visible primary attempt ended as a live error row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayErrorKind {
    /// User/daemon cancellation after visible provisional output.
    Cancelled,
    /// Terminal failure after visible provisional output.
    Failed,
}

/// A terminal display error for an attempt. Converts the provisional row
/// into one explicit error row with no performance snapshot.
///
/// `AssistantDisplayError` is terminal: it never follows Complete, preserves
/// the visible provisional body through optional `presentation_text`, and
/// renders one error row (TUI/web/native) or a CLI textual error without a
/// performance chip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayError {
    /// The attempt that failed terminally.
    pub attempt_id: AssistantAttemptId,
    /// Cancelled vs failed.
    pub kind: DisplayErrorKind,
    /// Redacted safe message for the error row.
    pub message: String,
    /// Visible provisional body preserved for the error row, when any.
    pub presentation_text: Option<String>,
}

/// The streaming events the classifier emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayEvent {
    /// A classified visible text delta.
    TextDelta(DisplayTextDelta),
    /// A classified reasoning delta.
    ReasoningDelta(DisplayReasoningDelta),
    /// The complete event owning the durable payload.
    Complete(DisplayComplete),
    /// A display-only reset for a failed attempt after visible text.
    AttemptReset(DisplayAttemptReset),
    /// A terminal display error for an attempt.
    Error(DisplayError),
}

/// Configuration for the classifier.
#[derive(Debug, Clone)]
pub struct DisplayClassifierConfig {
    /// Whether inline `<think>` blocks are classified as thinking (toggle
    /// ON) or response body (toggle OFF).
    pub inline_think: bool,
    /// Whether translation is enabled. When enabled, all raw-language
    /// assistant text deltas are suppressed; the completed body is
    /// translated and only the translated presentation is emitted.
    pub translation_enabled: bool,
    /// The shared tiktoken encoding for counting displayed tokens.
    pub encoding: TiktokenEncoding,
    /// When true, finish omits the performance snapshot without dropping
    /// the reply (simulates tokenizer failure). Production always leaves
    /// this `false`.
    pub force_tokenization_failure: bool,
}

impl Default for DisplayClassifierConfig {
    fn default() -> Self {
        Self {
            inline_think: true,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        }
    }
}

impl DisplayClassifierConfig {
    /// Whether tokenization should be treated as failed for this attempt.
    fn tokenization_failed(&self) -> bool {
        self.force_tokenization_failure
    }
}

/// Engine-owned classifier at the model-stream/event boundary.
///
/// Constructed at exact successful-attempt dispatch with an injected
/// `attempt_dispatched_at` instant. It owns accumulated raw body,
/// incremental think state, Harmony stripping, and whitespace. It emits
/// typed [`DisplayEvent`]s: [`DisplayEvent::TextDelta`] and
/// [`DisplayEvent::ReasoningDelta`] during streaming, then
/// [`DisplayEvent::Complete`] with the durable [`AssistantTextPayload`].
///
/// Only the classifier starts time. TTFT is the first non-whitespace
/// presentation emission minus `attempt_dispatched_at`. The injected
/// clock supplies every timestamp; production must not read a second real
/// clock at finish.
///
/// When translation is disabled, classified text is forwarded
/// incrementally. When enabled, all raw-language deltas are suppressed;
/// the completed body is translated and only the translated presentation
/// is emitted. TTFT then ends at first translated text; all-at-once
/// translated output has zero post-first duration and therefore no TPS
/// snapshot.
pub struct DisplayStreamClassifier {
    /// The attempt id for this display stream.
    attempt_id: AssistantAttemptId,
    /// Injected dispatch instant — TTFT is measured from here.
    attempt_dispatched_at: Instant,
    /// The injected clock. Production uses `Instant::now()`; tests inject
    /// a deterministic clock. The classifier never reads a second real
    /// clock at finish.
    clock: Box<dyn DisplayClock + Send>,
    /// Classifier configuration.
    config: DisplayClassifierConfig,
    /// Incremental think-tag splitter state.
    splitter: ThinkSplitter,
    /// Accumulated raw body (post-think-split, pre-Harmony).
    accumulated_body: String,
    /// Accumulated reasoning (channel + inline).
    accumulated_reasoning: String,
    /// First non-whitespace presentation emission instant. `None` until
    /// the first visible text is emitted.
    first_non_whitespace_presentation_at: Option<Instant>,
    /// Whether any visible (non-whitespace) presentation text has been
    /// emitted. Used to distinguish empty/think-only responses.
    has_visible_body: bool,
    /// Whether translation is enabled (cached from config for clarity).
    translation_enabled: bool,
}

impl std::fmt::Debug for DisplayStreamClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisplayStreamClassifier")
            .field("attempt_id", &self.attempt_id)
            .field("attempt_dispatched_at", &self.attempt_dispatched_at)
            .field("config", &self.config)
            .field("accumulated_body_len", &self.accumulated_body.len())
            .field(
                "accumulated_reasoning_len",
                &self.accumulated_reasoning.len(),
            )
            .field(
                "first_non_whitespace_presentation_at",
                &self.first_non_whitespace_presentation_at,
            )
            .field("has_visible_body", &self.has_visible_body)
            .field("translation_enabled", &self.translation_enabled)
            .finish_non_exhaustive()
    }
}

/// The clock seam the classifier reads. Production uses the real
/// `std::time::Instant`; tests inject a deterministic clock so every
/// timestamp is exact.
pub trait DisplayClock {
    /// Return the current instant.
    fn now(&self) -> Instant;
}

/// Production clock — reads the real `std::time::Instant`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealDisplayClock;

impl DisplayClock for RealDisplayClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A deterministic injected clock for tests. Advances only when
/// [`set`](Self::set) is called.
#[derive(Debug, Default, Clone)]
pub struct InjectedDisplayClock {
    instant: Instant,
}

impl InjectedDisplayClock {
    /// Create a clock pinned to `instant`.
    pub fn new(instant: Instant) -> Self {
        Self { instant }
    }

    /// Advance the clock to `instant`. Must be monotonic (>= the last).
    pub fn set(&mut self, instant: Instant) {
        self.instant = instant;
    }

    /// The current pinned instant.
    pub fn current(&self) -> Instant {
        self.instant
    }
}

impl DisplayClock for InjectedDisplayClock {
    fn now(&self) -> Instant {
        self.instant
    }
}

impl DisplayStreamClassifier {
    /// Construct a new classifier at successful-attempt dispatch.
    ///
    /// `attempt_dispatched_at` is the injected dispatch instant — TTFT is
    /// measured from here. `clock` supplies every later timestamp
    /// (first-presentation, finish); production uses [`RealDisplayClock`],
    /// tests inject [`InjectedDisplayClock`].
    pub fn new(
        attempt_id: AssistantAttemptId,
        attempt_dispatched_at: Instant,
        clock: Box<dyn DisplayClock + Send>,
        config: DisplayClassifierConfig,
    ) -> Self {
        let translation_enabled = config.translation_enabled;
        Self {
            attempt_id,
            attempt_dispatched_at,
            clock,
            config,
            splitter: ThinkSplitter::default(),
            accumulated_body: String::new(),
            accumulated_reasoning: String::new(),
            first_non_whitespace_presentation_at: None,
            has_visible_body: false,
            translation_enabled,
        }
    }

    /// Feed one raw text chunk from the model stream.
    ///
    /// When translation is disabled, this classifies the chunk through the
    /// think splitter and emits [`DisplayEvent::TextDelta`]s for visible
    /// body text. The first non-whitespace body emission records the
    /// first-presentation instant (starting the TTFT/generation clock).
    ///
    /// When translation is enabled, all raw-language deltas are
    /// suppressed — the completed body is translated and emitted only at
    /// [`finish`](Self::finish).
    pub fn feed_text(&mut self, chunk: &str) -> Vec<DisplayEvent> {
        let mut body_out = String::new();
        let mut reasoning_out = String::new();
        let wrote_body = if self.config.inline_think {
            self.splitter.feed(chunk, &mut body_out, &mut reasoning_out)
        } else {
            // Toggle OFF: inline <think> is body. Still accumulate so
            // finish can produce the canonical form.
            body_out.push_str(chunk);
            !body_out.trim().is_empty()
        };

        // Accumulate for the final canonical form regardless of whether we
        // emit deltas now.
        self.accumulated_body.push_str(&body_out);
        if !reasoning_out.is_empty() {
            self.accumulated_reasoning.push_str(&reasoning_out);
        }

        let mut events = Vec::new();

        // Reasoning deltas are always forwarded (they are never translated).
        if !reasoning_out.is_empty() {
            events.push(DisplayEvent::ReasoningDelta(DisplayReasoningDelta {
                attempt_id: self.attempt_id,
                delta: reasoning_out,
            }));
        }

        // Text deltas: only when translation is disabled. When enabled,
        // suppress all raw-language deltas — the translated presentation
        // is emitted at finish.
        if !self.translation_enabled && !body_out.is_empty() {
            // Track first non-whitespace presentation emission for timing.
            if wrote_body
                && !body_out.trim().is_empty()
                && self.first_non_whitespace_presentation_at.is_none()
            {
                self.first_non_whitespace_presentation_at = Some(self.clock.now());
                self.has_visible_body = true;
            }
            events.push(DisplayEvent::TextDelta(DisplayTextDelta {
                attempt_id: self.attempt_id,
                delta: body_out,
            }));
        } else if !self.translation_enabled && wrote_body {
            // wrote_body but body_out is whitespace-only: still mark the
            // first-presentation instant only when non-whitespace arrives.
            // (Whitespace alone does not start the clock.)
        }

        events
    }

    /// Feed one raw reasoning chunk (native `reasoning_content` channel).
    /// Reasoning deltas are always forwarded — they are never translated.
    pub fn feed_reasoning(&mut self, chunk: &str) -> Vec<DisplayEvent> {
        if chunk.is_empty() {
            return Vec::new();
        }
        self.accumulated_reasoning.push_str(chunk);
        vec![DisplayEvent::ReasoningDelta(DisplayReasoningDelta {
            attempt_id: self.attempt_id,
            delta: chunk.to_string(),
        })]
    }

    /// Finish the classifier after the stream completes.
    ///
    /// `choice_text` is the final assembled text from the provider's
    /// choice (used as the canonical `text`/wire body when non-empty, so
    /// the durable form matches the model's output even if streaming
    /// accumulation diverged). `reasoning` is the finalized channel
    /// reasoning. `translated_presentation` is `Some(translated)` when
    /// translation succeeded, `None` when translation was disabled or
    /// failed (fallback emits the original body).
    ///
    /// Returns the [`DisplayComplete`] event (or `None` when there is no
    /// visible body and no reasoning — a body-less, reasoning-less turn
    /// finalizes nothing).
    ///
    /// The finish instant is read from the injected clock — never a
    /// second real clock.
    pub fn finish(
        &mut self,
        choice_text: &str,
        channel_reasoning: &str,
        translated_presentation: Option<String>,
    ) -> Option<DisplayComplete> {
        // Flush any buffered think-splitter state.
        let mut body_tail = String::new();
        let mut reasoning_tail = String::new();
        self.splitter.finish(&mut body_tail, &mut reasoning_tail);
        if !body_tail.is_empty() {
            self.accumulated_body.push_str(&body_tail);
        }
        if !reasoning_tail.is_empty() {
            self.accumulated_reasoning.push_str(&reasoning_tail);
        }

        // Canonical text: prefer the provider's final choice text when
        // non-empty (it is the authoritative assembled form); fall back to
        // our accumulated body.
        let text = if !choice_text.trim().is_empty() {
            // Re-derive the body through split_think so the canonical form
            // matches the one-shot finalization path (the streaming
            // accumulation may have split at different chunk boundaries).
            let (body, _) = crate::engine::think::split_think(choice_text);
            body
        } else {
            self.accumulated_body.clone()
        };

        // Reasoning: channel reasoning + accumulated inline reasoning.
        let reasoning = if channel_reasoning.is_empty() {
            self.accumulated_reasoning.clone()
        } else if self.accumulated_reasoning.is_empty() {
            channel_reasoning.to_string()
        } else {
            format!("{channel_reasoning}\n{}", self.accumulated_reasoning)
        };

        // Determine presentation text. Translation success persists
        // both `text` (model-context/wire body) and `presentation_text`
        // (the translated form shown to users). Silent fallback
        // (translation failed/unavailable/empty) and the disabled case
        // persist only `text` when identical.
        let presentation_text = match &translated_presentation {
            Some(translated) if self.translation_enabled => Some(translated.clone()),
            _ => None,
        };

        // The presentation text whose tokens are counted and whose
        // first-emit instant anchors the clock.
        let display_text = presentation_text.as_deref().unwrap_or(&text).to_string();

        // When translation is enabled, all raw deltas were suppressed
        // during streaming. The first-presentation instant is recorded
        // here (at finish) — for both the translated-success case and the
        // fallback case (translation failed/unavailable/empty: the
        // original completed body is emitted once through the
        // presentation path and measured). All-at-once output has zero
        // post-first duration.
        if self.translation_enabled
            && !display_text.trim().is_empty()
            && self.first_non_whitespace_presentation_at.is_none()
        {
            self.first_non_whitespace_presentation_at = Some(self.clock.now());
            self.has_visible_body = true;
        }

        // Empty/think-only/no-visible-body responses omit the snapshot.
        // Tokenizer failure also omits the snapshot without dropping the reply.
        let performance = if display_text.trim().is_empty() || self.config.tokenization_failed() {
            None
        } else {
            let finish_at = self.clock.now();
            ResponsePerformance::from_measurements(
                self.attempt_dispatched_at,
                self.first_non_whitespace_presentation_at,
                finish_at,
                &display_text,
                self.config.encoding,
            )
        };

        // A body-less, reasoning-less turn finalizes nothing.
        if text.trim().is_empty() && reasoning.trim().is_empty() {
            return None;
        }

        Some(DisplayComplete {
            attempt_id: self.attempt_id,
            assistant: AssistantTextPayload {
                text,
                presentation_text,
                reasoning,
                seq: None, // Stamped by the caller after persistence.
                response_performance: performance,
            },
        })
    }

    /// The attempt id for this classifier's display stream.
    pub fn attempt_id(&self) -> AssistantAttemptId {
        self.attempt_id
    }

    /// Whether any visible (non-whitespace) presentation text has been
    /// emitted so far.
    pub fn has_visible_body(&self) -> bool {
        self.has_visible_body
    }

    /// The first non-whitespace presentation instant, if recorded.
    pub fn first_presentation_at(&self) -> Option<Instant> {
        self.first_non_whitespace_presentation_at
    }

    /// Provisional body text preserved for a terminal error row when the
    /// attempt fails/cancels after visible output.
    pub fn accumulated_presentation_for_error(&self) -> String {
        self.accumulated_body.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a classifier with an injected clock pinned to `t0`.
    fn make_classifier(
        attempt_id: u64,
        t0: Instant,
        config: DisplayClassifierConfig,
    ) -> (
        DisplayStreamClassifier,
        std::rc::Rc<std::cell::RefCell<InjectedDisplayClock>>,
    ) {
        let clock = std::rc::Rc::new(std::cell::RefCell::new(InjectedDisplayClock::new(t0)));
        let send_clock = RcClock(clock.clone());
        let classifier = DisplayStreamClassifier::new(
            AssistantAttemptId::new(attempt_id),
            t0,
            Box::new(send_clock),
            config,
        );
        (classifier, clock)
    }

    /// Wrapper to make `Rc<RefCell<InjectedDisplayClock>>` Send for tests.
    /// This is safe in single-threaded tests.
    struct RcClock(std::rc::Rc<std::cell::RefCell<InjectedDisplayClock>>);

    impl DisplayClock for RcClock {
        fn now(&self) -> Instant {
            self.0.borrow().current()
        }
    }

    // Safety: RcClock is only used in single-threaded tests. We implement
    // Send manually so the classifier can own it behind `Box<dyn Send>`.
    unsafe impl Send for RcClock {}

    fn ms(milliseconds: u64) -> Duration {
        Duration::from_millis(milliseconds)
    }

    fn instant_after(base: Instant, dur: Duration) -> Instant {
        Instant::from_std(base.as_std() + dur)
    }

    #[test]
    fn response_performance_engine_display_classifier_emits_visible_events() {
        // Streaming branch: text deltas forwarded, TTFT/generation/TPS exact.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: true,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(1, t0, config);

        // First chunk: leading whitespace + first visible text.
        // Whitespace alone does not start the clock; the first
        // non-whitespace presentation emission does.
        clock.borrow_mut().set(instant_after(t0, ms(100)));
        let events = classifier.feed_text("   Hello");
        assert_eq!(events.len(), 1);
        match &events[0] {
            DisplayEvent::TextDelta(delta) => {
                assert_eq!(delta.attempt_id, AssistantAttemptId::new(1));
                assert_eq!(delta.delta, "   Hello");
            }
            other => panic!("expected TextDelta, got {other:?}"),
        }
        assert_eq!(
            classifier.first_presentation_at(),
            Some(instant_after(t0, ms(100)))
        );

        // Second chunk at t0+300ms.
        clock.borrow_mut().set(instant_after(t0, ms(300)));
        let events = classifier.feed_text(" world");
        assert_eq!(events.len(), 1);

        // Finish at t0+500ms.
        clock.borrow_mut().set(instant_after(t0, ms(500)));
        let complete = classifier
            .finish("   Hello world", "", None)
            .expect("non-empty body should complete");

        let perf = complete
            .assistant
            .response_performance
            .as_ref()
            .expect("streaming branch should have performance");
        // TTFT = 100ms (first non-whitespace at t0+100, dispatch at t0).
        assert_eq!(perf.ttft_ms, 100);
        // generation_ms = 500 - 100 = 400ms.
        assert_eq!(perf.generation_ms, 400);
        // TPS = displayed_tokens / generation_ms * 1000.
        let expected_tokens = TiktokenEncoding::Cl100k.count("   Hello world") as u64;
        assert_eq!(perf.displayed_tokens, expected_tokens);
        let tps = perf.tps().expect("non-zero generation should have TPS");
        assert!((tps - expected_tokens as f64 * 1000.0 / 400.0).abs() < 0.001);
    }

    #[test]
    fn response_performance_think_only_omits_snapshot() {
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig::default();
        let (mut classifier, _clock) = make_classifier(1, t0, config);

        // A think-only turn: reasoning but no body.
        classifier.feed_text("<think>internal reasoning</think>");
        let complete = classifier.finish("", "", None);

        // Think-only with no body text but reasoning should still complete
        // (reasoning survives) but with no performance snapshot.
        if let Some(complete) = complete {
            assert!(complete.assistant.response_performance.is_none());
            assert!(!complete.assistant.reasoning.is_empty());
        }
        // If it returns None that's also acceptable (body-less, but
        // reasoning is non-empty so it should complete).
    }

    #[test]
    fn response_performance_empty_response_omits_snapshot() {
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig::default();
        let (mut classifier, _clock) = make_classifier(1, t0, config);

        // No text, no reasoning → finalizes nothing.
        let complete = classifier.finish("", "", None);
        assert!(complete.is_none());
    }

    #[test]
    fn response_performance_translation_measures_displayed_user_experience() {
        // Translation enabled: raw deltas suppressed, translated body
        // emitted at finish, TTFT ends at first translated text,
        // all-at-once translated output has zero post-first duration.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: true,
            translation_enabled: true,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(1, t0, config);

        // Raw deltas are suppressed during streaming.
        let events = classifier.feed_text("Bonjour le monde");
        assert!(events.is_empty(), "translation should suppress raw deltas");
        assert!(
            !classifier.has_visible_body(),
            "no visible body until translated presentation"
        );

        // Finish with a translated presentation. The clock is at t0+200ms
        // (simulating the translation call taking 200ms).
        clock.borrow_mut().set(instant_after(t0, ms(200)));
        let complete = classifier
            .finish("Bonjour le monde", "", Some("Hello world".to_string()))
            .expect("translated body should complete");

        // Presentation text is the translated form.
        assert_eq!(
            complete.assistant.presentation_text.as_deref(),
            Some("Hello world")
        );
        assert_eq!(complete.assistant.text, "Bonjour le monde");

        let perf = complete
            .assistant
            .response_performance
            .as_ref()
            .expect("translated response should have performance");
        // TTFT = 200ms (first translated text at t0+200, dispatch at t0).
        assert_eq!(perf.ttft_ms, 200);
        // All-at-once translated: generation_ms = 0 (finish == first-presentation).
        assert_eq!(perf.generation_ms, 0);
        // Zero generation → no TPS.
        assert!(perf.tps().is_none());
        // Token count is for the translated presentation text.
        let expected_tokens = TiktokenEncoding::Cl100k.count("Hello world") as u64;
        assert_eq!(perf.displayed_tokens, expected_tokens);
    }

    #[test]
    fn response_performance_translation_fallback_displays_and_measures_original() {
        // Translation enabled but failed (None): emit the original body
        // once through the presentation path, measure it, never release
        // suppressed raw deltas late.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: true,
            translation_enabled: true,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(1, t0, config);

        // Raw deltas suppressed.
        classifier.feed_text("Hello world");

        // Finish with NO translation (fallback). The original body is
        // emitted at finish through the presentation path.
        clock.borrow_mut().set(instant_after(t0, ms(150)));
        let complete = classifier
            .finish("Hello world", "", None)
            .expect("fallback body should complete");

        // Fallback: presentation_text is None (identical to text).
        assert!(complete.assistant.presentation_text.is_none());
        assert_eq!(complete.assistant.text, "Hello world");

        let perf = complete
            .assistant
            .response_performance
            .as_ref()
            .expect("fallback should have performance");
        // TTFT = 150ms (first-presentation at finish, dispatch at t0).
        assert_eq!(perf.ttft_ms, 150);
        // All-at-once fallback: generation_ms = 0.
        assert_eq!(perf.generation_ms, 0);
    }

    #[test]
    fn response_performance_split_token_boundary() {
        // BPE tokens split across stream chunks have the same result as
        // unsplit text — counting happens only at finish on the canonical
        // presentation text.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(1, t0, config.clone());

        // Feed "Hello world" split across two chunks.
        clock.borrow_mut().set(instant_after(t0, ms(100)));
        classifier.feed_text("Hello ");
        clock.borrow_mut().set(instant_after(t0, ms(200)));
        classifier.feed_text("world");
        clock.borrow_mut().set(instant_after(t0, ms(300)));
        let complete_chunked = classifier.finish("Hello world", "", None).unwrap();

        // Compare with a single-chunk feed.
        let (mut classifier2, clock2) = make_classifier(2, t0, config);
        clock2.borrow_mut().set(instant_after(t0, ms(100)));
        classifier2.feed_text("Hello world");
        clock2.borrow_mut().set(instant_after(t0, ms(300)));
        let complete_single = classifier2.finish("Hello world", "", None).unwrap();

        // Token counts must match regardless of chunking.
        assert_eq!(
            complete_chunked
                .assistant
                .response_performance
                .as_ref()
                .unwrap()
                .displayed_tokens,
            complete_single
                .assistant
                .response_performance
                .as_ref()
                .unwrap()
                .displayed_tokens
        );
    }

    #[test]
    fn response_performance_round_trips_through_serde() {
        let perf = ResponsePerformance {
            ttft_ms: 120,
            generation_ms: 340,
            displayed_tokens: 42,
            encoding: TiktokenEncoding::O200k,
        };
        let json = serde_json::to_string(&perf).unwrap();
        let back: ResponsePerformance = serde_json::from_str(&json).unwrap();
        assert_eq!(perf, back);
        // The JSON keys match the spec: ttft_ms, generation_ms,
        // displayed_tokens, encoding.
        assert!(json.contains("\"ttft_ms\""));
        assert!(json.contains("\"generation_ms\""));
        assert!(json.contains("\"displayed_tokens\""));
        assert!(json.contains("\"encoding\""));
    }

    #[test]
    fn response_performance_absent_legacy_field_round_trips() {
        // A legacy AssistantTextPayload without response_performance /
        // presentation_text must still deserialize.
        let legacy = serde_json::json!({
            "text": "hello",
            "reasoning": "",
            "seq": 7
        });
        let payload: AssistantTextPayload = serde_json::from_value(legacy).unwrap();
        assert_eq!(payload.text, "hello");
        assert_eq!(payload.seq, Some(7));
        assert!(payload.presentation_text.is_none());
        assert!(payload.response_performance.is_none());
        // display_text falls back to text.
        assert_eq!(payload.display_text(), "hello");
    }

    #[test]
    fn assistant_attempt_id_is_opaque_and_monotonic() {
        let a = AssistantAttemptId::new(1);
        let b = AssistantAttemptId::new(2);
        assert_ne!(a, b);
        assert_eq!(a.as_u64(), 1);
        assert_eq!(format!("{a}"), "attempt-1");
    }

    #[test]
    fn assistant_text_payload_display_text_uses_presentation_when_present() {
        let payload = AssistantTextPayload {
            text: "Bonjour".to_string(),
            presentation_text: Some("Hello".to_string()),
            reasoning: String::new(),
            seq: None,
            response_performance: None,
        };
        assert_eq!(payload.display_text(), "Hello");
    }

    #[test]
    fn display_attempt_reset_carries_failed_and_replacement_ids() {
        let reset = DisplayAttemptReset {
            failed_attempt_id: AssistantAttemptId::new(1),
            replacement_attempt_id: AssistantAttemptId::new(2),
            reason: "timeout".to_string(),
        };
        assert_eq!(reset.failed_attempt_id.as_u64(), 1);
        assert_eq!(reset.replacement_attempt_id.as_u64(), 2);
    }

    #[test]
    fn response_performance_stream_visible_user_body_timing() {
        // Injected clock: whitespace alone does not start TTFT; first
        // non-whitespace presentation does; generation_ms is finish - first.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: true,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(7, t0, config);

        clock.borrow_mut().set(instant_after(t0, ms(50)));
        let _ = classifier.feed_text("   ");
        assert!(
            classifier.first_presentation_at().is_none(),
            "whitespace alone must not start TTFT"
        );

        clock.borrow_mut().set(instant_after(t0, ms(250)));
        let events = classifier.feed_text("Hi");
        assert_eq!(events.len(), 1);
        assert_eq!(
            classifier.first_presentation_at(),
            Some(instant_after(t0, ms(250)))
        );

        clock.borrow_mut().set(instant_after(t0, ms(850)));
        let complete = classifier
            .finish("Hi there", "", None)
            .expect("visible body completes");
        let perf = complete
            .assistant
            .response_performance
            .expect("nonzero-duration visible body has snapshot");
        assert_eq!(perf.ttft_ms, 250);
        assert_eq!(perf.generation_ms, 600);
        let tokens = TiktokenEncoding::Cl100k.count("Hi there") as u64;
        assert_eq!(perf.displayed_tokens, tokens);
        let tps = perf.tps().expect("nonzero generation has TPS");
        assert!((tps - tokens as f64 * 1000.0 / 600.0).abs() < 0.001);
        assert_eq!(complete.attempt_id.as_u64(), 7);
    }

    #[test]
    fn response_performance_tokenization_failure_omits_metrics_without_dropping_reply() {
        // Force tokenizer failure: reply must still complete; snapshot omitted.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: true,
        };
        let (mut classifier, clock) = make_classifier(3, t0, config);
        clock.borrow_mut().set(instant_after(t0, ms(10)));
        classifier.feed_text("Keep this reply");
        clock.borrow_mut().set(instant_after(t0, ms(50)));
        let complete = classifier
            .finish("Keep this reply", "", None)
            .expect("tokenization failure must not drop the reply");
        assert_eq!(complete.assistant.text, "Keep this reply");
        assert!(
            complete.assistant.response_performance.is_none(),
            "tokenizer failure omits the snapshot"
        );
    }

    #[test]
    fn response_performance_live_event_survives_assistant_message_write_failure() {
        // Live Complete keeps its computed snapshot even when seq is None
        // (timeline write failed). Durable rehydration then omits it.
        let t0 = Instant::from_std(std::time::Instant::now());
        let config = DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        };
        let (mut classifier, clock) = make_classifier(4, t0, config);
        clock.borrow_mut().set(instant_after(t0, ms(20)));
        classifier.feed_text("Live body");
        clock.borrow_mut().set(instant_after(t0, ms(120)));
        let mut complete = classifier.finish("Live body", "", None).unwrap();
        assert!(complete.assistant.response_performance.is_some());
        // Simulate write failure: seq stays None; live event retains snapshot.
        complete.assistant.seq = None;
        assert!(complete.assistant.response_performance.is_some());
        assert_eq!(complete.assistant.display_text(), "Live body");
        // Durable wire payload without seq still carries performance for the
        // live event; persistence failure is seq=None, not snapshot drop.
        let live_json = serde_json::to_value(&complete.assistant).unwrap();
        assert!(live_json.get("response_performance").is_some());
        assert!(live_json.get("seq").is_none() || live_json["seq"].is_null());
    }

    #[test]
    fn response_performance_round_trips_through_assistant_wire_history() {
        let perf = ResponsePerformance {
            ttft_ms: 120,
            generation_ms: 340,
            displayed_tokens: 42,
            encoding: TiktokenEncoding::O200k,
        };
        let payload = AssistantTextPayload {
            text: "wire body".into(),
            presentation_text: Some("shown".into()),
            reasoning: "think".into(),
            seq: Some(9),
            response_performance: Some(perf),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["response_performance"]["ttft_ms"], 120);
        assert_eq!(json["response_performance"]["encoding"], "o200k_base");
        assert!(json.get("attempt_id").is_none());
        let back: AssistantTextPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back, payload);
        assert_eq!(back.display_text(), "shown");

        // Wire HistoryEntry shape (proto) round-trips without attempt_id.
        let history = crate::daemon::proto::HistoryEntry::Assistant {
            agent: "Build".into(),
            text: "wire body".into(),
            presentation_text: Some("shown".into()),
            reasoning: "think".into(),
            response_performance: Some(crate::daemon::proto::ResponsePerformance {
                ttft_ms: 120,
                generation_ms: 340,
                displayed_tokens: 42,
                encoding: "o200k_base".into(),
            }),
            ts_ms: 1,
            seq: 9,
        };
        let hist_json = serde_json::to_value(&history).unwrap();
        assert!(hist_json.get("attempt_id").is_none());
        let hist_back: crate::daemon::proto::HistoryEntry =
            serde_json::from_value(hist_json).unwrap();
        match hist_back {
            crate::daemon::proto::HistoryEntry::Assistant {
                response_performance: Some(p),
                presentation_text,
                ..
            } => {
                assert_eq!(p.ttft_ms, 120);
                assert_eq!(presentation_text.as_deref(), Some("shown"));
            }
            other => panic!("expected Assistant history, got {other:?}"),
        }
    }
}
