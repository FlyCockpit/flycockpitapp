//! Production wiring for [`DisplayStreamClassifier`] at successful-attempt
//! dispatch. Constructed once the provider stream is live; emits typed
//! `AssistantDisplay*` turn events; leaves the open classifier for the turn
//! phase to finish after translation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::engine::agent::TurnEvent;
use crate::engine::response_performance::DisplayComplete;
use crate::engine::response_performance::{
    AssistantAttemptId, DisplayClassifierConfig, DisplayClock, DisplayEvent,
    DisplayStreamClassifier, DisplayTokenizer, EncodingDisplayTokenizer, Instant, RealDisplayClock,
};

/// Crate-private clock factory. Production [`DisplayAttemptSlot::new`]
/// supplies [`RealDisplayClock`]; the e2e driver injects a manual clock
/// through the same seam.
pub(crate) type DisplayClockFactory = Arc<dyn Fn() -> Box<dyn DisplayClock + Send> + Send + Sync>;

/// Monotonic attempt-id allocator for live display correlation. Process-wide
/// so concurrent sessions never collide; never persisted.
static NEXT_ASSISTANT_ATTEMPT_ID: AtomicU64 = AtomicU64::new(1);

/// Shared mutable slot owned by one `complete_*` call. The successful
/// attempt's classifier is left here for turn-phase finish.
#[derive(Clone)]
pub(crate) struct DisplayAttemptSlot(Arc<Mutex<DisplayAttemptSlotInner>>);

struct DisplayAttemptSlotInner {
    config: DisplayClassifierConfig,
    classifier: Option<DisplayStreamClassifier>,
    previous_failed_visible: Option<(AssistantAttemptId, String)>,
    clock_factory: DisplayClockFactory,
    tokenizer: Arc<dyn DisplayTokenizer>,
    response_window_closed: Arc<std::sync::atomic::AtomicBool>,
}

impl DisplayAttemptSlot {
    pub(crate) fn new(config: DisplayClassifierConfig) -> Self {
        let tokenizer: Arc<dyn DisplayTokenizer> = Arc::new(EncodingDisplayTokenizer {
            encoding: config.encoding,
            force_failure: config.force_tokenization_failure,
        });
        Self::new_with_clock_tokenizer_and_window(
            config,
            Arc::new(|| Box::new(RealDisplayClock)),
            tokenizer,
            Arc::default(),
        )
    }

    /// Test/e2e constructor: same dispatcher object as production, with an
    /// injected clock factory and tokenizer. Production
    /// [`new`](Self::new) supplies [`RealDisplayClock`] and
    /// [`EncodingDisplayTokenizer`].
    pub(crate) fn new_with_clock_and_tokenizer(
        config: DisplayClassifierConfig,
        clock_factory: DisplayClockFactory,
        tokenizer: Arc<dyn DisplayTokenizer>,
    ) -> Self {
        Self::new_with_clock_tokenizer_and_window(config, clock_factory, tokenizer, Arc::default())
    }

    pub(crate) fn new_with_response_window(
        config: DisplayClassifierConfig,
        response_window_closed: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let tokenizer: Arc<dyn DisplayTokenizer> = Arc::new(EncodingDisplayTokenizer {
            encoding: config.encoding,
            force_failure: config.force_tokenization_failure,
        });
        Self::new_with_clock_tokenizer_and_window(
            config,
            Arc::new(|| Box::new(RealDisplayClock)),
            tokenizer,
            response_window_closed,
        )
    }

    fn new_with_clock_tokenizer_and_window(
        config: DisplayClassifierConfig,
        clock_factory: DisplayClockFactory,
        tokenizer: Arc<dyn DisplayTokenizer>,
        response_window_closed: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self(Arc::new(Mutex::new(DisplayAttemptSlotInner {
            config,
            classifier: None,
            previous_failed_visible: None,
            clock_factory,
            tokenizer,
            response_window_closed,
        })))
    }

    /// Allocate attempt id + construct classifier at successful-attempt
    /// dispatch (stream is live). Emits Reset when a prior visible attempt
    /// failed (explicit [`mark_failed_visible`] or an open classifier left
    /// after a drained attempt failed and a replacement is starting).
    pub(crate) async fn begin_successful_attempt(
        &self,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        dispatched_at: std::time::Instant,
    ) {
        self.begin_successful_attempt_at(agent_name, event_tx, Instant::from_std(dispatched_at))
            .await;
    }

    pub(crate) async fn begin_successful_attempt_at(
        &self,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        dispatched_at: Instant,
    ) {
        let reset = {
            let mut inner = self.0.lock().expect("display attempt slot");
            let replacement =
                AssistantAttemptId::new(NEXT_ASSISTANT_ATTEMPT_ID.fetch_add(1, Ordering::SeqCst));
            // Prefer an explicitly armed failure; otherwise absorb an open
            // visible classifier left by a failed drain so the replacement
            // emits Reset (and never Error for that attempt).
            let from_open = match inner.classifier.take() {
                Some(classifier) if classifier.has_visible_body() => {
                    Some((classifier.attempt_id(), "stream attempt failed".to_string()))
                }
                _ => None,
            };
            let reset = inner
                .previous_failed_visible
                .take()
                .or(from_open)
                .map(|(failed, reason)| (failed, replacement, reason));
            let clock = (inner.clock_factory)();
            inner.classifier = Some(DisplayStreamClassifier::new_with_tokenizer(
                replacement,
                dispatched_at,
                clock,
                inner.config.clone(),
                Arc::clone(&inner.tokenizer),
            ));
            reset
        };
        if let Some((failed, replacement, reason)) = reset
            && let Some(tx) = event_tx
        {
            let _ = tx
                .send(TurnEvent::AssistantDisplayAttemptReset {
                    agent: agent_name.to_string(),
                    failed_attempt_id: failed,
                    replacement_attempt_id: replacement,
                    reason,
                })
                .await;
        }
    }

    pub(crate) async fn feed_text(
        &self,
        agent_name: &str,
        chunk: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
    ) {
        let events = {
            let mut inner = self.0.lock().expect("display attempt slot");
            let Some(classifier) = inner.classifier.as_mut() else {
                return;
            };
            let events = classifier.feed_text(chunk);
            let has_response_text = classifier.has_response_text();
            if has_response_text {
                inner
                    .response_window_closed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            events
        };
        emit_display_events(agent_name, events, event_tx).await;
    }

    pub(crate) fn close_response_window(&self) {
        self.0
            .lock()
            .expect("display attempt slot")
            .response_window_closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) async fn feed_reasoning(
        &self,
        agent_name: &str,
        chunk: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
    ) {
        let events = {
            let mut inner = self.0.lock().expect("display attempt slot");
            let Some(classifier) = inner.classifier.as_mut() else {
                return;
            };
            classifier.feed_reasoning(chunk)
        };
        emit_display_events(agent_name, events, event_tx).await;
    }

    /// Record that the current attempt failed after visible output so the
    /// next attempt emits Reset first. Prefer leaving the classifier open
    /// after a drain failure (production): the next
    /// [`begin_successful_attempt`] absorbs it. This remains for explicit
    /// arming when the classifier must be taken early.
    #[allow(dead_code)]
    pub(crate) fn mark_failed_visible(&self, reason: impl Into<String>) {
        let mut inner = self.0.lock().expect("display attempt slot");
        if let Some(classifier) = inner.classifier.take()
            && classifier.has_visible_body()
        {
            inner.previous_failed_visible = Some((classifier.attempt_id(), reason.into()));
        }
    }

    /// Take the open classifier for turn-phase finish (successful attempt).
    pub(crate) fn take_open_classifier(&self) -> Option<DisplayStreamClassifier> {
        self.0
            .lock()
            .expect("display attempt slot")
            .classifier
            .take()
    }

    /// Terminal failure/cancel after visible provisional output: emit one
    /// `AssistantDisplayError` row (no performance chip). Attempts with no
    /// visible body emit nothing. Does not arm Reset for a replacement.
    pub(crate) async fn finish_as_error(
        &self,
        agent_name: &str,
        kind: crate::engine::response_performance::DisplayErrorKind,
        message: impl Into<String>,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
    ) -> bool {
        let err = {
            let mut inner = self.0.lock().expect("display attempt slot");
            let Some(classifier) = inner.classifier.take() else {
                return false;
            };
            if !classifier.has_visible_body() {
                return false;
            }
            // Drop any pending reset arming — this attempt is terminal.
            inner.previous_failed_visible = None;
            crate::engine::response_performance::DisplayError {
                attempt_id: classifier.attempt_id(),
                kind,
                message: message.into(),
                presentation_text: {
                    // Preserve whatever provisional body the classifier saw.
                    let body = classifier.accumulated_presentation_for_error();
                    if body.trim().is_empty() {
                        None
                    } else {
                        Some(body)
                    }
                },
            }
        };
        emit_display_events(agent_name, vec![DisplayEvent::Error(err)], event_tx).await;
        true
    }
}

pub(crate) fn finish_open_display_classifier(
    classifier: &mut DisplayStreamClassifier,
    choice_text: &str,
    channel_reasoning: &str,
    translated_presentation: Option<String>,
) -> Option<DisplayComplete> {
    classifier.finish(choice_text, channel_reasoning, translated_presentation)
}

pub(crate) fn assistant_display_complete_turn_event(
    agent_name: &str,
    complete: DisplayComplete,
) -> TurnEvent {
    TurnEvent::AssistantDisplayComplete {
        agent: agent_name.to_string(),
        attempt_id: complete.attempt_id,
        assistant: complete.assistant,
    }
}

async fn emit_display_events(
    agent_name: &str,
    events: Vec<DisplayEvent>,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
) {
    let Some(tx) = event_tx else {
        return;
    };
    for event in events {
        let turn = match event {
            DisplayEvent::TextDelta(delta) => TurnEvent::AssistantDisplayTextDelta {
                agent: agent_name.to_string(),
                attempt_id: delta.attempt_id,
                delta: delta.delta,
            },
            DisplayEvent::ReasoningDelta(delta) => TurnEvent::AssistantDisplayReasoningDelta {
                agent: agent_name.to_string(),
                attempt_id: delta.attempt_id,
                delta: delta.delta,
            },
            DisplayEvent::Complete(complete) => {
                assistant_display_complete_turn_event(agent_name, complete)
            }
            DisplayEvent::AttemptReset(reset) => TurnEvent::AssistantDisplayAttemptReset {
                agent: agent_name.to_string(),
                failed_attempt_id: reset.failed_attempt_id,
                replacement_attempt_id: reset.replacement_attempt_id,
                reason: reset.reason,
            },
            DisplayEvent::Error(err) => TurnEvent::AssistantDisplayError {
                agent: agent_name.to_string(),
                attempt_id: err.attempt_id,
                kind: err.kind,
                message: err.message,
                presentation_text: err.presentation_text,
            },
        };
        let _ = tx.send(turn).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn response_window_ignores_reasoning_and_closes_on_body_or_tool() {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let slot = DisplayAttemptSlot::new_with_response_window(
            DisplayClassifierConfig {
                inline_think: true,
                translation_enabled: false,
                encoding: TiktokenEncoding::Cl100k,
                force_tokenization_failure: false,
            },
            Arc::clone(&closed),
        );
        slot.begin_successful_attempt("main", None, std::time::Instant::now())
            .await;
        slot.feed_reasoning("main", "thinking", None).await;
        assert!(!closed.load(std::sync::atomic::Ordering::SeqCst));
        slot.feed_text("main", "answer", None).await;
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));

        closed.store(false, std::sync::atomic::Ordering::SeqCst);
        slot.close_response_window();
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    }
    use cockpit_tokenizer::TiktokenEncoding;

    #[tokio::test]
    async fn response_performance_retry_backup_and_tool_rounds_are_attempt_scoped() {
        let slot = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx, mut rx) = mpsc::channel(16);
        let t0 = std::time::Instant::now();

        slot.begin_successful_attempt("main", Some(&tx), t0).await;
        slot.feed_text("main", "primary partial", Some(&tx)).await;
        let first_delta = rx.recv().await.expect("primary delta");
        let primary_id = match first_delta {
            TurnEvent::AssistantDisplayTextDelta { attempt_id, .. } => attempt_id,
            other => panic!("expected primary delta, got {other:?}"),
        };

        // Production leaves the open visible classifier after a failed drain;
        // the next begin absorbs it and emits Reset (no Error for retries).
        slot.begin_successful_attempt("main", Some(&tx), t0).await;
        let reset = rx.recv().await.expect("reset before replacement");
        let (failed, replacement) = match reset {
            TurnEvent::AssistantDisplayAttemptReset {
                failed_attempt_id,
                replacement_attempt_id,
                reason,
                ..
            } => {
                assert_eq!(failed_attempt_id, primary_id);
                assert_eq!(reason, "stream attempt failed");
                (failed_attempt_id, replacement_attempt_id)
            }
            other => panic!("expected AttemptReset, got {other:?}"),
        };
        assert_ne!(failed, replacement, "attempts are independently scoped");

        slot.feed_text("main", "backup body", Some(&tx)).await;
        let second_delta = rx.recv().await.expect("backup delta");
        match second_delta {
            TurnEvent::AssistantDisplayTextDelta { attempt_id, .. } => {
                assert_eq!(attempt_id, replacement);
            }
            other => panic!("expected backup delta, got {other:?}"),
        }
        assert_eq!(
            slot.take_open_classifier()
                .expect("open backup classifier")
                .attempt_id(),
            replacement
        );
    }

    #[tokio::test]
    async fn response_performance_classifier_constructed_at_attempt_dispatch() {
        let slot = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: true,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx, mut rx) = mpsc::channel(8);
        let t0 = std::time::Instant::now();
        slot.begin_successful_attempt("main", Some(&tx), t0).await;
        assert!(slot.0.lock().unwrap().classifier.is_some());
        slot.feed_text("main", "Hi", Some(&tx)).await;
        let event = rx.recv().await.expect("typed delta");
        match event {
            TurnEvent::AssistantDisplayTextDelta {
                attempt_id, delta, ..
            } => {
                assert!(attempt_id.as_u64() > 0);
                assert_eq!(delta, "Hi");
            }
            other => panic!("expected AssistantDisplayTextDelta, got {other:?}"),
        }
        assert!(slot.take_open_classifier().is_some());
    }

    #[tokio::test]
    async fn visible_primary_partial_terminal_failure_or_cancel_becomes_error_row() {
        use crate::config::providers::TimeoutConfig;
        use crate::engine::response_performance::DisplayErrorKind;
        use futures::stream;
        use rig::streaming::StreamedAssistantContent;

        // Production path: drain_items feeds the classifier, then the same
        // finish_as_error seam dispatch.rs Err arms call (~1083/1128).
        let slot = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx, mut rx) = mpsc::channel(16);
        let t0 = std::time::Instant::now();
        slot.begin_successful_attempt("main", Some(&tx), t0).await;

        let mut stream = Box::pin(stream::iter(vec![
            Ok::<_, rig::completion::CompletionError>(StreamedAssistantContent::text(
                "partial visible",
            )),
        ]));
        let timeout = TimeoutConfig {
            ttft_secs: 30,
            idle_secs: 30,
        };
        let phase = std::sync::atomic::AtomicU8::new(0);
        let first_token_ms = std::sync::atomic::AtomicU64::new(0);
        let output_sent = std::sync::atomic::AtomicBool::new(false);
        let cancel = tokio_util::sync::CancellationToken::new();
        let drain_res = super::super::drain_items(
            &mut stream,
            &timeout,
            false,
            &phase,
            t0,
            &first_token_ms,
            "main",
            "local",
            "test-model",
            Some(&tx),
            &cancel,
            &output_sent,
            Some(&slot),
        )
        .await;
        assert!(
            drain_res.is_ok(),
            "drain of one chunk must succeed: {drain_res:?}"
        );
        let _ = rx.recv().await.expect("typed delta from drain");

        // Terminal failure after visible partial (production Err arm).
        slot.finish_as_error(
            "main",
            DisplayErrorKind::Failed,
            "provider failed",
            Some(&tx),
        )
        .await;
        let event = rx.recv().await.expect("error row");
        match event {
            TurnEvent::AssistantDisplayError {
                attempt_id,
                kind,
                message,
                presentation_text,
                ..
            } => {
                assert!(attempt_id.as_u64() > 0);
                assert_eq!(kind, DisplayErrorKind::Failed);
                assert_eq!(message, "provider failed");
                assert_eq!(presentation_text.as_deref(), Some("partial visible"));
            }
            other => panic!("expected AssistantDisplayError, got {other:?}"),
        }
        assert!(slot.take_open_classifier().is_none());

        // Cancel after visible partial via production cancel + finish_as_error.
        let slot_c = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx_c, mut rx_c) = mpsc::channel(8);
        slot_c
            .begin_successful_attempt("main", Some(&tx_c), t0)
            .await;
        slot_c
            .feed_text("main", "cancelled body", Some(&tx_c))
            .await;
        let _ = rx_c.recv().await.expect("cancel delta");
        slot_c
            .finish_as_error(
                "main",
                DisplayErrorKind::Cancelled,
                "cancelled",
                Some(&tx_c),
            )
            .await;
        match rx_c.recv().await.expect("cancel error") {
            TurnEvent::AssistantDisplayError {
                kind,
                presentation_text,
                ..
            } => {
                assert_eq!(kind, DisplayErrorKind::Cancelled);
                assert_eq!(presentation_text.as_deref(), Some("cancelled body"));
            }
            other => panic!("expected cancelled AssistantDisplayError, got {other:?}"),
        }

        // No-visible attempt emits no error row.
        let slot2 = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx2, mut rx2) = mpsc::channel(8);
        slot2.begin_successful_attempt("main", Some(&tx2), t0).await;
        slot2
            .finish_as_error("main", DisplayErrorKind::Cancelled, "cancelled", Some(&tx2))
            .await;
        assert!(rx2.try_recv().is_err(), "no-visible cancel emits no row");
    }

    #[tokio::test]
    async fn response_performance_engine_dispatch_emits_typed_lifecycle() {
        use crate::config::providers::TimeoutConfig;
        use futures::stream;
        use rig::streaming::StreamedAssistantContent;

        // Stream fake deltas through production drain_items → finish →
        // nonzero snapshot fields (chip input).
        let slot = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx, mut rx) = mpsc::channel(16);
        let t0 = std::time::Instant::now();
        slot.begin_successful_attempt("Build", Some(&tx), t0).await;

        let mut stream = Box::pin(stream::iter(vec![
            Ok::<_, rig::completion::CompletionError>(StreamedAssistantContent::text("Hello ")),
            Ok(StreamedAssistantContent::text("world")),
        ]));
        let timeout = TimeoutConfig {
            ttft_secs: 30,
            idle_secs: 30,
        };
        let phase = std::sync::atomic::AtomicU8::new(0);
        let first_token_ms = std::sync::atomic::AtomicU64::new(0);
        let output_sent = std::sync::atomic::AtomicBool::new(false);
        let cancel = tokio_util::sync::CancellationToken::new();
        let drain_res = super::super::drain_items(
            &mut stream,
            &timeout,
            false,
            &phase,
            t0,
            &first_token_ms,
            "Build",
            "local",
            "test-model",
            Some(&tx),
            &cancel,
            &output_sent,
            Some(&slot),
        )
        .await;
        assert!(drain_res.is_ok(), "e2e drain must succeed: {drain_res:?}");

        let mut deltas = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            deltas.push(ev);
        }
        assert!(
            deltas
                .iter()
                .any(|e| matches!(e, TurnEvent::AssistantDisplayTextDelta { .. })),
            "typed deltas must reach the consumer via drain_items"
        );
        assert!(
            !deltas
                .iter()
                .any(|e| matches!(e, TurnEvent::AssistantTextDelta { .. })),
            "raw AssistantTextDelta must not drive the live chip path when display is wired"
        );
        let mut classifier = slot.take_open_classifier().expect("open classifier");
        let complete = classifier
            .finish("Hello world", "", None)
            .expect("complete");
        let perf = complete
            .assistant
            .response_performance
            .expect("streamed body yields snapshot for the clickable chip");
        assert!(perf.ttft_ms > 0 || perf.displayed_tokens > 0);
        assert!(perf.displayed_tokens > 0);
        assert_eq!(
            TiktokenEncoding::Cl100k.count("Hello world") as u64,
            perf.displayed_tokens
        );

        // Production terminal path: finish_as_error is what dispatch.rs Err
        // arms call (not mark_failed_visible). Exercise that emission seam
        // after a successful drain so the typed error row is reachable from
        // the same DisplayAttemptSlot consumers use in production.
        let slot_err = DisplayAttemptSlot::new(DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        });
        let (tx_err, mut rx_err) = mpsc::channel(8);
        slot_err
            .begin_successful_attempt("Build", Some(&tx_err), t0)
            .await;
        slot_err
            .feed_text("Build", "chip body", Some(&tx_err))
            .await;
        let _ = rx_err.recv().await.expect("typed delta");
        // Mirror dispatch.rs cancel/fail arms.
        slot_err
            .finish_as_error(
                "Build",
                crate::engine::response_performance::DisplayErrorKind::Failed,
                "provider failed",
                Some(&tx_err),
            )
            .await;
        match rx_err.recv().await.expect("error row") {
            TurnEvent::AssistantDisplayError {
                kind,
                presentation_text,
                ..
            } => {
                assert_eq!(
                    kind,
                    crate::engine::response_performance::DisplayErrorKind::Failed
                );
                assert_eq!(presentation_text.as_deref(), Some("chip body"));
            }
            other => panic!("expected AssistantDisplayError from finish_as_error, got {other:?}"),
        }
        // Cancellation remains terminal at dispatch; failed attempts defer
        // terminal presentation until the backup wrapper knows no replacement
        // will start.
        let dispatch_src = include_str!("dispatch.rs");
        assert!(
            dispatch_src.matches(".finish_as_error(").count() == 1,
            "only the cancellation Err arm may finish display at dispatch"
        );
        assert!(
            !dispatch_src.contains("mark_failed_visible("),
            "terminal path must not call mark_failed_visible"
        );
    }
}
