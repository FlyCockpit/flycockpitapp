//! Feature-gated test facades. Compiled only with `cockpit-core/test-support`.
//!
//! The public allowlist is exactly three items: the e2e stream-chunk enum,
//! the production dispatcher driver, and the thin proto-conversion wrapper.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::engine::TurnEvent;
use crate::engine::model::{
    DisplayAttemptSlot, DisplayClockFactory, assistant_display_complete_turn_event,
    drain_items_for_response_performance_e2e, finish_open_display_classifier,
};
use crate::engine::response_performance::{
    DisplayClassifierConfig, DisplayClock, DisplayTokenizer, InjectedDisplayClock, Instant,
};

/// One fake provider/model stream chunk with a manual-clock instant.
pub enum ResponsePerformanceE2eStreamChunk {
    Text { at: Duration, text: String },
    Reasoning { at: Duration, text: String },
}

struct SharedInjectedClock(Arc<Mutex<InjectedDisplayClock>>);

impl DisplayClock for SharedInjectedClock {
    fn now(&self) -> Instant {
        self.0.lock().expect("injected display clock").current()
    }
}

struct ScriptedDisplayTokenizer {
    outcomes: Mutex<VecDeque<Result<usize, String>>>,
    exhausted: AtomicBool,
}

impl ScriptedDisplayTokenizer {
    fn new(outcomes: Vec<Result<usize, String>>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from(outcomes)),
            exhausted: AtomicBool::new(false),
        }
    }

    fn leftover(&self) -> usize {
        self.outcomes
            .lock()
            .expect("scripted tokenizer outcomes")
            .len()
    }

    fn was_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
    }
}

impl DisplayTokenizer for ScriptedDisplayTokenizer {
    fn count(&self, _text: &str) -> Result<usize, String> {
        match self
            .outcomes
            .lock()
            .expect("scripted tokenizer outcomes")
            .pop_front()
        {
            Some(outcome) => outcome,
            None => {
                self.exhausted.store(true, Ordering::SeqCst);
                Err("exhausted tokenizer outcomes".to_string())
            }
        }
    }
}

struct ScriptedProviderStream {
    chunks: VecDeque<ResponsePerformanceE2eStreamChunk>,
    clock: Arc<Mutex<InjectedDisplayClock>>,
}

impl futures::Stream for ScriptedProviderStream {
    type Item = Result<rig::streaming::StreamedAssistantContent, rig::completion::CompletionError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(chunk) = self.chunks.pop_front() else {
            return Poll::Ready(None);
        };
        let (at, item) = match chunk {
            ResponsePerformanceE2eStreamChunk::Text { at, text } => {
                (at, rig::streaming::StreamedAssistantContent::text(&text))
            }
            ResponsePerformanceE2eStreamChunk::Reasoning { at, text } => (
                at,
                rig::streaming::StreamedAssistantContent::ReasoningDelta {
                    id: "response-performance-e2e-reasoning".to_string(),
                    provider_id: None,
                    reasoning: text,
                },
            ),
        };
        self.clock
            .lock()
            .expect("injected display clock")
            .set(Instant::manual(at));
        Poll::Ready(Some(Ok(item)))
    }
}

/// Drive the production display dispatcher with a fake stream, injected
/// clock, and ordered tokenizer outcomes. Collects real typed `TurnEvent`s
/// (deltas plus exactly one `AssistantDisplayComplete`) from an in-memory
/// channel. Does not construct a classifier or synthesize display events.
pub async fn drive_response_performance_dispatcher_for_e2e(
    agent: String,
    provider: String,
    model: String,
    chunks: Vec<ResponsePerformanceE2eStreamChunk>,
    tokenizer_outcomes: Vec<Result<usize, String>>,
) -> Vec<TurnEvent> {
    let t0 = Instant::manual(Duration::ZERO);
    let shared_clock = Arc::new(Mutex::new(InjectedDisplayClock::new(t0)));
    let clock_factory: DisplayClockFactory = {
        let clock = Arc::clone(&shared_clock);
        Arc::new(move || Box::new(SharedInjectedClock(Arc::clone(&clock))))
    };
    let tokenizer = Arc::new(ScriptedDisplayTokenizer::new(tokenizer_outcomes));
    let slot = DisplayAttemptSlot::new_with_clock_and_tokenizer(
        DisplayClassifierConfig {
            inline_think: false,
            translation_enabled: false,
            encoding: cockpit_tokenizer::TiktokenEncoding::Cl100k,
            force_tokenization_failure: false,
        },
        clock_factory,
        Arc::clone(&tokenizer) as Arc<dyn DisplayTokenizer>,
    );

    let event_capacity = chunks.len().saturating_mul(2).saturating_add(4).max(1);
    let (tx, mut rx) = mpsc::channel(event_capacity);
    slot.begin_successful_attempt_at(&agent, Some(&tx), t0)
        .await;

    let mut last_at = Duration::ZERO;
    let mut choice = String::new();
    let mut reasoning = String::new();
    for chunk in &chunks {
        let at = match chunk {
            ResponsePerformanceE2eStreamChunk::Text { at, .. }
            | ResponsePerformanceE2eStreamChunk::Reasoning { at, .. } => *at,
        };
        if at < last_at {
            panic!("response-performance e2e chunks must be monotonic in `at`");
        }
        last_at = at;
        match chunk {
            ResponsePerformanceE2eStreamChunk::Text { text, .. } => {
                choice.push_str(text);
            }
            ResponsePerformanceE2eStreamChunk::Reasoning { text, .. } => {
                reasoning.push_str(text);
            }
        }
    }

    let mut stream = ScriptedProviderStream {
        chunks: VecDeque::from(chunks),
        clock: Arc::clone(&shared_clock),
    };
    let timeout = crate::config::providers::TimeoutConfig {
        ttft_secs: 30,
        idle_secs: 30,
    };
    let phase = AtomicU8::new(0);
    let first_token_ms = AtomicU64::new(0);
    let output_sent = AtomicBool::new(false);
    let cancel = CancellationToken::new();
    drain_items_for_response_performance_e2e(
        &mut stream,
        &timeout,
        &phase,
        &first_token_ms,
        &agent,
        &provider,
        &model,
        Some(&tx),
        &cancel,
        &output_sent,
        Some(&slot),
        || {
            shared_clock
                .lock()
                .expect("injected display clock")
                .current()
                .checked_duration_since(t0)
                .expect("manual clock stays on one timeline")
                .as_millis() as u64
        },
    )
    .await
    .expect("scripted provider stream must drain through production");

    let mut classifier = slot
        .take_open_classifier()
        .expect("production drain leaves the successful classifier for turn finish");
    let complete = finish_open_display_classifier(&mut classifier, &choice, &reasoning, None)
        .expect("scripted visible response must finish through production classifier path");
    tx.send(assistant_display_complete_turn_event(&agent, complete))
        .await
        .expect("in-memory turn-event sink remains attached");
    drop(tx);

    if tokenizer.leftover() > 0 {
        panic!(
            "unused tokenizer outcomes remaining: {}",
            tokenizer.leftover()
        );
    }
    if tokenizer.was_exhausted() {
        panic!("tokenizer outcomes exhausted before production finish");
    }

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

/// Thin wrapper around the crate-private `TurnEvent` → wire converter.
/// Contains no match, mapping, filtering, redaction, or copied logic.
pub fn turn_event_to_proto_for_response_performance_e2e(
    event: TurnEvent,
    session_id: Uuid,
) -> Vec<cockpit_proto::Event> {
    crate::daemon::proto::turn_event_to_proto(event, session_id)
}
