//! Feature-gated test facades. Compiled only with `cockpit-core/test-support`.
//!
//! The public allowlist is exactly three items: the e2e stream-chunk enum,
//! the production dispatcher driver, and the thin proto-conversion wrapper.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use uuid::Uuid;

use crate::engine::TurnEvent;
use crate::engine::model::{DisplayAttemptSlot, DisplayClockFactory};
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
    drop((provider, model));

    let origin = std::time::Instant::now();
    let t0 = Instant::from_std(origin);
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

    let (tx, mut rx) = mpsc::channel(64);
    slot.begin_successful_attempt(&agent, Some(&tx), origin)
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
        shared_clock
            .lock()
            .expect("injected display clock")
            .set(Instant::from_std(origin + at));
        match chunk {
            ResponsePerformanceE2eStreamChunk::Text { text, .. } => {
                choice.push_str(text);
                slot.feed_text(&agent, text, Some(&tx)).await;
            }
            ResponsePerformanceE2eStreamChunk::Reasoning { text, .. } => {
                reasoning.push_str(text);
                slot.feed_reasoning(&agent, text, Some(&tx)).await;
            }
        }
    }

    slot.finish_successful_attempt(&agent, &choice, &reasoning, None, Some(&tx))
        .await;
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
