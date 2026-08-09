use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::{pending, poll_fn};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, EventStream};
use futures::{Stream, StreamExt};
use tokio::sync::mpsc;

pub const MAX_DRAIN_PER_PASS: usize = 256;
static NEXT_TERMINAL_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A terminal event stamped at the instant the underlying event stream yields it.
///
/// Keeping this envelope at the source prevents redraws, reducer stalls and drain
/// batching from changing shortcut and rapid-paste timing decisions.
#[derive(Debug)]
pub struct ObservedTerminalEvent {
    pub event: io::Result<Event>,
    pub observed_at: Duration,
    pub terminal_generation: u64,
    /// Authoritative adapter provenance for a paste event. Raw terminal
    /// `EventStream` paste frames are bracketed PTY input; a native adapter
    /// may construct the same envelope with `NativePaste` without injecting
    /// duplicate key bytes.
    pub paste_source: Option<crate::tui::structured_paste::PasteSource>,
    pub paste_correlation_id: Option<uuid::Uuid>,
}

type MonotonicClock = Arc<dyn Fn() -> Duration + Send + Sync>;

#[derive(Clone)]
pub struct NativePasteAdapter {
    tx: mpsc::UnboundedSender<ObservedTerminalEvent>,
    clock: MonotonicClock,
    terminal_generation: u64,
}

impl NativePasteAdapter {
    pub fn enqueue(&self, text: String) -> bool {
        self.tx
            .send(ObservedTerminalEvent {
                event: Ok(Event::Paste(text)),
                observed_at: (self.clock)(),
                terminal_generation: self.terminal_generation,
                paste_source: Some(crate::tui::structured_paste::PasteSource::NativePaste),
                paste_correlation_id: Some(uuid::Uuid::new_v4()),
            })
            .is_ok()
    }

    pub fn enqueue_with_correlation(
        &self,
        text: String,
        correlation_id: uuid::Uuid,
    ) -> Option<tokio::sync::oneshot::Receiver<crate::tui::structured_paste::DedupResult>> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if let Ok(mut acks) = native_paste_acks().lock() {
            acks.entry(correlation_id).or_default().push(ack_tx);
        }
        let sent = self
            .tx
            .send(ObservedTerminalEvent {
                event: Ok(Event::Paste(text)),
                observed_at: (self.clock)(),
                terminal_generation: self.terminal_generation,
                paste_source: Some(crate::tui::structured_paste::PasteSource::NativePaste),
                paste_correlation_id: Some(correlation_id),
            })
            .is_ok();
        if sent {
            Some(ack_rx)
        } else {
            if let Ok(mut acks) = native_paste_acks().lock() {
                acks.remove(&correlation_id);
            }
            None
        }
    }
}

static NATIVE_PASTE_ADAPTER: OnceLock<Mutex<Option<NativePasteAdapter>>> = OnceLock::new();
type NativePasteAckSender = tokio::sync::oneshot::Sender<crate::tui::structured_paste::DedupResult>;
static NATIVE_PASTE_ACKS: OnceLock<Mutex<HashMap<uuid::Uuid, Vec<NativePasteAckSender>>>> =
    OnceLock::new();

fn native_paste_acks() -> &'static Mutex<HashMap<uuid::Uuid, Vec<NativePasteAckSender>>> {
    NATIVE_PASTE_ACKS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn acknowledge_native_paste(
    correlation_id: uuid::Uuid,
    result: crate::tui::structured_paste::DedupResult,
) {
    if let Ok(mut acks) = native_paste_acks().lock()
        && let Some(waiters) = acks.remove(&correlation_id)
    {
        for ack in waiters {
            let _ = ack.send(result);
        }
    }
}

pub fn install_native_paste_adapter(adapter: NativePasteAdapter) {
    if let Ok(mut slot) = NATIVE_PASTE_ADAPTER.get_or_init(|| Mutex::new(None)).lock() {
        *slot = Some(adapter);
    }
}

pub fn clear_native_paste_adapter() {
    if let Some(slot) = NATIVE_PASTE_ADAPTER.get()
        && let Ok(mut slot) = slot.lock()
    {
        *slot = None;
    }
    if let Ok(mut acks) = native_paste_acks().lock() {
        for (_, waiters) in acks.drain() {
            for ack in waiters {
                let _ = ack.send(crate::tui::structured_paste::DedupResult::Busy);
            }
        }
    }
}

/// Production native platform hooks call this entrypoint once per direct
/// paste. It wakes the same `TerminalInput::next` select used by PTY input.
pub fn enqueue_native_paste(text: String) -> bool {
    NATIVE_PASTE_ADAPTER
        .get()
        .and_then(|slot| slot.lock().ok())
        .and_then(|slot| slot.as_ref().cloned())
        .is_some_and(|adapter| adapter.enqueue(text))
}

pub struct TerminalInput {
    stream: Option<TerminalInputStream>,
    native_paste_tx: mpsc::UnboundedSender<ObservedTerminalEvent>,
    native_paste_rx: mpsc::UnboundedReceiver<ObservedTerminalEvent>,
    pending_observed: VecDeque<ObservedTerminalEvent>,
    clock: MonotonicClock,
    generation: u64,
    native_adapter_installed: bool,
    #[cfg(test)]
    test_stream: bool,
}

impl TerminalInput {
    pub fn new() -> Self {
        let origin = Instant::now();
        let clock: MonotonicClock = Arc::new(move || origin.elapsed());
        let generation = next_generation();
        let (native_paste_tx, native_paste_rx) = mpsc::unbounded_channel();
        Self {
            stream: Some(TerminalInputStream::new()),
            native_paste_tx,
            native_paste_rx,
            pending_observed: VecDeque::new(),
            clock,
            generation,
            native_adapter_installed: false,
            #[cfg(test)]
            test_stream: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new_for_test_with_clock(Arc::new(|| Duration::ZERO))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_clock(clock: MonotonicClock) -> Self {
        let (native_paste_tx, native_paste_rx) = mpsc::unbounded_channel();
        Self {
            stream: Some(TerminalInputStream::TestLive(VecDeque::new())),
            native_paste_tx,
            native_paste_rx,
            pending_observed: VecDeque::new(),
            clock,
            generation: next_generation(),
            native_adapter_installed: false,
            test_stream: true,
        }
    }

    pub async fn next(&mut self) -> Option<ObservedTerminalEvent> {
        while let Ok(event) = self.native_paste_rx.try_recv() {
            self.pending_observed.push_back(event);
        }
        self.pending_observed
            .make_contiguous()
            .sort_by_key(|event| event.observed_at);
        if let Some(event) = self.pending_observed.pop_front() {
            return Some(event);
        }
        let clock = Arc::clone(&self.clock);
        let generation = self.generation;
        match self.stream.as_mut() {
            Some(stream) => tokio::select! {
                biased;
                native = self.native_paste_rx.recv() => native,
                event = stream.next() => event.map(|event| ObservedTerminalEvent {
                paste_correlation_id: event.as_ref().ok().and_then(|event| {
                    matches!(event, Event::Paste(_)).then_some(uuid::Uuid::new_v4())
                }),
                paste_source: event.as_ref().ok().and_then(|event| {
                    matches!(event, Event::Paste(_))
                        .then_some(crate::tui::structured_paste::PasteSource::BracketedPty)
                }),
                event,
                observed_at: clock(),
                terminal_generation: generation,
                }),
            },
            None => pending().await,
        }
    }

    pub async fn drain_ready<F>(&mut self, cap: usize, mut on_event: F) -> Result<bool>
    where
        F: FnMut(Option<ObservedTerminalEvent>) -> Result<bool>,
    {
        let mut ready = Vec::new();
        while let Some(event) = self.pending_observed.pop_front() {
            ready.push((event.observed_at, 0_u8, Some(event)));
        }
        loop {
            let Some(event) = self.native_paste_rx.try_recv().ok() else {
                break;
            };
            ready.push((event.observed_at, 0_u8, Some(event)));
        }
        let Some(stream) = self.stream.as_mut() else {
            ready.sort_by_key(|(observed_at, source_order, _)| (*observed_at, *source_order));
            for (_, _, event) in ready {
                if on_event(event)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        };
        let clock = Arc::clone(&self.clock);
        let generation = self.generation;
        // Always sample at least one ready PTY event even when native events
        // fill the output cap. The timestamp merge below emits only `cap`
        // items and retains overflow for the next call.
        let remaining = cap.max(1);
        stream
            .drain_ready(remaining, |item| {
                let observed_at = clock();
                let event = item.map(|event| ObservedTerminalEvent {
                    paste_source: event.as_ref().ok().and_then(|event| {
                        matches!(event, Event::Paste(_))
                            .then_some(crate::tui::structured_paste::PasteSource::BracketedPty)
                    }),
                    paste_correlation_id: event.as_ref().ok().and_then(|event| {
                        matches!(event, Event::Paste(_)).then_some(uuid::Uuid::new_v4())
                    }),
                    event,
                    observed_at,
                    terminal_generation: generation,
                });
                ready.push((observed_at, 1_u8, event));
                Ok(false)
            })
            .await?;
        ready.sort_by_key(|(observed_at, source_order, _)| (*observed_at, *source_order));
        let overflow = ready.split_off(cap.min(ready.len()));
        for (_, _, event) in overflow {
            if let Some(event) = event {
                self.pending_observed.push_back(event);
            }
        }
        for (_, _, event) in ready {
            if on_event(event)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Native platform adapters call this exactly once per direct paste and
    /// must not also enqueue key bytes for the same operation.
    pub fn enqueue_native_paste(&mut self, text: String) {
        let _ = self.native_paste_tx.send(ObservedTerminalEvent {
            event: Ok(Event::Paste(text)),
            observed_at: (self.clock)(),
            terminal_generation: self.generation,
            paste_source: Some(crate::tui::structured_paste::PasteSource::NativePaste),
            paste_correlation_id: Some(uuid::Uuid::new_v4()),
        });
    }

    pub fn native_paste_adapter(&self) -> NativePasteAdapter {
        NativePasteAdapter {
            tx: self.native_paste_tx.clone(),
            clock: Arc::clone(&self.clock),
            terminal_generation: self.generation,
        }
    }

    pub fn install_native_paste_adapter(&mut self) {
        install_native_paste_adapter(self.native_paste_adapter());
        self.native_adapter_installed = true;
    }

    pub fn suspend(&mut self) {
        self.stream = None;
        if self.native_adapter_installed {
            clear_native_paste_adapter();
        }
        while self.native_paste_rx.try_recv().is_ok() {}
    }

    pub fn resume(&mut self) {
        if self.stream.is_none() {
            self.stream = Some(self.new_stream());
            self.generation = next_generation();
            if self.native_adapter_installed {
                install_native_paste_adapter(self.native_paste_adapter());
            }
        }
    }

    pub fn is_suspended(&self) -> bool {
        self.stream.is_none()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn now(&self) -> Duration {
        (self.clock)()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_events(
        clock: MonotonicClock,
        events: impl IntoIterator<Item = io::Result<Event>>,
    ) -> Self {
        let (native_paste_tx, native_paste_rx) = mpsc::unbounded_channel();
        Self {
            stream: Some(TerminalInputStream::TestLive(events.into_iter().collect())),
            native_paste_tx,
            native_paste_rx,
            clock,
            generation: next_generation(),
            native_adapter_installed: false,
            pending_observed: VecDeque::new(),
            test_stream: true,
        }
    }

    fn new_stream(&self) -> TerminalInputStream {
        #[cfg(test)]
        if self.test_stream {
            return TerminalInputStream::TestLive(VecDeque::new());
        }
        TerminalInputStream::new()
    }
}

fn next_generation() -> u64 {
    NEXT_TERMINAL_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("terminal input generation exhausted")
}

impl Default for TerminalInput {
    fn default() -> Self {
        Self::new()
    }
}

enum TerminalInputStream {
    Real(EventStream),
    #[cfg(test)]
    TestLive(VecDeque<io::Result<Event>>),
}

impl TerminalInputStream {
    fn new() -> Self {
        Self::Real(EventStream::new())
    }

    async fn next(&mut self) -> Option<io::Result<Event>> {
        match self {
            Self::Real(stream) => stream.next().await,
            #[cfg(test)]
            Self::TestLive(events) => match events.pop_front() {
                Some(event) => Some(event),
                None => pending().await,
            },
        }
    }

    async fn drain_ready<F>(&mut self, cap: usize, on_event: F) -> Result<bool>
    where
        F: FnMut(Option<io::Result<Event>>) -> Result<bool>,
    {
        match self {
            Self::Real(stream) => drain_ready_impl(stream, cap, on_event).await,
            #[cfg(test)]
            Self::TestLive(events) => {
                let mut on_event = on_event;
                for _ in 0..cap {
                    let Some(event) = events.pop_front() else {
                        break;
                    };
                    if on_event(Some(event))? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

pub fn with_input_suspended<T>(
    input: &mut TerminalInput,
    f: impl FnOnce(&mut TerminalInput) -> T,
) -> T {
    input.suspend();
    debug_assert!(input.is_suspended());
    let guard = ResumeInputOnDrop { input };
    f(guard.input)
}

struct ResumeInputOnDrop<'a> {
    input: &'a mut TerminalInput,
}

impl Drop for ResumeInputOnDrop<'_> {
    fn drop(&mut self) {
        self.input.resume();
    }
}

pub(crate) async fn drain_ready_impl<S, F>(
    events: &mut S,
    cap: usize,
    mut on_event: F,
) -> Result<bool>
where
    S: Stream<Item = io::Result<Event>> + Unpin,
    F: FnMut(Option<io::Result<Event>>) -> Result<bool>,
{
    for _ in 0..cap {
        let ready = poll_fn(|cx| {
            Poll::Ready(match events.poll_next_unpin(cx) {
                Poll::Ready(item) => Some(item),
                Poll::Pending => None,
            })
        })
        .await;
        match ready {
            Some(item) => {
                if on_event(item)? {
                    return Ok(true);
                }
            }
            None => return Ok(false),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Context;
    use std::task::Waker;

    use futures::task::{ArcWake, waker};

    struct CountingWaker {
        wakes: Arc<AtomicUsize>,
    }

    impl ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Waker, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        (
            waker(Arc::new(CountingWaker {
                wakes: Arc::clone(&wakes),
            })),
            wakes,
        )
    }

    struct FakeStream {
        ready: VecDeque<io::Result<Event>>,
        pending_waker: Option<Waker>,
    }

    impl FakeStream {
        fn with_ready(count: usize) -> Self {
            Self {
                ready: (0..count)
                    .map(|idx| Ok(Event::Resize(idx as u16, idx as u16)))
                    .collect(),
                pending_waker: None,
            }
        }
    }

    impl Stream for FakeStream {
        type Item = io::Result<Event>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if let Some(item) = self.ready.pop_front() {
                Poll::Ready(Some(item))
            } else {
                self.pending_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    #[test]
    fn drain_registers_a_live_waker_when_stream_is_pending() {
        let mut stream = FakeStream::with_ready(0);
        let (our_waker, wake_count) = counting_waker();
        let mut cx = Context::from_waker(&our_waker);

        let result = {
            let mut fut = Box::pin(drain_ready_impl(&mut stream, MAX_DRAIN_PER_PASS, |_| {
                Ok(false)
            }));
            fut.as_mut().poll(&mut cx)
        };

        assert!(matches!(result, Poll::Ready(Ok(false))));
        let registered = stream
            .pending_waker
            .take()
            .expect("pending poll should register a waker");
        assert!(registered.will_wake(&our_waker));
        registered.wake();
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn terminal_input_observation_time_is_source_time() {
        let mut input = TerminalInput::new_for_test();
        let first = input.generation();
        input.suspend();
        input.resume();
        assert!(input.generation() > first);

        let ticks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&ticks);
        let mut input = TerminalInput::new_for_test_events(
            Arc::new(move || Duration::from_millis(observed.fetch_add(5, Ordering::SeqCst) as u64)),
            "12345678".chars().map(|ch| {
                Ok(Event::Key(crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char(ch),
                    crossterm::event::KeyModifiers::NONE,
                )))
            }),
        );
        let mut classifier = crate::tui::structured_paste::TerminalPasteClassifier::default();
        for _ in 0..8 {
            let observed = input.next().await.expect("test event");
            classifier.observe(observed.event.unwrap(), observed.observed_at);
        }
        assert!(matches!(
            classifier.flush_idle(Duration::from_millis(47)),
            crate::tui::structured_paste::ClassifierDecision::Paste { .. }
        ));

        let mut shortcut_input = TerminalInput::new_for_test_events(
            Arc::new(|| Duration::from_millis(1_000)),
            [Ok(Event::Key(crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('v'),
                crossterm::event::KeyModifiers::CONTROL,
            )))],
        );
        let observed = shortcut_input.next().await.expect("shortcut event");
        let mut shortcut = crate::tui::structured_paste::TerminalPasteClassifier::default();
        shortcut.observe(observed.event.unwrap(), observed.observed_at);
        assert!(matches!(
            shortcut.flush_due(Duration::from_millis(1_249)),
            crate::tui::structured_paste::ClassifierDecision::Pending
        ));
        assert!(matches!(
            shortcut.flush_due(Duration::from_millis(1_250)),
            crate::tui::structured_paste::ClassifierDecision::PasteUnavailable
        ));
    }

    #[tokio::test]
    async fn timestamped_test_stream_preserves_yield_order_and_time() {
        let ticks = Arc::new(AtomicUsize::new(10));
        let observed = Arc::clone(&ticks);
        let mut input = TerminalInput::new_for_test_events(
            Arc::new(move || Duration::from_millis(observed.fetch_add(5, Ordering::SeqCst) as u64)),
            [
                Ok(Event::Resize(1, 1)),
                Ok(Event::Resize(2, 2)),
                Ok(Event::Resize(3, 3)),
            ],
        );
        let first = input.next().await.unwrap();
        assert_eq!(first.observed_at, Duration::from_millis(10));
        let mut drained = Vec::new();
        input
            .drain_ready(2, |item| {
                drained.push(item.unwrap());
                Ok(false)
            })
            .await
            .unwrap();
        assert_eq!(drained[0].observed_at, Duration::from_millis(15));
        assert_eq!(drained[1].observed_at, Duration::from_millis(20));
        assert!(matches!(drained[1].event, Ok(Event::Resize(3, 3))));
    }

    #[tokio::test]
    async fn drain_coalesces_all_ready_events() {
        let mut stream = FakeStream::with_ready(4);
        let mut handled = 0;

        let quit = drain_ready_impl(&mut stream, MAX_DRAIN_PER_PASS, |item| {
            assert!(item.is_some());
            handled += 1;
            Ok(false)
        })
        .await
        .unwrap();

        assert!(!quit);
        assert_eq!(handled, 4);
        assert_eq!(stream.ready.len(), 0);
        assert!(stream.pending_waker.is_some());
    }

    #[tokio::test]
    async fn drain_stops_at_cap_and_leaves_remainder() {
        let mut stream = FakeStream::with_ready(5);
        let mut handled = 0;

        let quit = drain_ready_impl(&mut stream, 3, |item| {
            assert!(item.is_some());
            handled += 1;
            Ok(false)
        })
        .await
        .unwrap();

        assert!(!quit);
        assert_eq!(handled, 3);
        assert_eq!(stream.ready.len(), 2);
        assert!(stream.pending_waker.is_none());
    }

    #[tokio::test]
    async fn drain_propagates_quit_midway() {
        let mut stream = FakeStream::with_ready(5);
        let mut handled = 0;

        let quit = drain_ready_impl(&mut stream, MAX_DRAIN_PER_PASS, |item| {
            assert!(item.is_some());
            handled += 1;
            Ok(handled == 2)
        })
        .await
        .unwrap();

        assert!(quit);
        assert_eq!(handled, 2);
        assert_eq!(stream.ready.len(), 3);
        assert!(stream.pending_waker.is_none());
    }

    #[test]
    fn suspended_input_next_never_resolves() {
        let mut input = TerminalInput::new_for_test();
        input.suspend();
        let (our_waker, _wake_count) = counting_waker();
        let mut cx = Context::from_waker(&our_waker);
        let mut fut = Box::pin(input.next());

        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
    }

    #[test]
    fn suspend_and_resume_are_idempotent() {
        let mut input = TerminalInput::new_for_test();
        assert!(!input.is_suspended());

        input.suspend();
        input.suspend();
        assert!(input.is_suspended());

        input.resume();
        input.resume();
        assert!(!input.is_suspended());
    }

    #[tokio::test]
    async fn with_input_suspended_suspends_for_the_closure_and_resumes_after() {
        let mut input = TerminalInput::new_for_test();

        let result = with_input_suspended(&mut input, |input| {
            assert!(input.is_suspended());
            Ok::<_, &'static str>(())
        });
        assert_eq!(result, Ok(()));
        assert!(!input.is_suspended());

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_input_suspended(&mut input, |input| {
                assert!(input.is_suspended());
                panic!("editor failed while input was suspended");
            });
        }));
        assert!(panic_result.is_err());
        assert!(!input.is_suspended());
    }
}
