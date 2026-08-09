#[cfg(test)]
use std::collections::VecDeque;
use std::future::{pending, poll_fn};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, EventStream};
use futures::{Stream, StreamExt};

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
}

type MonotonicClock = Arc<dyn Fn() -> Duration + Send + Sync>;

pub struct TerminalInput {
    stream: Option<TerminalInputStream>,
    clock: MonotonicClock,
    generation: u64,
    #[cfg(test)]
    test_stream: bool,
}

impl TerminalInput {
    pub fn new() -> Self {
        let origin = Instant::now();
        Self {
            stream: Some(TerminalInputStream::new()),
            clock: Arc::new(move || origin.elapsed()),
            generation: next_generation(),
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
        Self {
            stream: Some(TerminalInputStream::TestLive(VecDeque::new())),
            clock,
            generation: next_generation(),
            test_stream: true,
        }
    }

    pub async fn next(&mut self) -> Option<ObservedTerminalEvent> {
        match self.stream.as_mut() {
            Some(stream) => stream.next().await.map(|event| ObservedTerminalEvent {
                event,
                observed_at: (self.clock)(),
                terminal_generation: self.generation,
            }),
            None => pending().await,
        }
    }

    pub async fn drain_ready<F>(&mut self, cap: usize, mut on_event: F) -> Result<bool>
    where
        F: FnMut(Option<ObservedTerminalEvent>) -> Result<bool>,
    {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(false);
        };
        let clock = Arc::clone(&self.clock);
        let generation = self.generation;
        stream
            .drain_ready(cap, move |item| {
                on_event(item.map(|event| ObservedTerminalEvent {
                    event,
                    observed_at: clock(),
                    terminal_generation: generation,
                }))
            })
            .await
    }

    pub fn suspend(&mut self) {
        self.stream = None;
    }

    pub fn resume(&mut self) {
        if self.stream.is_none() {
            self.stream = Some(self.new_stream());
            self.generation = next_generation();
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
        Self {
            stream: Some(TerminalInputStream::TestLive(events.into_iter().collect())),
            clock,
            generation: next_generation(),
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

    #[test]
    fn terminal_input_observation_time_is_source_time() {
        let mut input = TerminalInput::new_for_test();
        let first = input.generation();
        input.suspend();
        input.resume();
        assert!(input.generation() > first);

        let ticks = Arc::new(AtomicUsize::new(4));
        let observed = Arc::clone(&ticks);
        let input = TerminalInput::new_for_test_with_clock(Arc::new(move || {
            Duration::from_millis(observed.fetch_add(1, Ordering::SeqCst) as u64)
        }));
        assert_eq!((input.clock)(), Duration::from_millis(4));
        assert_eq!((input.clock)(), Duration::from_millis(5));

        let mut classifier = crate::tui::structured_paste::TerminalPasteClassifier::default();
        for (index, ch) in "12345678".chars().enumerate() {
            classifier.observe(
                Event::Key(crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char(ch),
                    crossterm::event::KeyModifiers::NONE,
                )),
                Duration::from_millis(index as u64 * 5),
            );
        }
        // Arbitrary reducer delay cannot rewrite the already observed gaps.
        assert!(matches!(
            classifier.flush_idle(Duration::from_millis(47)),
            crate::tui::structured_paste::ClassifierDecision::Paste { .. }
        ));

        let mut shortcut = crate::tui::structured_paste::TerminalPasteClassifier::default();
        shortcut.observe(
            Event::Key(crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char('v'),
                crossterm::event::KeyModifiers::CONTROL,
            )),
            Duration::from_millis(1_000),
        );
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
