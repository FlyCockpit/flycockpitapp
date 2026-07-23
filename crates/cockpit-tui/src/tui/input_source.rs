use std::future::{pending, poll_fn};
use std::io;
use std::task::Poll;

use anyhow::Result;
use crossterm::event::{Event, EventStream};
use futures::{Stream, StreamExt};

pub const MAX_DRAIN_PER_PASS: usize = 256;

pub struct TerminalInput {
    stream: Option<TerminalInputStream>,
    #[cfg(test)]
    test_stream: bool,
}

impl TerminalInput {
    pub fn new() -> Self {
        Self {
            stream: Some(TerminalInputStream::new()),
            #[cfg(test)]
            test_stream: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self {
            stream: Some(TerminalInputStream::TestLive),
            test_stream: true,
        }
    }

    pub async fn next(&mut self) -> Option<io::Result<Event>> {
        match self.stream.as_mut() {
            Some(stream) => stream.next().await,
            None => pending().await,
        }
    }

    pub async fn drain_ready<F>(&mut self, cap: usize, on_event: F) -> Result<bool>
    where
        F: FnMut(Option<io::Result<Event>>) -> Result<bool>,
    {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(false);
        };
        stream.drain_ready(cap, on_event).await
    }

    pub fn suspend(&mut self) {
        self.stream = None;
    }

    pub fn resume(&mut self) {
        if self.stream.is_none() {
            self.stream = Some(self.new_stream());
        }
    }

    pub fn is_suspended(&self) -> bool {
        self.stream.is_none()
    }

    fn new_stream(&self) -> TerminalInputStream {
        #[cfg(test)]
        if self.test_stream {
            return TerminalInputStream::TestLive;
        }
        TerminalInputStream::new()
    }
}

impl Default for TerminalInput {
    fn default() -> Self {
        Self::new()
    }
}

enum TerminalInputStream {
    Real(EventStream),
    #[cfg(test)]
    TestLive,
}

impl TerminalInputStream {
    fn new() -> Self {
        Self::Real(EventStream::new())
    }

    async fn next(&mut self) -> Option<io::Result<Event>> {
        match self {
            Self::Real(stream) => stream.next().await,
            #[cfg(test)]
            Self::TestLive => pending().await,
        }
    }

    async fn drain_ready<F>(&mut self, cap: usize, on_event: F) -> Result<bool>
    where
        F: FnMut(Option<io::Result<Event>>) -> Result<bool>,
    {
        match self {
            Self::Real(stream) => drain_ready_impl(stream, cap, on_event).await,
            #[cfg(test)]
            Self::TestLive => Ok(false),
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
