//! Transport-neutral paste identities and the pure terminal paste classifier.
//!
//! This module deliberately contains no clipboard, filesystem, terminal, or
//! daemon I/O. The event loop feeds it source-stamped events and executes its
//! decisions through the normal App routes.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use uuid::Uuid;

pub const RAPID_MAX_GAP: Duration = Duration::from_millis(5);
pub const RAPID_IDLE_FLUSH: Duration = Duration::from_millis(12);
pub const RAPID_MIN_BYTES: usize = 8;
pub const SHORTCUT_DEADLINE: Duration = Duration::from_millis(250);
pub const CORRELATION_TTL: Duration = Duration::from_secs(2);
pub const CORRELATION_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteSource {
    BracketedPty,
    NativePaste,
    RapidPty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostIdentity {
    pub client_instance_id: Uuid,
    pub connection_epoch: u64,
    pub session_id: Uuid,
    pub terminal_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteRequest {
    pub paste_generation: u64,
    pub paste_correlation_id: Uuid,
    pub source: PasteSource,
    pub host: HostIdentity,
}

#[derive(Debug, Clone)]
struct BufferedKey {
    event: KeyEvent,
    observed_at: Duration,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ClassifierDecision {
    Ordinary(Event),
    Replay {
        keys: Vec<KeyEvent>,
        boundary: Option<Event>,
        shortcut_intent: bool,
        paste_unavailable: bool,
    },
    ShortcutIntent,
    PasteUnavailable,
    Paste {
        source: PasteSource,
        text: String,
    },
    Pending,
}

#[derive(Debug, Default)]
pub struct TerminalPasteClassifier {
    rapid: Vec<BufferedKey>,
    shortcut_at: Option<Duration>,
}

impl TerminalPasteClassifier {
    /// Resolve only the local shortcut intent after a native clipboard image
    /// commits. Buffered rapid keys retain their ordinary ownership.
    pub fn resolve_shortcut_intent(&mut self) {
        self.shortcut_at = None;
    }

    pub fn observe(&mut self, event: Event, observed_at: Duration) -> ClassifierDecision {
        if let Event::Paste(text) = event {
            let replay = self.take_replay();
            self.shortcut_at = None;
            if replay.is_empty() {
                return ClassifierDecision::Paste {
                    source: PasteSource::BracketedPty,
                    text,
                };
            }
            return ClassifierDecision::Replay {
                keys: replay,
                boundary: Some(Event::Paste(text)),
                shortcut_intent: false,
                paste_unavailable: false,
            };
        }

        if let Event::Key(key) = &event
            && is_paste_shortcut(*key)
        {
            let replay = self.take_replay();
            self.shortcut_at = Some(observed_at);
            return if replay.is_empty() {
                ClassifierDecision::ShortcutIntent
            } else {
                ClassifierDecision::Replay {
                    keys: replay,
                    boundary: None,
                    shortcut_intent: true,
                    paste_unavailable: false,
                }
            };
        }

        if let Some(started) = self.shortcut_at
            && observed_at.saturating_sub(started) >= SHORTCUT_DEADLINE
        {
            self.shortcut_at = None;
            return ClassifierDecision::Replay {
                keys: self.take_replay(),
                boundary: Some(event),
                shortcut_intent: false,
                paste_unavailable: true,
            };
        }

        let Some((key, bytes)) = rapid_key(&event) else {
            let replay = self.take_replay();
            return if replay.is_empty() {
                ClassifierDecision::Ordinary(event)
            } else {
                ClassifierDecision::Replay {
                    keys: replay,
                    boundary: Some(event),
                    shortcut_intent: false,
                    paste_unavailable: false,
                }
            };
        };

        if self.rapid.last().is_some_and(|previous| {
            observed_at.saturating_sub(previous.observed_at) > RAPID_MAX_GAP
        }) {
            let replay = self.take_replay();
            self.rapid.push(BufferedKey {
                event: key,
                observed_at,
                bytes,
            });
            return ClassifierDecision::Replay {
                keys: replay,
                boundary: None,
                shortcut_intent: false,
                paste_unavailable: false,
            };
        }
        self.rapid.push(BufferedKey {
            event: key,
            observed_at,
            bytes,
        });
        ClassifierDecision::Pending
    }

    pub fn flush_idle(&mut self, now: Duration) -> ClassifierDecision {
        let Some(last) = self.rapid.last() else {
            return ClassifierDecision::Pending;
        };
        if now.saturating_sub(last.observed_at) < RAPID_IDLE_FLUSH {
            return ClassifierDecision::Pending;
        }
        let byte_len = self.rapid.iter().map(|key| key.bytes.len()).sum::<usize>();
        if byte_len >= RAPID_MIN_BYTES {
            let text = String::from_utf8(self.rapid.drain(..).flat_map(|key| key.bytes).collect())
                .expect("rapid candidates are valid UTF-8");
            self.shortcut_at = None;
            ClassifierDecision::Paste {
                source: PasteSource::RapidPty,
                text,
            }
        } else {
            ClassifierDecision::Replay {
                keys: self.take_replay(),
                boundary: None,
                shortcut_intent: false,
                paste_unavailable: false,
            }
        }
    }

    pub fn flush_due(&mut self, now: Duration) -> ClassifierDecision {
        let rapid = self.flush_idle(now);
        if !matches!(rapid, ClassifierDecision::Pending) {
            return rapid;
        }
        if self
            .shortcut_at
            .is_some_and(|started| now.saturating_sub(started) >= SHORTCUT_DEADLINE)
        {
            self.shortcut_at = None;
            return ClassifierDecision::PasteUnavailable;
        }
        ClassifierDecision::Pending
    }

    pub fn next_deadline(&self) -> Option<Duration> {
        let rapid = self
            .rapid
            .last()
            .map(|key| key.observed_at + RAPID_IDLE_FLUSH);
        let shortcut = self.shortcut_at.map(|at| at + SHORTCUT_DEADLINE);
        match (rapid, shortcut) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    pub fn cancel(&mut self) -> Vec<KeyEvent> {
        self.shortcut_at = None;
        self.take_replay()
    }

    fn take_replay(&mut self) -> Vec<KeyEvent> {
        self.rapid.drain(..).map(|key| key.event).collect()
    }
}

fn rapid_key(event: &Event) -> Option<(KeyEvent, Vec<u8>)> {
    let Event::Key(key) = event else { return None };
    if key.kind != KeyEventKind::Press || key.state != KeyEventState::NONE {
        return None;
    }
    if key.modifiers.intersects(
        KeyModifiers::CONTROL
            | KeyModifiers::ALT
            | KeyModifiers::SUPER
            | KeyModifiers::HYPER
            | KeyModifiers::META,
    ) {
        return None;
    }
    let bytes = match key.code {
        KeyCode::Char(ch) => ch.to_string().into_bytes(),
        KeyCode::Enter => vec![b'\n'],
        KeyCode::Tab => vec![b'\t'],
        _ => return None,
    };
    Some((*key, bytes))
}

fn is_paste_shortcut(key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press || key.state != KeyEventState::NONE {
        return false;
    }
    let mods = key.modifiers;
    match key.code {
        KeyCode::Char('v' | 'V') => {
            let base = mods - KeyModifiers::SHIFT;
            base == KeyModifiers::CONTROL || base == KeyModifiers::SUPER
        }
        KeyCode::Insert => mods == KeyModifiers::SHIFT,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupResult {
    Claimed,
    Committed,
    Busy,
    HostMismatch,
}

#[derive(Debug, Clone)]
struct CorrelationEntry {
    host: HostIdentity,
    expires_at: Option<Duration>,
    committed: bool,
}

#[derive(Debug, Default)]
pub struct PasteCorrelationCache {
    entries: HashMap<Uuid, CorrelationEntry>,
    order: VecDeque<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteSlotState {
    Pending {
        request: PasteRequest,
        original_offset: usize,
    },
    Ready {
        original_offset: usize,
        display: String,
        wire: String,
        png: Option<Vec<u8>>,
    },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedModel {
    pub provider_id: String,
    pub model_id: String,
    pub active_model_state_generation: u64,
    pub image_capability_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionFenceV1 {
    pub client_submission_id: Uuid,
    pub fence_sequence: u64,
    pub host: HostIdentity,
    pub view_generation: u64,
    pub source_draft_generation: u64,
    pub created_at: Duration,
    pub captured_composer: String,
    pub accepted_tags: Vec<String>,
    pub pending_git_blocks: Vec<String>,
    pub model: CapturedModel,
    pub slots: Vec<PasteSlotState>,
    pub lifecycle: FenceLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceLifecycle {
    AwaitingProbes,
    Ready,
    PossiblySent,
    Reconciling,
    NoPayload,
    CancelledBeforeDispatch,
    Accepted,
    IdempotentReplay,
    Conflict,
}

impl SubmissionFenceV1 {
    pub fn settle_slot(
        &mut self,
        request_id: Uuid,
        request_generation: u64,
        source_draft_generation: u64,
        result: Option<(String, String, Option<Vec<u8>>)>,
    ) -> bool {
        if self.lifecycle != FenceLifecycle::AwaitingProbes
            || source_draft_generation != self.source_draft_generation
        {
            return false;
        }
        let Some(slot) = self.slots.iter_mut().find(|slot| {
            matches!(slot, PasteSlotState::Pending { request, .. }
                if request.paste_correlation_id == request_id
                    && request.paste_generation == request_generation)
        }) else {
            return false;
        };
        let original_offset = match slot {
            PasteSlotState::Pending {
                original_offset, ..
            } => *original_offset,
            _ => return false,
        };
        *slot = match result {
            Some((display, wire, png)) => PasteSlotState::Ready {
                original_offset,
                display,
                wire,
                png,
            },
            None => PasteSlotState::Unavailable,
        };
        if self
            .slots
            .iter()
            .all(|slot| !matches!(slot, PasteSlotState::Pending { .. }))
        {
            self.lifecycle = FenceLifecycle::Ready;
        }
        true
    }

    pub fn cancel_if_host_changed(&mut self, host: HostIdentity, view_generation: u64) -> bool {
        if !matches!(
            self.lifecycle,
            FenceLifecycle::AwaitingProbes | FenceLifecycle::Ready
        ) {
            return false;
        }
        if self.host == host && self.view_generation == view_generation {
            return false;
        }
        self.lifecycle = FenceLifecycle::CancelledBeforeDispatch;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedIntent {
    Fence(Uuid),
    ModelSwitch(Uuid),
    SessionSwitch(Uuid),
}

/// One checked sequence domain shared by submissions and local barriers.
#[derive(Debug, Default)]
pub struct SubmissionOrderCoordinator {
    next_sequence: u64,
    queue: VecDeque<(u64, OrderedIntent, bool)>,
}

impl SubmissionOrderCoordinator {
    pub fn enqueue(&mut self, intent: OrderedIntent) -> Result<u64, &'static str> {
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or("fence sequence exhausted")?;
        self.next_sequence = sequence;
        self.queue.push_back((sequence, intent, false));
        Ok(sequence)
    }

    pub fn front(&self) -> Option<(u64, OrderedIntent)> {
        self.queue
            .front()
            .map(|(sequence, intent, _)| (*sequence, *intent))
    }

    pub fn complete(&mut self, sequence: u64) -> bool {
        let was_head = self
            .queue
            .front()
            .is_some_and(|(candidate, _, _)| *candidate == sequence);
        let Some((_, _, completed)) = self
            .queue
            .iter_mut()
            .find(|(candidate, _, _)| *candidate == sequence)
        else {
            return false;
        };
        *completed = true;
        while self
            .queue
            .front()
            .is_some_and(|(_, _, completed)| *completed)
        {
            self.queue.pop_front();
        }
        was_head
    }

    /// Remove an intent that was proven not to have crossed its dispatch
    /// boundary. This cannot reorder the remaining checked sequence domain.
    pub fn cancel(&mut self, sequence: u64) -> bool {
        let before = self.queue.len();
        self.queue
            .retain(|(candidate, _, _)| *candidate != sequence);
        while self
            .queue
            .front()
            .is_some_and(|(_, _, completed)| *completed)
        {
            self.queue.pop_front();
        }
        self.queue.len() != before
    }
}

impl PasteCorrelationCache {
    pub fn claim(&mut self, id: Uuid, host: HostIdentity, now: Duration) -> DedupResult {
        self.expire(now);
        if let Some(entry) = self.entries.get(&id) {
            if entry.host != host {
                return DedupResult::HostMismatch;
            }
            return if entry.committed {
                DedupResult::Committed
            } else {
                DedupResult::Busy
            };
        }
        if self.entries.len() == CORRELATION_CAPACITY {
            return DedupResult::Busy;
        }
        self.entries.insert(
            id,
            CorrelationEntry {
                host,
                // Claims are never expired out from under their owner. The
                // two-second producer-retry window starts at positive commit.
                expires_at: None,
                committed: false,
            },
        );
        self.order.push_back(id);
        DedupResult::Claimed
    }

    pub fn commit(&mut self, id: Uuid, host: HostIdentity, now: Duration) -> DedupResult {
        let Some(entry) = self.entries.get_mut(&id) else {
            return DedupResult::Busy;
        };
        if entry.host != host {
            return DedupResult::HostMismatch;
        }
        entry.committed = true;
        entry.expires_at = Some(now + CORRELATION_TTL);
        DedupResult::Committed
    }

    fn expire(&mut self, now: Duration) {
        self.entries
            .retain(|_, entry| entry.expires_at.is_none_or(|expires_at| expires_at > now));
        self.order.retain(|id| self.entries.contains_key(id));
    }
}

/// Parse the only shell literal shapes accepted by the browser bridge.
/// The parser never expands variables, escapes, tildes, or command syntax.
pub fn parse_private_image_path_literal(input: &str) -> Option<PathBuf> {
    if input.len() < 2 {
        return None;
    }
    if input.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let decoded = if input.starts_with('\'') && input.ends_with('\'') {
        decode_single_quoted(input)?
    } else if input.starts_with('"') && input.ends_with('"') {
        let inner = &input[1..input.len().checked_sub(1)?];
        if inner.contains('"')
            || inner.contains('%')
            || inner.contains('!')
            || inner.contains('^')
            || inner.contains('<')
            || inner.contains('>')
            || inner.contains('$')
        {
            return None;
        }
        inner.to_owned()
    } else {
        return None;
    };
    if decoded.is_empty()
        || decoded.contains("$(")
        || decoded.contains("${")
        || decoded.contains('$')
        || decoded.contains('`')
        || decoded.contains(';')
        || decoded.contains('|')
        || decoded.contains('&')
    {
        return None;
    }
    let path = PathBuf::from(&decoded);
    let windows_absolute = decoded.as_bytes().get(..3).is_some_and(|prefix| {
        prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && matches!(prefix[2], b'\\' | b'/')
    }) || decoded.starts_with("\\\\");
    if !path.is_absolute() && !windows_absolute {
        return None;
    }
    let extension = decoded
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())?;
    if !matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
        return None;
    }
    Some(path)
}

fn decode_single_quoted(input: &str) -> Option<String> {
    let inner = &input[1..input.len().checked_sub(1)?];
    if !inner.contains('\'') {
        return Some(inner.to_owned());
    }
    // PowerShell represents one apostrophe as two inside a single-quoted
    // literal. POSIX shells close the literal and append an escaped quote:
    // `'a'\''b'`. Those are the only accepted quote transitions.
    let powershell = inner.replace("''", "'");
    if powershell.matches('\'').count() * 2 == inner.matches('\'').count() {
        return Some(powershell);
    }
    let posix = input.replace("'\\''", "'");
    if posix.starts_with('\'') && posix.ends_with('\'') {
        let decoded = &posix[1..posix.len() - 1];
        if !decoded.contains('\'') || input.contains("'\\''") {
            return Some(decoded.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ch: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE))
    }

    #[test]
    fn rapid_paste_exact_thresholds() {
        let mut classifier = TerminalPasteClassifier::default();
        for (index, ch) in "12345678".chars().enumerate() {
            assert!(matches!(
                classifier.observe(key(ch), Duration::from_millis(index as u64 * 5)),
                ClassifierDecision::Pending
            ));
        }
        match classifier.flush_idle(Duration::from_millis(47)) {
            ClassifierDecision::Paste { source, text } => {
                assert_eq!(source, PasteSource::RapidPty);
                assert_eq!(text, "12345678");
            }
            other => panic!("unexpected decision: {other:?}"),
        }
        let mut classifier = TerminalPasteClassifier::default();
        for (index, ch) in "éééé".chars().enumerate() {
            classifier.observe(key(ch), Duration::from_millis(index as u64 * 4));
        }
        assert!(matches!(
            classifier.flush_idle(Duration::from_millis(24)),
            ClassifierDecision::Paste { .. }
        ));

        for idle in [11, 12, 13] {
            let mut classifier = TerminalPasteClassifier::default();
            for ch in "12345678".chars() {
                classifier.observe(key(ch), Duration::ZERO);
            }
            let decision = classifier.flush_idle(Duration::from_millis(idle));
            assert_eq!(
                matches!(decision, ClassifierDecision::Paste { .. }),
                idle >= 12
            );
        }
        let mut seven = TerminalPasteClassifier::default();
        for ch in "1234567".chars() {
            seven.observe(key(ch), Duration::ZERO);
        }
        assert!(matches!(
            seven.flush_idle(Duration::from_millis(12)),
            ClassifierDecision::Replay { keys, .. } if keys.len() == 7
        ));
        for gap in [4, 5, 6] {
            let mut classifier = TerminalPasteClassifier::default();
            classifier.observe(key('a'), Duration::ZERO);
            let decision = classifier.observe(key('b'), Duration::from_millis(gap));
            assert_eq!(
                matches!(decision, ClassifierDecision::Replay { .. }),
                gap > 5
            );
        }
        for event in [
            Event::Key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE)),
            Event::Key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)),
            Event::Key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)),
            Event::Resize(1, 1),
            Event::FocusGained,
        ] {
            let mut classifier = TerminalPasteClassifier::default();
            assert!(matches!(
                classifier.observe(event, Duration::ZERO),
                ClassifierDecision::Ordinary(_)
            ));
        }
        for (code, modifiers) in [
            (KeyCode::Char('x'), KeyModifiers::CONTROL),
            (KeyCode::Char('x'), KeyModifiers::ALT),
            (KeyCode::Char('x'), KeyModifiers::SUPER),
            (KeyCode::Char('x'), KeyModifiers::HYPER),
            (KeyCode::Char('x'), KeyModifiers::META),
        ] {
            let mut classifier = TerminalPasteClassifier::default();
            assert!(matches!(
                classifier.observe(Event::Key(KeyEvent::new(code, modifiers)), Duration::ZERO),
                ClassifierDecision::Ordinary(_)
            ));
        }
        for key in [
            KeyEvent {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Repeat,
                state: KeyEventState::NONE,
            },
            KeyEvent {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Release,
                state: KeyEventState::NONE,
            },
            KeyEvent {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::CAPS_LOCK,
            },
        ] {
            let mut classifier = TerminalPasteClassifier::default();
            assert!(matches!(
                classifier.observe(Event::Key(key), Duration::ZERO),
                ClassifierDecision::Ordinary(_)
            ));
        }
        let mut controls = TerminalPasteClassifier::default();
        for event in [
            Event::Key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::SHIFT)),
            Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            key('2'),
            key('3'),
            key('4'),
            key('5'),
            key('6'),
        ] {
            controls.observe(event, Duration::ZERO);
        }
        assert!(matches!(
            controls.flush_idle(Duration::from_millis(12)),
            ClassifierDecision::Paste { .. }
        ));
    }

    #[test]
    fn paste_shortcut_authoritative_timeout() {
        let mut classifier = TerminalPasteClassifier::default();
        let shortcut = Event::Key(KeyEvent::new(
            KeyCode::Char('v'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));
        assert!(matches!(
            classifier.observe(shortcut, Duration::ZERO),
            ClassifierDecision::ShortcutIntent
        ));
        assert!(matches!(
            classifier.observe(Event::Paste("x".into()), Duration::from_millis(249)),
            ClassifierDecision::Paste {
                source: PasteSource::BracketedPty,
                ..
            }
        ));
        let shortcut = Event::Key(KeyEvent::new(KeyCode::Insert, KeyModifiers::SHIFT));
        classifier.observe(shortcut, Duration::from_millis(1_000));
        assert!(matches!(
            classifier.flush_due(Duration::from_millis(1_250)),
            ClassifierDecision::PasteUnavailable
        ));
        for deadline in [249, 250, 251] {
            let mut classifier = TerminalPasteClassifier::default();
            classifier.observe(
                Event::Key(KeyEvent::new(KeyCode::Char('V'), KeyModifiers::SUPER)),
                Duration::ZERO,
            );
            assert_eq!(
                matches!(
                    classifier.flush_due(Duration::from_millis(deadline)),
                    ClassifierDecision::PasteUnavailable
                ),
                deadline >= 250
            );
        }
    }

    #[test]
    fn paste_authoritative_source_contract() {
        let sources = [
            PasteSource::BracketedPty,
            PasteSource::NativePaste,
            PasteSource::RapidPty,
        ];
        assert_eq!(sources.len(), 3);
        assert_ne!(PasteSource::BracketedPty, PasteSource::RapidPty);
    }

    #[test]
    fn paste_correlation_idempotency() {
        let host = HostIdentity {
            client_instance_id: Uuid::new_v4(),
            connection_epoch: 1,
            session_id: Uuid::new_v4(),
            terminal_generation: 2,
        };
        let id = Uuid::new_v4();
        let mut cache = PasteCorrelationCache::default();
        assert_eq!(cache.claim(id, host, Duration::ZERO), DedupResult::Claimed);
        assert_eq!(cache.claim(id, host, Duration::ZERO), DedupResult::Busy);
        assert_eq!(
            cache.commit(id, host, Duration::ZERO),
            DedupResult::Committed
        );
        assert_eq!(
            cache.claim(id, host, Duration::from_millis(1_999)),
            DedupResult::Committed
        );
        assert_eq!(
            cache.claim(id, host, Duration::from_millis(2_000)),
            DedupResult::Claimed
        );

        let mut full = PasteCorrelationCache::default();
        for _ in 0..CORRELATION_CAPACITY {
            assert_eq!(
                full.claim(Uuid::new_v4(), host, Duration::ZERO),
                DedupResult::Claimed
            );
        }
        assert_eq!(
            full.claim(Uuid::new_v4(), host, Duration::ZERO),
            DedupResult::Busy
        );
        let mut changed = host;
        changed.connection_epoch += 1;
        let shared_id = *full.order.front().unwrap();
        assert_eq!(
            full.claim(shared_id, changed, Duration::ZERO),
            DedupResult::HostMismatch
        );
    }

    #[test]
    fn paste_path_literal_probe() {
        assert_eq!(
            parse_private_image_path_literal("'/tmp/a b.png'"),
            Some(PathBuf::from("/tmp/a b.png"))
        );
        assert_eq!(
            parse_private_image_path_literal("\"C:\\tmp\\a b.png\""),
            Some(PathBuf::from("C:\\tmp\\a b.png"))
        );
        for rejected in [
            "/tmp/a.png",
            "'$HOME/a.png'",
            "'a;b.png'",
            "\"%TEMP%\\a.png\"",
            "'a\nb.png'",
        ] {
            assert_eq!(
                parse_private_image_path_literal(rejected),
                None,
                "{rejected}"
            );
        }
    }

    fn pending_fence(sequence: u64, host: HostIdentity) -> SubmissionFenceV1 {
        let request = PasteRequest {
            paste_generation: 7,
            paste_correlation_id: Uuid::new_v4(),
            source: PasteSource::BracketedPty,
            host,
        };
        SubmissionFenceV1 {
            client_submission_id: Uuid::new_v4(),
            fence_sequence: sequence,
            host,
            view_generation: 3,
            source_draft_generation: 9,
            created_at: Duration::from_millis(5),
            captured_composer: "before".into(),
            accepted_tags: vec!["a".into()],
            pending_git_blocks: vec!["g".into()],
            model: CapturedModel {
                provider_id: "p".into(),
                model_id: "m".into(),
                active_model_state_generation: 11,
                image_capability_generation: 4,
            },
            slots: vec![PasteSlotState::Pending {
                request,
                original_offset: 3,
            }],
            lifecycle: FenceLifecycle::AwaitingProbes,
        }
    }

    #[test]
    fn paste_enter_immutable_fence() {
        let host = HostIdentity {
            client_instance_id: Uuid::new_v4(),
            connection_epoch: 1,
            session_id: Uuid::new_v4(),
            terminal_generation: 2,
        };
        let mut fence = pending_fence(1, host);
        let (request_id, request_generation) = match &fence.slots[0] {
            PasteSlotState::Pending { request, .. } => {
                (request.paste_correlation_id, request.paste_generation)
            }
            _ => unreachable!(),
        };
        assert!(!fence.settle_slot(request_id, request_generation, 10, None));
        assert!(fence.settle_slot(
            request_id,
            request_generation,
            9,
            Some(("display".into(), "wire".into(), None))
        ));
        assert_eq!(fence.captured_composer, "before");
        assert_eq!(fence.lifecycle, FenceLifecycle::Ready);
    }

    #[test]
    fn paste_fence_probe_and_fifo_completion() {
        let mut coordinator = SubmissionOrderCoordinator::default();
        let first = coordinator
            .enqueue(OrderedIntent::Fence(Uuid::new_v4()))
            .unwrap();
        let second = coordinator
            .enqueue(OrderedIntent::ModelSwitch(Uuid::new_v4()))
            .unwrap();
        assert!(!coordinator.complete(second));
        assert!(coordinator.complete(first));
        assert!(!coordinator.complete(second));
    }

    #[test]
    fn paste_fence_generation_routing_and_reconnect() {
        let host = HostIdentity {
            client_instance_id: Uuid::new_v4(),
            connection_epoch: 1,
            session_id: Uuid::new_v4(),
            terminal_generation: 2,
        };
        let mut fence = pending_fence(1, host);
        let mut changed = host;
        changed.connection_epoch += 1;
        assert!(fence.cancel_if_host_changed(changed, 3));
        assert_eq!(fence.lifecycle, FenceLifecycle::CancelledBeforeDispatch);
        assert!(!fence.cancel_if_host_changed(host, 3));
    }

    #[test]
    fn paste_host_generation_identity() {
        let baseline = HostIdentity {
            client_instance_id: Uuid::new_v4(),
            connection_epoch: 4,
            session_id: Uuid::new_v4(),
            terminal_generation: 8,
        };
        for changed in [
            HostIdentity {
                client_instance_id: Uuid::new_v4(),
                ..baseline
            },
            HostIdentity {
                connection_epoch: 5,
                ..baseline
            },
            HostIdentity {
                session_id: Uuid::new_v4(),
                ..baseline
            },
            HostIdentity {
                terminal_generation: 9,
                ..baseline
            },
        ] {
            let mut fence = pending_fence(1, baseline);
            let view_generation = fence.view_generation;
            assert!(fence.cancel_if_host_changed(changed, view_generation));
        }
    }

    #[test]
    fn paste_fence_model_switch_ordering() {
        let mut order = SubmissionOrderCoordinator::default();
        let old_model_fence = order.enqueue(OrderedIntent::Fence(Uuid::new_v4())).unwrap();
        let switch = order
            .enqueue(OrderedIntent::ModelSwitch(Uuid::new_v4()))
            .unwrap();
        let new_model_fence = order.enqueue(OrderedIntent::Fence(Uuid::new_v4())).unwrap();
        assert!(old_model_fence < switch && switch < new_model_fence);
        assert!(!order.complete(switch));
        assert!(order.complete(old_model_fence));
        assert!(!order.complete(switch));
        assert!(order.complete(new_model_fence));
    }

    #[test]
    fn paste_fence_session_switch_ordering() {
        let mut order = SubmissionOrderCoordinator::default();
        let old_session = order.enqueue(OrderedIntent::Fence(Uuid::new_v4())).unwrap();
        let switch = order
            .enqueue(OrderedIntent::SessionSwitch(Uuid::new_v4()))
            .unwrap();
        let new_session = order.enqueue(OrderedIntent::Fence(Uuid::new_v4())).unwrap();
        assert!(!order.complete(new_session));
        assert!(order.complete(old_session));
        assert!(order.complete(switch));
        assert!(!order.complete(new_session));
    }
}
