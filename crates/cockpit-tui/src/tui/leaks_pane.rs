//! `/leaks` pane — the machine-wide Owner leak worklist with authenticated
//! reveal.
//!
//! The pane is the **sole owner** of a revealed `Zeroizing<String>`
//! ([`LeaksPaneRevealBuffer`]): a revealed secret lives for at most 30 seconds,
//! is rendered each frame only by borrowing `buffer.plaintext()`, and is
//! zeroized (with a generation bump) on close, daemon detach, timeout, a new
//! reveal, or a late-result generation mismatch. The plaintext is never copied
//! into App messages, cached `Text`, history, search, selection, clipboard,
//! `AsyncActionPayload`, analytics, or logs — the reveal RPC result travels
//! outside the async payload enum straight into this buffer.
//!
//! The list rows carry only safe metadata (`proto::LeakReportMetadata`), which
//! cannot represent plaintext, ciphertext, a prefix, a length, or a fingerprint.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use zeroize::Zeroizing;

use cockpit_core::daemon::proto::{
    LeakReportMetadata, LeakRotationDisposition, LeakRotationState, Request, Response,
};

/// The reveal buffer lifetime: 30 seconds.
pub const LEAK_REVEAL_BUFFER_TTL: Duration = Duration::from_secs(30);

/// The TUI-side ephemeral reveal buffer: the sole plaintext owner. A
/// `Zeroizing<String>` exists for at most [`LEAK_REVEAL_BUFFER_TTL`] and is
/// zeroized + generation-bumped on close/detach/timeout/new-reveal. The clock
/// is injectable so tests exercise the TTL without real sleeps.
pub struct LeaksPaneRevealBuffer {
    plaintext: Option<Zeroizing<String>>,
    report_id: Option<String>,
    generation: u64,
    created_at: Option<Instant>,
}

impl std::fmt::Debug for LeaksPaneRevealBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the plaintext — `Zeroizing<String>` derives a Debug that
        // would echo the secret. Report only presence/length and safe metadata.
        struct Redacted(Option<usize>);
        impl std::fmt::Debug for Redacted {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.0 {
                    Some(len) => write!(f, "<redacted; {len} bytes>"),
                    None => write!(f, "<none>"),
                }
            }
        }
        f.debug_struct("LeaksPaneRevealBuffer")
            .field(
                "plaintext",
                &Redacted(self.plaintext.as_ref().map(|p| p.len())),
            )
            .field("report_id", &self.report_id)
            .field("generation", &self.generation)
            .field("active", &self.plaintext.is_some())
            .finish()
    }
}

impl LeaksPaneRevealBuffer {
    pub fn new() -> Self {
        Self {
            plaintext: None,
            report_id: None,
            generation: 0,
            created_at: None,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_active(&self) -> bool {
        self.plaintext.is_some()
    }

    pub fn report_id(&self) -> Option<&str> {
        self.report_id.as_deref()
    }

    /// Install a revealed plaintext at `generation` using an injected `now`.
    /// A stale generation (a late result from before a zeroize) is rejected and
    /// the plaintext is dropped/zeroized on return.
    pub fn install_at(
        &mut self,
        plaintext: Zeroizing<String>,
        report_id: String,
        generation: u64,
        now: Instant,
    ) -> bool {
        if generation != self.generation {
            return false;
        }
        self.plaintext = Some(plaintext);
        self.report_id = Some(report_id);
        self.created_at = Some(now);
        true
    }

    /// Install using the real clock.
    pub fn install(
        &mut self,
        plaintext: Zeroizing<String>,
        report_id: String,
        generation: u64,
    ) -> bool {
        self.install_at(plaintext, report_id, generation, Instant::now())
    }

    /// If the TTL has elapsed relative to `now`, zeroize + bump the generation
    /// and return true.
    pub fn check_timeout_at(&mut self, now: Instant) -> bool {
        if let Some(created) = self.created_at
            && now.duration_since(created) >= LEAK_REVEAL_BUFFER_TTL
        {
            self.zeroize();
            return true;
        }
        false
    }

    /// Check the TTL against the real clock.
    pub fn check_timeout(&mut self) -> bool {
        self.check_timeout_at(Instant::now())
    }

    /// Zeroize the plaintext, clear the binding, and bump the generation so any
    /// in-flight late result is discarded on arrival.
    pub fn zeroize(&mut self) {
        // Dropping the `Zeroizing<String>` scrubs its bytes.
        self.plaintext = None;
        self.report_id = None;
        self.created_at = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Borrow the plaintext for rendering only. Never clone or copy this out.
    pub fn plaintext(&self) -> Option<&Zeroizing<String>> {
        self.plaintext.as_ref()
    }
}

impl Default for LeaksPaneRevealBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop-on-close zeroization: even if the pane is dropped without an explicit
/// close, the plaintext is scrubbed (`Zeroizing` handles the bytes).
impl Drop for LeaksPane {
    fn drop(&mut self) {
        self.reveal.zeroize();
    }
}

/// Distinct pane states so empty / filtered-empty / unavailable never collapse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaksPaneState {
    Loading,
    Ready,
    /// The machine list is empty (no filter active).
    Empty,
    /// A filter is active and matched nothing.
    FilteredEmpty,
    /// The daemon is detached / the list RPC failed.
    Unavailable,
}

pub struct LeaksPane {
    /// Unique identity for this concrete pane lifetime.  A reveal worker from
    /// a closed pane must never publish into a later pane whose local buffer
    /// generation happens to match.
    instance_id: uuid::Uuid,
    daemon_socket: Option<PathBuf>,
    reports: Vec<LeakReportMetadata>,
    selected: usize,
    next_cursor: Option<String>,
    has_more: bool,
    rotation_filter: Option<LeakRotationState>,
    state: LeaksPaneState,
    status: Option<String>,
    /// A report id awaiting an explicit delete confirmation.
    confirm_delete: Option<String>,
    /// The sole revealed-plaintext owner.
    reveal: LeaksPaneRevealBuffer,
    /// A distinct reveal error (rate-limited vs unavailable vs unauthorized).
    reveal_error: Option<String>,
    /// Set when the reveal buffer expired (TTL) and the App must force a full
    /// clear-and-redraw so no stale plaintext cells survive. Drained by the App
    /// via [`Self::take_pending_clear`] in both the timed tick and the render
    /// dispatch.
    pending_clear: bool,
}

/// The outcome of routing a key to the pane.
pub enum LeaksOutcome {
    Stay,
    Close,
    /// Run a metadata RPC (list/rotate/delete) asynchronously.
    Rpc(LeaksRpcAction),
    /// Begin the reveal of `report_id`; the App performs it off the async
    /// payload path and installs the plaintext into this pane's buffer at
    /// `generation`.
    Reveal {
        pane_instance_id: uuid::Uuid,
        report_id: String,
        generation: u64,
    },
    /// The buffer was just zeroized mid-session; the App must force a full
    /// clear-and-redraw so no stale plaintext cells survive.
    ForceClear,
}

/// A metadata-only leaks RPC. Never carries or returns plaintext.
pub struct LeaksRpcAction {
    daemon_socket: PathBuf,
    kind: LeaksRpcKind,
}

enum LeaksRpcKind {
    List {
        cursor: Option<String>,
        rotation: Option<LeakRotationState>,
        append: bool,
    },
    Rotate {
        report_id: String,
        rotation: LeakRotationDisposition,
    },
    Delete {
        report_id: String,
    },
}

/// The safe (Debug/Clone) result of a leaks metadata RPC. No plaintext.
#[derive(Debug, Clone)]
pub struct LeaksRpcResult {
    reports: Vec<LeakReportMetadata>,
    next_cursor: Option<String>,
    has_more: bool,
    append: bool,
    filtered: bool,
    status: Option<String>,
}

impl LeaksRpcAction {
    pub fn run_blocking_rpc(self) -> Result<LeaksRpcResult, String> {
        let socket = self.daemon_socket;
        let send = |request| crate::tui::agent_runner::daemon_request_at_blocking(&socket, request);
        match self.kind {
            LeaksRpcKind::List {
                cursor,
                rotation,
                append,
            } => {
                let filtered = rotation.is_some();
                match send(Request::ListLeakReports {
                    cursor,
                    limit: None,
                    project_root: None,
                    session_id: None,
                    rotation,
                })? {
                    Response::LeakReports { page } => Ok(LeaksRpcResult {
                        reports: page.reports,
                        next_cursor: page.next_cursor,
                        has_more: page.has_more,
                        append,
                        filtered,
                        status: None,
                    }),
                    other => Err(format!("unexpected leaks response: {other:?}")),
                }
            }
            LeaksRpcKind::Rotate {
                report_id,
                rotation,
            } => {
                send(Request::MarkLeakRotated {
                    report_id,
                    rotation,
                })?;
                // Re-list from the top after a mutation.
                relist(&socket, None).map(|mut r| {
                    r.status = Some("rotation updated".to_string());
                    r
                })
            }
            LeaksRpcKind::Delete { report_id } => {
                send(Request::DeleteLeakReport { report_id })?;
                relist(&socket, None).map(|mut r| {
                    r.status = Some("protected value deleted".to_string());
                    r
                })
            }
        }
    }
}

fn relist(
    socket: &std::path::Path,
    rotation: Option<LeakRotationState>,
) -> Result<LeaksRpcResult, String> {
    match crate::tui::agent_runner::daemon_request_at_blocking(
        socket,
        Request::ListLeakReports {
            cursor: None,
            limit: None,
            project_root: None,
            session_id: None,
            rotation,
        },
    )? {
        Response::LeakReports { page } => Ok(LeaksRpcResult {
            reports: page.reports,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
            append: false,
            filtered: rotation.is_some(),
            status: None,
        }),
        other => Err(format!("unexpected leaks response: {other:?}")),
    }
}

impl LeaksPane {
    /// Open the pane. The first page load is deferred to
    /// [`Self::initial_load_action`] so opening never blocks the runtime.
    pub fn open(daemon_socket: Option<PathBuf>) -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4(),
            daemon_socket,
            reports: Vec::new(),
            selected: 0,
            next_cursor: None,
            has_more: false,
            rotation_filter: None,
            state: LeaksPaneState::Loading,
            status: None,
            confirm_delete: None,
            reveal: LeaksPaneRevealBuffer::new(),
            reveal_error: None,
            pending_clear: false,
        }
    }

    pub fn instance_id(&self) -> uuid::Uuid {
        self.instance_id
    }

    /// The initial (first-page) list action, or `None` if the daemon socket is
    /// unknown (detached).
    pub fn initial_load_action(&self) -> Option<LeaksRpcAction> {
        Some(LeaksRpcAction {
            daemon_socket: self.daemon_socket.clone()?,
            kind: LeaksRpcKind::List {
                cursor: None,
                rotation: self.rotation_filter,
                append: false,
            },
        })
    }

    /// Apply a metadata RPC result (list/rotate/delete). Never receives plaintext.
    pub fn apply_rpc_result(&mut self, result: Result<LeaksRpcResult, String>) {
        match result {
            Ok(res) => {
                if res.append {
                    self.reports.extend(res.reports);
                } else {
                    self.reports = res.reports;
                    self.selected = 0;
                }
                self.next_cursor = res.next_cursor;
                self.has_more = res.has_more;
                self.status = res.status;
                self.state = if self.reports.is_empty() {
                    if res.filtered {
                        LeaksPaneState::FilteredEmpty
                    } else {
                        LeaksPaneState::Empty
                    }
                } else {
                    LeaksPaneState::Ready
                };
                self.clamp_selection();
            }
            Err(err) => {
                // A stale cursor auto-refreshes into a fresh snapshot.
                if err.contains("invalid_cursor") {
                    self.next_cursor = None;
                    self.status = Some("list refreshed".to_string());
                } else {
                    self.state = LeaksPaneState::Unavailable;
                    self.status = Some("daemon unavailable".to_string());
                }
            }
        }
    }

    /// Install a revealed secret (called by the App off the async-payload path).
    /// `expected_generation` is the generation captured when the reveal began;
    /// a mismatch (the buffer was zeroized/replaced meanwhile) discards the late
    /// result without installing it.
    pub fn install_reveal(
        &mut self,
        plaintext: Zeroizing<String>,
        report_id: String,
        expected_generation: u64,
    ) {
        if expected_generation != self.reveal.generation() {
            // Late/stale result: `plaintext` (a Zeroizing<String>) is scrubbed
            // on drop here; never installed.
            return;
        }
        self.reveal
            .install(plaintext, report_id, expected_generation);
        self.reveal_error = None;
    }

    /// Record a distinct reveal denial message.
    pub fn set_reveal_error(&mut self, message: impl Into<String>) {
        self.reveal_error = Some(message.into());
    }

    /// Zeroize the reveal buffer (close/detach). Returns whether it was active.
    pub fn zeroize_reveal(&mut self) -> bool {
        let was_active = self.reveal.is_active();
        self.reveal.zeroize();
        was_active
    }

    /// Borrow the reveal buffer (for tests / render).
    pub fn reveal_buffer(&self) -> &LeaksPaneRevealBuffer {
        &self.reveal
    }

    /// Service the TTL. If the buffer just timed out it is zeroized and a full
    /// clear is flagged (drained via [`Self::take_pending_clear`]). Returns
    /// whether it just expired. Driven from the App's timed tick so an idle pane
    /// (no re-render) still expires + clears on time.
    pub fn tick(&mut self) -> bool {
        self.tick_at(Instant::now())
    }

    /// [`Self::tick`] with an injected clock (test seam for the 30s TTL).
    pub fn tick_at(&mut self, now: Instant) -> bool {
        if self.reveal.check_timeout_at(now) {
            self.pending_clear = true;
            true
        } else {
            false
        }
    }

    /// Take the "force a full clear" flag set on TTL expiry (or a render-time
    /// expiry). The App sets `leaks_reveal_clear_pending` from this.
    pub fn take_pending_clear(&mut self) -> bool {
        std::mem::take(&mut self.pending_clear)
    }

    fn clamp_selection(&mut self) {
        if self.selected >= self.reports.len() {
            self.selected = self.reports.len().saturating_sub(1);
        }
    }

    fn selected_report_id(&self) -> Option<String> {
        self.reports.get(self.selected).map(|r| r.report_id.clone())
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> LeaksOutcome {
        // A live reveal buffer: any key hides (zeroizes) it and forces a clear
        // so no stale plaintext cells survive.
        if self.reveal.is_active() {
            self.reveal.zeroize();
            return LeaksOutcome::ForceClear;
        }

        // A pending delete confirmation.
        if let Some(report_id) = self.confirm_delete.clone() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.confirm_delete = None;
                    if let Some(socket) = self.daemon_socket.clone() {
                        return LeaksOutcome::Rpc(LeaksRpcAction {
                            daemon_socket: socket,
                            kind: LeaksRpcKind::Delete { report_id },
                        });
                    }
                    return LeaksOutcome::Stay;
                }
                _ => {
                    self.confirm_delete = None;
                    return LeaksOutcome::Stay;
                }
            }
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => LeaksOutcome::Close,
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                LeaksOutcome::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.reports.len() {
                    self.selected += 1;
                } else if self.has_more {
                    // Page at end: fetch the next page with the MAC cursor.
                    if let (Some(socket), Some(cursor)) =
                        (self.daemon_socket.clone(), self.next_cursor.clone())
                    {
                        return LeaksOutcome::Rpc(LeaksRpcAction {
                            daemon_socket: socket,
                            kind: LeaksRpcKind::List {
                                cursor: Some(cursor),
                                rotation: self.rotation_filter,
                                append: true,
                            },
                        });
                    }
                }
                LeaksOutcome::Stay
            }
            KeyCode::Enter | KeyCode::Char('r') => {
                if let Some(report_id) = self.selected_report_id() {
                    LeaksOutcome::Reveal {
                        pane_instance_id: self.instance_id,
                        report_id,
                        generation: self.reveal.generation(),
                    }
                } else {
                    LeaksOutcome::Stay
                }
            }
            KeyCode::Char('a') => self.rotate(LeakRotationDisposition::Accept),
            KeyCode::Char('d') => self.rotate(LeakRotationDisposition::Dismiss),
            KeyCode::Char('m') => self.rotate(LeakRotationDisposition::Rotated),
            KeyCode::Char('D') => {
                if let Some(report_id) = self.selected_report_id() {
                    self.confirm_delete = Some(report_id);
                }
                LeaksOutcome::Stay
            }
            _ => LeaksOutcome::Stay,
        }
    }

    fn rotate(&mut self, rotation: LeakRotationDisposition) -> LeaksOutcome {
        if let (Some(socket), Some(report_id)) =
            (self.daemon_socket.clone(), self.selected_report_id())
        {
            LeaksOutcome::Rpc(LeaksRpcAction {
                daemon_socket: socket,
                kind: LeaksRpcKind::Rotate {
                    report_id,
                    rotation,
                },
            })
        } else {
            LeaksOutcome::Stay
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        // Service the TTL each frame so an expired secret is never drawn; flag a
        // full clear so the App scrubs the backbuffer (stale/shorter cells).
        if self.reveal.check_timeout() {
            self.pending_clear = true;
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" /leaks — contained leak reports ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();

        if let Some(plaintext) = self.reveal.plaintext() {
            // The plaintext is rendered by borrowing the buffer — never copied
            // into any cached Text/history/message.
            lines.push(Line::from(Span::styled(
                format!("revealed [{}]:", self.reveal.report_id().unwrap_or("")),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            // Borrow the plaintext straight from the zeroizing buffer — no owned
            // `String`/`Span` copy is created (an owned copy would not be
            // scrubbed when the `Line` drops, breaking sole-owner containment).
            lines.push(Line::from(Span::styled(
                plaintext.as_str(),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "press any key to hide (auto-hides in 30s)",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            match &self.state {
                LeaksPaneState::Loading => lines.push(Line::from("loading…")),
                LeaksPaneState::Empty => lines.push(Line::from("no contained leak reports")),
                LeaksPaneState::FilteredEmpty => {
                    lines.push(Line::from("no reports match the active filter"))
                }
                LeaksPaneState::Unavailable => {
                    lines.push(Line::from("daemon unavailable — reattach and retry"))
                }
                LeaksPaneState::Ready => {
                    for (i, report) in self.reports.iter().enumerate() {
                        let marker = if i == self.selected { "▶ " } else { "  " };
                        let style = if i == self.selected {
                            Style::default().add_modifier(Modifier::REVERSED)
                        } else {
                            Style::default()
                        };
                        lines.push(Line::from(Span::styled(
                            format!(
                                "{marker}{} | {} | {} | {} | {}",
                                report.report_id,
                                report.source,
                                report.category,
                                report.status,
                                report.rotation
                            ),
                            style,
                        )));
                    }
                    if self.has_more {
                        lines.push(Line::from(Span::styled(
                            "… more (scroll down)",
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
            }

            if let Some(report_id) = &self.confirm_delete {
                lines.push(Line::from(Span::styled(
                    format!("delete protected value for {report_id}? (y/N)"),
                    Style::default().fg(Color::Red),
                )));
            }
            if let Some(err) = &self.reveal_error {
                lines.push(Line::from(Span::styled(
                    err.clone(),
                    Style::default().fg(Color::Red),
                )));
            }
            if let Some(status) = &self.status {
                lines.push(Line::from(Span::styled(
                    status.clone(),
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines.push(Line::from(Span::styled(
                "enter/r reveal · a accept · d dismiss · m rotated · D delete · esc close",
                Style::default().fg(Color::DarkGray),
            )));
        }

        frame.render_widget(Paragraph::new(lines), inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> Zeroizing<String> {
        Zeroizing::new("SENTINEL_SECRET_123".to_owned())
    }

    #[test]
    fn leaks_pane_reveal_buffer_lifecycle() {
        let mut buf = LeaksPaneRevealBuffer::new();
        let gen0 = buf.generation();
        assert!(!buf.is_active());

        // Install at the current generation succeeds; the plaintext is the sole
        // owner and renders from a borrow.
        let now = Instant::now();
        assert!(buf.install_at(sample_secret(), "r1".into(), gen0, now));
        assert!(buf.is_active());
        assert_eq!(buf.plaintext().unwrap().as_str(), "SENTINEL_SECRET_123");
        assert_eq!(buf.report_id(), Some("r1"));

        // A late result from a PRIOR generation is discarded.
        buf.zeroize();
        let gen1 = buf.generation();
        assert_ne!(gen0, gen1);
        assert!(!buf.is_active());
        assert!(!buf.install_at(sample_secret(), "r1".into(), gen0, now));
        assert!(!buf.is_active());

        // The 30s TTL (injected time, no real sleeps) zeroizes and bumps the
        // generation.
        assert!(buf.install_at(sample_secret(), "r2".into(), gen1, now));
        assert!(!buf.check_timeout_at(now + Duration::from_secs(29)));
        assert!(buf.is_active());
        assert!(buf.check_timeout_at(now + Duration::from_secs(30)));
        assert!(!buf.is_active());
        assert_ne!(buf.generation(), gen1);

        // Close/detach zeroize and retire the generation.
        let gen2 = buf.generation();
        buf.install_at(sample_secret(), "r3".into(), gen2, now);
        assert!(buf.is_active());
        buf.zeroize();
        assert!(!buf.is_active());
        assert!(buf.plaintext().is_none());
    }

    #[test]
    fn leaks_pane_install_reveal_is_sole_owner() {
        let mut pane = LeaksPane::open(Some(PathBuf::from("/test.sock")));
        pane.install_reveal(
            sample_secret(),
            "r1".into(),
            pane.reveal_buffer().generation(),
        );
        assert!(pane.reveal_buffer().is_active());
        assert_eq!(
            pane.reveal_buffer().plaintext().unwrap().as_str(),
            "SENTINEL_SECRET_123"
        );
        // Zeroize on close scrubs it.
        assert!(pane.zeroize_reveal());
        assert!(!pane.reveal_buffer().is_active());
    }

    #[test]
    fn reopened_pane_has_distinct_reveal_authority_identity() {
        let first = LeaksPane::open(Some(PathBuf::from("/test.sock")));
        let first_id = first.instance_id();
        drop(first);
        let second = LeaksPane::open(Some(PathBuf::from("/test.sock")));
        assert_ne!(first_id, second.instance_id());
        assert_eq!(second.reveal_buffer().generation(), 0);
    }

    /// TU1: the 30s TTL (injected clock) zeroizes the buffer AND flags a full
    /// clear so the App scrubs the terminal backbuffer — an idle pane expires
    /// via `tick_at` without any render.
    #[test]
    fn leaks_pane_ttl_expiry_flags_clear() {
        let mut pane = LeaksPane::open(Some(PathBuf::from("/t.sock")));
        pane.install_reveal(
            sample_secret(),
            "r1".into(),
            pane.reveal_buffer().generation(),
        );
        assert!(pane.reveal_buffer().is_active());
        let base = Instant::now();

        // Before the TTL: no expiry, no clear flag.
        assert!(!pane.tick_at(base + Duration::from_secs(29)));
        assert!(!pane.take_pending_clear());
        assert!(pane.reveal_buffer().is_active());

        // At the TTL: zeroize + flag a full clear.
        assert!(pane.tick_at(base + Duration::from_secs(30)));
        assert!(
            !pane.reveal_buffer().is_active(),
            "TTL must zeroize the buffer"
        );
        assert!(
            pane.take_pending_clear(),
            "TTL expiry must flag a full clear"
        );
        // The flag is one-shot.
        assert!(!pane.take_pending_clear());
    }
}
