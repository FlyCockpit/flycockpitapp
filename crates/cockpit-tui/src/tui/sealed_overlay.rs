//! `/sealed` Owner command frontend: routing, no-echo write overlays, and the
//! ephemeral recover reveal.
//!
//! The TUI is a pure frontend over the remoted sealed-owner channel
//! ([`cockpit_core::sealed::owner_commands::parse_sealed_command`] parses the
//! grammar; the daemon serves every operation). This module NEVER opens the
//! credential store, the local database, or the vault directly: it only
//! constructs proto [`Request`]s and renders safe metadata.
//!
//! # Secret containment
//!
//! * A create/replace/rotate literal is entered through the **no-echo**
//!   [`SealedInputBuffer`]: a `Zeroizing<String>` that is masked on render, is
//!   redacted in `Debug`, exposes no `as_str`, and can only be moved out ONCE
//!   (into the apply request's [`SensitiveWireLiteral`]). It never enters the
//!   transcript, history, scrollback, an `AsyncActionPayload`, or a log.
//! * Dismissing a write overlay (keyboard **or** pointer) zeroizes the buffer
//!   and yields [`SealedOverlayOutcome::Cancel`] so the App spends and drops the
//!   minted capability.
//! * A recover reveal lives only in the ephemeral [`SealedRevealBuffer`], is
//!   painted by borrowing the `Zeroizing` buffer for a single frame, and is
//!   zeroized on dismiss/timeout/close/drop. The plaintext is never copied out.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use zeroize::Zeroizing;

use cockpit_core::sealed::identity::SealedScopeKind;
use cockpit_core::sealed::owner_commands::{SealedActionCommand, SealedCommand};
use cockpit_proto::{
    MAX_SENSITIVE_FRAME_BYTES, Request, Response, SealedOwnerInventoryItem, SealedOwnerScopeKind,
    SensitiveWireLiteral,
};

/// The ephemeral recover reveal lifetime: 30 seconds (mirrors `/leaks`).
pub const SEALED_REVEAL_BUFFER_TTL: Duration = Duration::from_secs(30);

/// Client-supplied scope key material for a `create` begin. The daemon requires
/// an explicit (possibly empty) `scope_key`: a session id for session scope, the
/// canonical project key for project scope, and an empty string for global.
/// Derived from the live App context; NOT from any vault read.
#[derive(Debug, Clone)]
pub(crate) struct SealedScopeContext {
    pub session_id: String,
    pub project_key: String,
}

/// Which write disposition a no-echo overlay is collecting a literal for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedWriteDisposition {
    Create,
    Replace,
    Rotate,
}

impl SealedWriteDisposition {
    /// The wire `disposition` string the daemon's closed matcher expects.
    fn wire(self) -> &'static str {
        match self {
            SealedWriteDisposition::Create => "create",
            SealedWriteDisposition::Replace => "replace",
            SealedWriteDisposition::Rotate => "rotate",
        }
    }

    /// A safe past-tense verb for the success line.
    fn done_verb(self) -> &'static str {
        match self {
            SealedWriteDisposition::Create => "created",
            SealedWriteDisposition::Replace => "replaced",
            SealedWriteDisposition::Rotate => "rotated",
        }
    }
}

/// A planned no-echo write: the `begin` request to mint the capability, the
/// disposition, and a SAFE label (name or record id — never a literal).
#[derive(Debug, Clone)]
pub(crate) struct SealedWritePlan {
    pub begin: Request,
    pub disposition: SealedWriteDisposition,
    pub label: String,
}

/// A planned literal-free owner control: `begin`, then immediately apply its
/// capability on the same attached connection.
#[derive(Debug, Clone)]
pub(crate) struct SealedControlPlan {
    pub begin: Request,
    pub success: String,
}

/// The routing decision for a parsed `/sealed` command.
#[derive(Debug)]
pub(crate) enum SealedDispatch {
    /// A metadata-only RPC: send it and render the safe response text.
    Metadata(Request),
    /// A create/replace/rotate write: `begin`, then open a no-echo overlay.
    Write(SealedWritePlan),
    /// A recover: `begin` + `apply(recover)` on one connection, reveal overlay.
    Recover { record_id: String },
    /// A reset/promotion: `begin` + literal-free control apply on one connection.
    Control(SealedControlPlan),
    /// A command with no landed owner RPC (fail closed with a message).
    Unsupported(String),
}

/// A fixed, content-free message for ANY `/sealed` parse failure.
///
/// The raw `parse_sealed_command` error echoes the rejected token verbatim (e.g.
/// `unknown `/sealed` subcommand: `<token>``). A user who mistypes a secret on
/// the command line — `/sealed <ACTUAL_SECRET>`, the exact misuse the no-echo
/// design exists to defend against — would otherwise get it echoed into
/// scrollback/history/exit-tail. This message NEVER contains the user's input.
pub(crate) const SEALED_PARSE_ERROR: &str = "/sealed: invalid command — try /sealed help";

/// Parse `/sealed` tokens, mapping ANY failure to the content-free
/// [`SEALED_PARSE_ERROR`]. This is the single funnel every render/history path
/// goes through, so no typed token can reach the transcript.
pub(crate) fn parse_sealed_tokens(tokens: &[&str]) -> Result<SealedCommand, &'static str> {
    cockpit_core::sealed::owner_commands::parse_sealed_command(tokens)
        .map_err(|_| SEALED_PARSE_ERROR)
}

fn scope_kind_wire(scope: &SealedScopeKind) -> &'static str {
    match scope {
        SealedScopeKind::Session => "session",
        SealedScopeKind::Project => "project",
        SealedScopeKind::Global => "global",
        SealedScopeKind::KnowledgeBase => "knowledge_base",
    }
}

/// The `begin` request for a create, or `None` if `ctx` is unavailable. Session
/// scope requires a session id and project scope a project key; global uses an
/// empty key.
fn create_begin(
    name: &str,
    scope: &SealedScopeKind,
    description: &str,
    ctx: &SealedScopeContext,
) -> Request {
    let scope_key = match scope {
        SealedScopeKind::Session => ctx.session_id.clone(),
        SealedScopeKind::Project => ctx.project_key.clone(),
        SealedScopeKind::Global => String::new(),
        // KB-scoped values are created by the KB flow, which supplies an exact
        // KB id. The generic /sealed overlay has no ambient KB attachment.
        SealedScopeKind::KnowledgeBase => String::new(),
    };
    Request::BeginSealedOwnerOperation {
        disposition: "create".to_string(),
        record_id: None,
        name: Some(name.to_string()),
        description: Some(description.to_string()),
        scope_kind: Some(scope_kind_wire(scope).to_string()),
        scope_key: Some(scope_key),
    }
}

/// The `begin` request for a replace/rotate/recover (record id only).
fn record_begin(disposition: &str, record_id: &str) -> Request {
    Request::BeginSealedOwnerOperation {
        disposition: disposition.to_string(),
        record_id: Some(record_id.to_string()),
        name: None,
        description: None,
        scope_kind: None,
        scope_key: None,
    }
}

fn promote_begin(
    record_id: &str,
    target_scope: &SealedScopeKind,
    ctx: &SealedScopeContext,
) -> Request {
    let scope_key = match target_scope {
        SealedScopeKind::Project => ctx.project_key.clone(),
        SealedScopeKind::Global => String::new(),
        // The command parser rejects non-persistent targets before dispatch.
        SealedScopeKind::Session | SealedScopeKind::KnowledgeBase => String::new(),
    };
    Request::BeginSealedOwnerOperation {
        disposition: "promote".to_string(),
        record_id: Some(record_id.to_string()),
        name: None,
        description: None,
        scope_kind: Some(scope_kind_wire(target_scope).to_string()),
        scope_key: Some(scope_key),
    }
}

/// The apply request for a create/replace/rotate write. The `literal` rides the
/// apply frame and nowhere else.
pub(crate) fn apply_write_request(capability_id: &str, literal: SensitiveWireLiteral) -> Request {
    Request::ApplySealedOwnerOperation {
        capability_id: capability_id.to_string(),
        literal: Some(literal),
    }
}

/// The cancel request for a minted capability.
pub(crate) fn cancel_request(capability_id: &str) -> Request {
    Request::CancelSealedOwnerOperation {
        capability_id: capability_id.to_string(),
    }
}

/// Route a parsed `/sealed` command to its owner RPC(s). Metadata commands map
/// to a single request; create/replace/rotate open a no-echo overlay; recover
/// reveals; reset/promotion use literal-free controls; delete has no remoted
/// owner RPC and fails closed.
pub(crate) fn plan_dispatch(cmd: &SealedCommand, ctx: &SealedScopeContext) -> SealedDispatch {
    match cmd {
        SealedCommand::List { scope, project } => {
            SealedDispatch::Metadata(Request::SealedOwnerInventory {
                scope_kind: scope.as_ref().map(|s| scope_kind_wire(s).to_string()),
                scope_key: project.clone(),
            })
        }
        SealedCommand::Create {
            name,
            scope,
            description,
        } => SealedDispatch::Write(SealedWritePlan {
            begin: create_begin(name.as_str(), scope, description.as_str(), ctx),
            disposition: SealedWriteDisposition::Create,
            label: name.as_str().to_string(),
        }),
        SealedCommand::Replace { record_id } => SealedDispatch::Write(SealedWritePlan {
            begin: record_begin("replace", &record_id.to_string()),
            disposition: SealedWriteDisposition::Replace,
            label: record_id.to_string(),
        }),
        SealedCommand::Rotate { record_id } => SealedDispatch::Write(SealedWritePlan {
            begin: record_begin("rotate", &record_id.to_string()),
            disposition: SealedWriteDisposition::Rotate,
            label: record_id.to_string(),
        }),
        SealedCommand::Recover { record_id } => SealedDispatch::Recover {
            record_id: record_id.to_string(),
        },
        SealedCommand::Edit {
            record_id,
            description,
        } => SealedDispatch::Metadata(Request::EditSealedOwnerDescription {
            record_id: record_id.to_string(),
            description: description.as_str().to_string(),
        }),
        SealedCommand::Delete { .. } => SealedDispatch::Unsupported(
            "/sealed: delete has no owner RPC; rotate or replace the value instead".to_string(),
        ),
        SealedCommand::Reset { record_id, .. } => SealedDispatch::Control(SealedControlPlan {
            begin: record_begin("reset", &record_id.to_string()),
            success: format!("reset {record_id}"),
        }),
        SealedCommand::Promote {
            record_id,
            target_scope,
        } => SealedDispatch::Control(SealedControlPlan {
            begin: promote_begin(&record_id.to_string(), target_scope, ctx),
            success: format!(
                "promoted {record_id} to {} scope",
                scope_kind_wire(target_scope)
            ),
        }),
        SealedCommand::Action(action) => SealedDispatch::Metadata(action_request(action)),
    }
}

fn action_request(action: &SealedActionCommand) -> Request {
    match action {
        SealedActionCommand::List => Request::ListSealedActions,
        SealedActionCommand::Create {
            kind_id,
            project_id,
            description,
            origin_id,
            projection_id,
        } => Request::CreateSealedAction {
            kind_id: kind_id.clone(),
            project_id: project_id.clone(),
            description: description.as_str().to_string(),
            origin_id: origin_id.clone(),
            projection_id: projection_id.clone(),
        },
        SealedActionCommand::ReviseDescription {
            action_id,
            description,
        } => Request::ReviseSealedActionDescription {
            action_id: action_id.clone(),
            description: description.as_str().to_string(),
        },
        SealedActionCommand::ReviseEnabled { action_id, enabled } => {
            Request::ReviseSealedActionEnabled {
                action_id: action_id.clone(),
                enabled: *enabled,
            }
        }
        SealedActionCommand::Retire { action_id, confirm } => Request::RetireSealedAction {
            action_id: action_id.clone(),
            confirm: confirm.clone(),
        },
    }
}

fn scope_kind_label(kind: SealedOwnerScopeKind) -> &'static str {
    match kind {
        SealedOwnerScopeKind::Session => "session",
        SealedOwnerScopeKind::Project => "project",
        SealedOwnerScopeKind::Global => "global",
        SealedOwnerScopeKind::KnowledgeBase => "knowledge base",
    }
}

/// Render a page of sealed inventory as transcript text. Takes only
/// `&[SealedOwnerInventoryItem]`, which CANNOT represent a plaintext literal by
/// construction; every rendered field is safe metadata.
pub(crate) fn format_sealed_inventory(items: &[SealedOwnerInventoryItem]) -> String {
    if items.is_empty() {
        return "/sealed: no sealed values".to_string();
    }
    let mut out = String::from("/sealed: record_id | name | scope | key | version | description");
    for item in items {
        out.push('\n');
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {}",
            item.record_id,
            item.name,
            scope_kind_label(item.scope_kind),
            item.scope_key,
            item.active_version,
            item.description,
        ));
    }
    out
}

/// Map a `/sealed` metadata daemon result to transcript text. Follows the
/// `/leaks` shape: the unexpected-response arm NEVER renders a `Debug` of a
/// daemon response, so a `SealedOwnerOperationApplied` (the only literal-bearing
/// response) can never surface a revealed literal through this path.
pub(crate) fn sealed_response_text(result: Result<Response, String>) -> String {
    match result {
        Ok(Response::SealedOwnerInventory { items }) => format_sealed_inventory(&items),
        Ok(Response::SealedOwnerDescriptionEdited { record_id }) => {
            format!("/sealed: description updated for {record_id}")
        }
        Ok(Response::SealedActions { actions }) => {
            if actions.is_empty() {
                "/sealed action: no sealed actions".to_string()
            } else {
                let mut out = String::from(
                    "/sealed action: action_id | revision | enabled | project | description",
                );
                for action in actions {
                    out.push('\n');
                    out.push_str(&format!(
                        "{} | {} | {} | {} | {}",
                        action.action_id,
                        action.revision,
                        action.enabled,
                        action.project_key,
                        action.description,
                    ));
                }
                out
            }
        }
        Ok(Response::SealedActionCreated {
            action_id,
            revision,
        }) => format!("/sealed action: created {action_id} (revision {revision})"),
        Ok(Response::SealedActionRevised {
            action_id,
            revision,
        }) => format!("/sealed action: revised {action_id} (revision {revision})"),
        Ok(Response::SealedActionRetired { action_id, retired }) => {
            if retired {
                format!("/sealed action: retired {action_id}")
            } else {
                format!("/sealed action: {action_id} was already retired")
            }
        }
        Ok(_) => "/sealed: unexpected daemon response".to_string(),
        Err(e) => format!("/sealed: {e}"),
    }
}

/// The no-echo sealed-literal input buffer: the sole owner of a typed
/// `Zeroizing<String>`. It exposes NO plaintext accessor; the literal can only
/// be moved out ONCE via [`Self::take`] (into the apply frame's
/// [`SensitiveWireLiteral`]). Masked on render, redacted in `Debug`.
pub(crate) struct SealedInputBuffer {
    value: Zeroizing<String>,
}

impl std::fmt::Debug for SealedInputBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the buffered literal; report only its byte length.
        write!(
            f,
            "SealedInputBuffer(<redacted; {} bytes>)",
            self.value.len()
        )
    }
}

impl SealedInputBuffer {
    /// A zeroizing buffer pre-sized to the frame ceiling so per-keystroke
    /// `push`es never reallocate. A realloc would copy the partial secret into a
    /// fresh allocation and free the old one WITHOUT zeroizing it, stranding
    /// plaintext fragments in freed heap — the exact leak this type promises to
    /// avoid. Because `push` refuses any char that would exceed
    /// `MAX_SENSITIVE_FRAME_BYTES`, the reserved capacity is never outgrown, and
    /// `Zeroizing`'s drop scrubs the full capacity. 16 KiB is a trivial
    /// per-overlay allocation.
    fn empty_value() -> Zeroizing<String> {
        Zeroizing::new(String::with_capacity(MAX_SENSITIVE_FRAME_BYTES))
    }

    pub fn new() -> Self {
        Self {
            value: Self::empty_value(),
        }
    }

    /// Append a typed character, bounded by [`MAX_SENSITIVE_FRAME_BYTES`]. A
    /// character that would overflow the frame ceiling is dropped (fail closed).
    pub fn push(&mut self, c: char) {
        if self.value.len() + c.len_utf8() > MAX_SENSITIVE_FRAME_BYTES {
            return;
        }
        self.value.push(c);
    }

    pub fn pop(&mut self) {
        self.value.pop();
    }

    /// Zeroize the buffer (dismiss/close). Dropping `Zeroizing` scrubs the bytes.
    pub fn clear(&mut self) {
        self.value = Self::empty_value();
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The number of buffered characters — used only to size the render mask.
    pub fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    /// Move the literal out inside its zeroizing buffer, leaving `self` empty.
    /// No intermediate non-zeroizing copy is made.
    pub fn take(&mut self) -> Zeroizing<String> {
        std::mem::replace(&mut self.value, Self::empty_value())
    }
}

impl Default for SealedInputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// The ephemeral recover reveal buffer: the sole owner of a revealed
/// `Zeroizing<String>`, mirroring the `/leaks` reveal contract. Rendered by
/// borrowing the buffer for a single frame; zeroized (with a generation bump) on
/// dismiss/timeout/close. The clock is injectable for tests.
pub(crate) struct SealedRevealBuffer {
    plaintext: Option<Zeroizing<String>>,
    created_at: Option<Instant>,
}

impl std::fmt::Debug for SealedRevealBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the plaintext; report only presence/length.
        f.debug_struct("SealedRevealBuffer")
            .field(
                "plaintext",
                &self
                    .plaintext
                    .as_ref()
                    .map(|p| format!("<redacted; {} bytes>", p.len())),
            )
            .field("active", &self.plaintext.is_some())
            .finish()
    }
}

impl SealedRevealBuffer {
    pub fn new() -> Self {
        Self {
            plaintext: None,
            created_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.plaintext.is_some()
    }

    /// Install a revealed literal at `now`. Any prior plaintext is scrubbed first.
    pub fn install_at(&mut self, plaintext: Zeroizing<String>, now: Instant) {
        self.zeroize();
        self.plaintext = Some(plaintext);
        self.created_at = Some(now);
    }

    pub fn install(&mut self, plaintext: Zeroizing<String>) {
        self.install_at(plaintext, Instant::now());
    }

    /// Zeroize the plaintext, clearing the reveal.
    pub fn zeroize(&mut self) {
        self.plaintext = None;
        self.created_at = None;
    }

    /// If the TTL has elapsed relative to `now`, zeroize and return true.
    pub fn check_timeout_at(&mut self, now: Instant) -> bool {
        if let Some(created) = self.created_at
            && now.duration_since(created) >= SEALED_REVEAL_BUFFER_TTL
        {
            self.zeroize();
            return true;
        }
        false
    }

    pub fn check_timeout(&mut self) -> bool {
        self.check_timeout_at(Instant::now())
    }

    /// Borrow the plaintext for rendering only. Never clone or copy this out.
    pub fn plaintext(&self) -> Option<&Zeroizing<String>> {
        self.plaintext.as_ref()
    }
}

impl Default for SealedRevealBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// A live no-echo write overlay bound to a minted capability.
pub(crate) struct SealedWriteOverlay {
    capability_id: String,
    expires_at_ms: i64,
    disposition: SealedWriteDisposition,
    label: String,
    input: SealedInputBuffer,
    error: Option<String>,
}

impl SealedWriteOverlay {
    pub fn new(
        capability_id: String,
        expires_at_ms: i64,
        disposition: SealedWriteDisposition,
        label: String,
    ) -> Self {
        Self {
            capability_id,
            expires_at_ms,
            disposition,
            label,
            input: SealedInputBuffer::new(),
            error: None,
        }
    }

    pub fn disposition(&self) -> SealedWriteDisposition {
        self.disposition
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// Route a key. Enter submits (moving the literal into the apply frame), Esc
    /// cancels (zeroizing the buffer), printable characters are captured no-echo.
    pub fn handle_key(&mut self, key: KeyEvent) -> SealedOverlayOutcome {
        match key.code {
            KeyCode::Esc => {
                self.input.clear();
                SealedOverlayOutcome::Cancel {
                    capability_id: self.capability_id.clone(),
                }
            }
            KeyCode::Enter => {
                if self.input.is_empty() {
                    self.error = Some("literal must not be empty".to_string());
                    return SealedOverlayOutcome::Stay;
                }
                // Move the literal straight into the zeroizing wire type — no
                // intermediate non-zeroizing copy, and the buffer is left empty.
                let literal = SensitiveWireLiteral::from_zeroizing(self.input.take());
                SealedOverlayOutcome::Apply {
                    capability_id: self.capability_id.clone(),
                    literal,
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
                SealedOverlayOutcome::Stay
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.clear();
                SealedOverlayOutcome::Stay
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.push(c);
                SealedOverlayOutcome::Stay
            }
            _ => SealedOverlayOutcome::Stay,
        }
    }

    /// A pointer dismiss (a click on the overlay). Cancels exactly like Esc, so
    /// mouse users also spend and drop the capability.
    pub fn pointer_dismiss(&mut self) -> SealedOverlayOutcome {
        self.input.clear();
        SealedOverlayOutcome::Cancel {
            capability_id: self.capability_id.clone(),
        }
    }

    /// Exit/interrupt teardown: zeroize the typed buffer and surrender the
    /// capability id so the caller can send a best-effort
    /// `CancelSealedOwnerOperation` before shutdown. The overlay must not be
    /// applied after this.
    pub fn take_capability_for_teardown(&mut self) -> String {
        self.input.clear();
        self.capability_id.clone()
    }

    fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" /sealed — no-echo sensitive frame ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let muted = Style::default().fg(Color::DarkGray);
        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("{} `{}`", self.disposition.wire(), self.label),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!(
                "capability {} · expires_at {}ms",
                self.capability_id, self.expires_at_ms
            ),
            muted,
        )));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "enter the value (not echoed):",
            Style::default().fg(Color::White),
        )));
        // Mask the typed literal — render a bullet per character, never the
        // characters themselves.
        let mask: String = "•".repeat(self.input.char_count());
        lines.push(Line::from(Span::styled(
            format!("[{mask}]"),
            Style::default().fg(Color::Cyan),
        )));
        if let Some(err) = &self.error {
            lines.push(Line::from(Span::styled(
                err.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "enter: apply · esc/click: cancel (drops the capability)",
            muted,
        )));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// A live recover reveal overlay. Paints the plaintext once, then zeroizes on
/// any key / pointer / timeout / drop.
pub(crate) struct SealedRevealOverlay {
    record_id: String,
    reveal: SealedRevealBuffer,
    /// Set when the buffer was zeroized mid-session (dismiss/timeout); the App
    /// drains it to force a full screen clear so no stale plaintext cells linger.
    pending_clear: bool,
}

impl SealedRevealOverlay {
    pub fn new(record_id: String, plaintext: Zeroizing<String>) -> Self {
        let mut reveal = SealedRevealBuffer::new();
        reveal.install(plaintext);
        Self {
            record_id,
            reveal,
            pending_clear: false,
        }
    }

    pub fn reveal_buffer(&self) -> &SealedRevealBuffer {
        &self.reveal
    }

    /// Service the TTL (driven from the App's timed tick so an idle reveal still
    /// expires on time). Returns whether it just expired.
    pub fn tick_at(&mut self, now: Instant) -> bool {
        if self.reveal.check_timeout_at(now) {
            self.pending_clear = true;
            true
        } else {
            false
        }
    }

    pub fn tick(&mut self) -> bool {
        self.tick_at(Instant::now())
    }

    /// Take the "force a full clear" flag.
    pub fn take_pending_clear(&mut self) -> bool {
        std::mem::take(&mut self.pending_clear)
    }

    /// Any key hides (zeroizes) the reveal and closes the overlay.
    pub fn handle_key(&mut self, _key: KeyEvent) -> SealedOverlayOutcome {
        self.reveal.zeroize();
        self.pending_clear = true;
        SealedOverlayOutcome::Close
    }

    /// A pointer dismiss hides (zeroizes) the reveal and closes.
    pub fn pointer_dismiss(&mut self) -> SealedOverlayOutcome {
        self.reveal.zeroize();
        self.pending_clear = true;
        SealedOverlayOutcome::Close
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        // Service the TTL each frame so an expired secret is never drawn.
        if self.reveal.check_timeout() {
            self.pending_clear = true;
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" /sealed recover — reveal ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();
        if let Some(plaintext) = self.reveal.plaintext() {
            lines.push(Line::from(Span::styled(
                format!("revealed [{}]:", self.record_id),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            // Borrow the plaintext straight from the zeroizing buffer — no owned
            // `String`/`Span` copy (an owned copy would not be scrubbed when the
            // `Line` drops, breaking sole-owner containment).
            lines.push(Line::from(Span::styled(
                plaintext.as_str(),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "press any key to hide (auto-hides in 30s)",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "reveal cleared",
                Style::default().fg(Color::DarkGray),
            )));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

/// Drop-on-close zeroization: even if the overlay is dropped without an explicit
/// dismiss, the plaintext is scrubbed (`Zeroizing` handles the bytes).
impl Drop for SealedRevealOverlay {
    fn drop(&mut self) {
        self.reveal.zeroize();
    }
}

/// The `/sealed` overlay: a no-echo write frame or an ephemeral recover reveal.
pub(crate) enum SealedOverlay {
    Write(SealedWriteOverlay),
    Reveal(SealedRevealOverlay),
}

/// The outcome of routing a key/pointer to the overlay.
pub(crate) enum SealedOverlayOutcome {
    /// Stay open.
    Stay,
    /// Cancel a pending write: spend and drop the minted capability, then close.
    Cancel { capability_id: String },
    /// Apply a pending write with the collected literal, then close.
    Apply {
        capability_id: String,
        literal: SensitiveWireLiteral,
    },
    /// Close a recover reveal (already zeroized).
    Close,
}

impl SealedOverlay {
    /// A write overlay owns a daemon-minted capability until apply/cancel has
    /// produced an exact terminal receipt. It must survive an attempted exit.
    pub(crate) fn has_unsettled_local_authority(&self) -> bool {
        matches!(self, SealedOverlay::Write(_))
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> SealedOverlayOutcome {
        match self {
            SealedOverlay::Write(overlay) => overlay.handle_key(key),
            SealedOverlay::Reveal(overlay) => overlay.handle_key(key),
        }
    }

    pub fn pointer_dismiss(&mut self) -> SealedOverlayOutcome {
        match self {
            SealedOverlay::Write(overlay) => overlay.pointer_dismiss(),
            SealedOverlay::Reveal(overlay) => overlay.pointer_dismiss(),
        }
    }

    /// A SAFE past-tense summary of a write overlay (disposition + label, never
    /// a literal) for the success transcript line. `None` for a recover reveal.
    pub fn write_done_summary(&self) -> Option<String> {
        match self {
            SealedOverlay::Write(overlay) => Some(format!(
                "{} `{}`",
                overlay.disposition().done_verb(),
                overlay.label()
            )),
            SealedOverlay::Reveal(_) => None,
        }
    }

    /// Exit/interrupt teardown: if a WRITE is pending, zeroize its typed buffer
    /// and return the capability id to cancel over the attached binding before
    /// shutdown. A recover reveal has no live capability (it was spent by the
    /// apply); its buffer is zeroized on drop, so this returns `None`.
    pub fn take_pending_write_capability(&mut self) -> Option<String> {
        match self {
            SealedOverlay::Write(overlay) => Some(overlay.take_capability_for_teardown()),
            SealedOverlay::Reveal(_) => None,
        }
    }

    /// Whether a recover reveal is currently painting plaintext (keeps the
    /// 100ms tick alive so the TTL fires on an idle overlay).
    pub fn reveal_active(&self) -> bool {
        matches!(self, SealedOverlay::Reveal(overlay) if overlay.reveal_buffer().is_active())
    }

    /// Service the recover reveal TTL; returns whether it just expired.
    pub fn tick(&mut self) -> bool {
        match self {
            SealedOverlay::Reveal(overlay) => overlay.tick(),
            SealedOverlay::Write(_) => false,
        }
    }

    /// Take the "force a full clear" flag from a recover reveal.
    pub fn take_pending_clear(&mut self) -> bool {
        match self {
            SealedOverlay::Reveal(overlay) => overlay.take_pending_clear(),
            SealedOverlay::Write(_) => false,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        match self {
            SealedOverlay::Write(overlay) => overlay.render(frame, area),
            SealedOverlay::Reveal(overlay) => overlay.render(frame, area),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_core::sealed::identity::SealedRecordId;
    use cockpit_core::sealed::owner_commands::parse_sealed_command;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn ctx() -> SealedScopeContext {
        SealedScopeContext {
            session_id: "11111111-1111-1111-1111-111111111111".to_string(),
            project_key: "proj-key".to_string(),
        }
    }

    #[test]
    fn sealed_input_buffer_never_reallocates_on_push() {
        // The buffer must be pre-sized to the frame ceiling so per-keystroke
        // pushes never reallocate — a realloc would free an un-zeroized copy of
        // the partial secret, stranding plaintext in freed heap.
        let mut buf = SealedInputBuffer::new();
        let cap = buf.value.capacity();
        assert!(
            cap >= MAX_SENSITIVE_FRAME_BYTES,
            "buffer must reserve the frame ceiling up front"
        );
        for _ in 0..MAX_SENSITIVE_FRAME_BYTES {
            buf.push('x');
        }
        assert_eq!(buf.value.len(), MAX_SENSITIVE_FRAME_BYTES);
        assert_eq!(
            buf.value.capacity(),
            cap,
            "push must not reallocate (would strand plaintext in freed heap)"
        );
        // `clear` and `take` also restore a pre-sized buffer for reuse.
        buf.clear();
        assert!(buf.value.capacity() >= MAX_SENSITIVE_FRAME_BYTES);
        buf.push('y');
        let _ = buf.take();
        assert!(buf.value.capacity() >= MAX_SENSITIVE_FRAME_BYTES);
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn type_str(overlay: &mut SealedWriteOverlay, s: &str) {
        for c in s.chars() {
            overlay.handle_key(press(KeyCode::Char(c)));
        }
    }

    fn render_write(overlay: &SealedWriteOverlay) -> String {
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| overlay.render(frame, Rect::new(0, 0, 80, 12)))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..12)
            .map(|y| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn render_reveal(overlay: &mut SealedRevealOverlay) -> String {
        let backend = TestBackend::new(80, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| overlay.render(frame, Rect::new(0, 0, 80, 8)))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..8)
            .map(|y| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// AC1 (`tui_sealed_uses_owner_begin_apply`): a write command is routed to a
    /// `BeginSealedOwnerOperation` (NOT the legacy `ListSealedValues`), and the
    /// capability minted by begin is threaded verbatim into the
    /// `ApplySealedOwnerOperation`, which carries the typed literal. Distinguishing
    /// input: `rotate` (a write) — a broken frontend that dropped the literal or
    /// re-derived a fresh capability id would fail both assertions.
    #[test]
    fn tui_sealed_uses_owner_begin_apply() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["rotate", &id.to_string()]).unwrap();
        let plan = match plan_dispatch(&cmd, &ctx()) {
            SealedDispatch::Write(plan) => plan,
            other => panic!("rotate must route to a no-echo write, got {other:?}"),
        };
        match &plan.begin {
            Request::BeginSealedOwnerOperation {
                disposition,
                record_id,
                name,
                scope_kind,
                ..
            } => {
                assert_eq!(disposition, "rotate");
                assert_eq!(record_id.as_deref(), Some(id.to_string().as_str()));
                assert!(name.is_none(), "rotate begin carries only a record id");
                assert!(scope_kind.is_none());
            }
            other => panic!("expected a begin request, got {other:?}"),
        }
        assert_eq!(plan.disposition, SealedWriteDisposition::Rotate);

        // The daemon's begin mints this capability; the overlay must thread it
        // into apply unchanged.
        let mut overlay = SealedWriteOverlay::new(
            "cap-abc".to_string(),
            42,
            plan.disposition,
            plan.label.clone(),
        );
        type_str(&mut overlay, "hunter2");
        let outcome = overlay.handle_key(press(KeyCode::Enter));
        let (capability_id, literal) = match outcome {
            SealedOverlayOutcome::Apply {
                capability_id,
                literal,
            } => (capability_id, literal),
            _ => panic!("Enter on a filled no-echo frame must apply"),
        };
        assert_eq!(
            capability_id, "cap-abc",
            "capability threaded begin -> apply"
        );
        let apply = apply_write_request(&capability_id, literal);
        match apply {
            Request::ApplySealedOwnerOperation {
                capability_id,
                literal,
            } => {
                assert_eq!(capability_id, "cap-abc");
                let literal = literal.expect("a write apply carries the literal");
                assert_eq!(literal.as_str(), "hunter2", "the typed literal rides apply");
            }
            other => panic!("expected an apply request, got {other:?}"),
        }
    }

    /// AC1 (create arm): create routes to a begin whose scope key comes from the
    /// live context (session id / project key / empty for global), never a vault
    /// read. Distinguishing input: project scope must carry the canonical project
    /// key, not the session id.
    #[test]
    fn tui_sealed_create_begin_carries_scope_key() {
        let cmd = parse_sealed_command(&[
            "create",
            "deploy_token",
            "--scope",
            "project",
            "--description",
            "Deploy token",
        ])
        .unwrap();
        let plan = match plan_dispatch(&cmd, &ctx()) {
            SealedDispatch::Write(plan) => plan,
            other => panic!("create must route to a write, got {other:?}"),
        };
        match plan.begin {
            Request::BeginSealedOwnerOperation {
                disposition,
                name,
                description,
                scope_kind,
                scope_key,
                record_id,
            } => {
                assert_eq!(disposition, "create");
                assert_eq!(name.as_deref(), Some("deploy_token"));
                assert_eq!(description.as_deref(), Some("Deploy token"));
                assert_eq!(scope_kind.as_deref(), Some("project"));
                assert_eq!(
                    scope_key.as_deref(),
                    Some("proj-key"),
                    "project scope must carry the canonical project key"
                );
                assert!(record_id.is_none());
            }
            other => panic!("expected a create begin, got {other:?}"),
        }
    }

    /// AC2 (`tui_sealed_never_renders_plaintext_on_inventory`): the inventory list
    /// path renders only safe metadata, and its response matcher CANNOT surface a
    /// revealed literal. Distinguishing input: feed the ONLY literal-bearing
    /// response (`SealedOwnerOperationApplied` with a planted secret) to the
    /// inventory text path and assert the secret never appears.
    #[test]
    fn tui_sealed_never_renders_plaintext_on_inventory() {
        let items = vec![SealedOwnerInventoryItem {
            record_id: "rec-1".to_string(),
            name: "deploy_token".to_string(),
            description: "Deploy token".to_string(),
            scope_kind: SealedOwnerScopeKind::Project,
            scope_key: "proj-key".to_string(),
            active_version: 3,
            created_at_ms: 1_000,
        }];
        let rendered = sealed_response_text(Ok(Response::SealedOwnerInventory { items }));
        assert!(
            rendered.contains("rec-1"),
            "renders safe metadata: {rendered}"
        );
        assert!(rendered.contains("deploy_token"));
        assert!(rendered.contains("project"));

        // Precondition: this response really carries the secret.
        const SENTINEL: &str = "SENTINEL_LITERAL_XYZ";
        let applied = Response::SealedOwnerOperationApplied {
            revealed_literal: Some(SensitiveWireLiteral::new(SENTINEL.to_string())),
        };
        if let Response::SealedOwnerOperationApplied {
            revealed_literal: Some(lit),
        } = &applied
        {
            assert_eq!(lit.as_str(), SENTINEL, "precondition: secret is present");
        } else {
            panic!("precondition setup failed");
        }
        // The inventory/metadata text path must reject it as unexpected, never
        // rendering the literal.
        let rendered = sealed_response_text(Ok(applied));
        assert!(
            !rendered.contains(SENTINEL),
            "a literal-bearing response must never surface a literal: {rendered}"
        );
        assert_eq!(rendered, "/sealed: unexpected daemon response");
    }

    /// AC3 (`cancel_on_dismiss_drops_capability`): BOTH a keyboard dismiss (Esc)
    /// and a pointer dismiss yield `Cancel` carrying the exact minted capability,
    /// and both zeroize the typed buffer. Distinguishing control: a printable
    /// character must NOT cancel.
    #[test]
    fn cancel_on_dismiss_drops_capability() {
        // Keyboard dismiss.
        let mut overlay = SealedWriteOverlay::new(
            "cap-1".to_string(),
            0,
            SealedWriteDisposition::Replace,
            "rec".into(),
        );
        type_str(&mut overlay, "secret");
        // Positive control: typing does not cancel.
        assert!(matches!(
            overlay.handle_key(press(KeyCode::Char('x'))),
            SealedOverlayOutcome::Stay
        ));
        match overlay.handle_key(press(KeyCode::Esc)) {
            SealedOverlayOutcome::Cancel { capability_id } => assert_eq!(capability_id, "cap-1"),
            _ => panic!("Esc must cancel"),
        }
        assert!(
            overlay.input.is_empty(),
            "keyboard dismiss zeroizes the buffer"
        );

        // Pointer/mouse dismiss.
        let mut overlay = SealedWriteOverlay::new(
            "cap-1".to_string(),
            0,
            SealedWriteDisposition::Replace,
            "rec".into(),
        );
        type_str(&mut overlay, "secret");
        match overlay.pointer_dismiss() {
            SealedOverlayOutcome::Cancel { capability_id } => assert_eq!(capability_id, "cap-1"),
            _ => panic!("pointer dismiss must cancel"),
        }
        assert!(
            overlay.input.is_empty(),
            "pointer dismiss zeroizes the buffer"
        );
    }

    /// AC5 (`create_rotate_replace_are_no_echo`): a planted literal typed into a
    /// write overlay is NEVER painted (only a bullet mask), yet it IS captured
    /// (precondition) and rides only the apply frame. Distinguishing: a broken
    /// echo implementation would render the sentinel characters.
    #[test]
    fn create_rotate_replace_are_no_echo() {
        const SENTINEL: &str = "PLAINTEXT_NEVER_SHOWN";
        let mut overlay = SealedWriteOverlay::new(
            "cap-9".to_string(),
            0,
            SealedWriteDisposition::Create,
            "deploy_token".into(),
        );
        type_str(&mut overlay, SENTINEL);
        // Precondition: the buffer really holds the literal (not silently dropped).
        assert_eq!(overlay.input.char_count(), SENTINEL.chars().count());

        let rendered = render_write(&overlay);
        assert!(
            !rendered.contains(SENTINEL),
            "the literal must never be echoed to the screen: {rendered}"
        );
        assert!(rendered.contains('•'), "the field is masked: {rendered}");
        // The safe label/disposition is still shown.
        assert!(rendered.contains("deploy_token"));
        // Redacted Debug never leaks the literal either.
        assert!(!format!("{:?}", overlay.input).contains(SENTINEL));

        // The literal surfaces ONLY inside the apply frame's zeroizing wire type.
        match overlay.handle_key(press(KeyCode::Enter)) {
            SealedOverlayOutcome::Apply { literal, .. } => {
                assert_eq!(literal.as_str(), SENTINEL);
            }
            _ => panic!("Enter must apply"),
        }
    }

    /// AC5 (empty guard): Enter on an empty no-echo frame does not apply an empty
    /// literal; it stays open with an error.
    #[test]
    fn empty_no_echo_frame_rejects_apply() {
        let mut overlay = SealedWriteOverlay::new(
            "cap".into(),
            0,
            SealedWriteDisposition::Rotate,
            "rec".into(),
        );
        assert!(matches!(
            overlay.handle_key(press(KeyCode::Enter)),
            SealedOverlayOutcome::Stay
        ));
    }

    /// AC6 (`recover_plaintext_only_in_overlay`): the recover plaintext is painted
    /// only inside the reveal overlay and is cleared (zeroized) when the overlay is
    /// dismissed. Distinguishing: the sentinel is present in the active render and
    /// absent after dismissal.
    #[test]
    fn recover_plaintext_only_in_overlay() {
        const SENTINEL: &str = "RECOVERED_SECRET_42";
        let mut overlay =
            SealedRevealOverlay::new("rec-1".into(), Zeroizing::new(SENTINEL.to_string()));
        // Precondition: the reveal is active and the render shows the plaintext.
        assert!(overlay.reveal_buffer().is_active());
        let shown = render_reveal(&mut overlay);
        assert!(
            shown.contains(SENTINEL),
            "the reveal overlay is the only place the plaintext is painted: {shown}"
        );

        // Dismiss (keyboard): zeroize + close, and flag a full clear.
        assert!(matches!(
            overlay.handle_key(press(KeyCode::Char('q'))),
            SealedOverlayOutcome::Close
        ));
        assert!(
            !overlay.reveal_buffer().is_active(),
            "dismiss zeroizes the reveal"
        );
        assert!(overlay.take_pending_clear(), "dismiss flags a full clear");
        let after = render_reveal(&mut overlay);
        assert!(
            !after.contains(SENTINEL),
            "after dismiss the plaintext is gone: {after}"
        );
        // Redacted Debug never leaks the plaintext.
        assert!(!format!("{:?}", overlay.reveal_buffer()).contains(SENTINEL));
    }

    /// AC6 (TTL): the 30s TTL (injected clock) zeroizes the reveal and flags a
    /// clear even on an idle overlay that never re-renders.
    #[test]
    fn recover_reveal_ttl_expiry_flags_clear() {
        let mut overlay =
            SealedRevealOverlay::new("rec".into(), Zeroizing::new("secret".to_string()));
        let base = Instant::now();
        assert!(!overlay.tick_at(base + Duration::from_secs(29)));
        assert!(overlay.reveal_buffer().is_active());
        assert!(overlay.tick_at(base + Duration::from_secs(30)));
        assert!(
            !overlay.reveal_buffer().is_active(),
            "TTL zeroizes the reveal"
        );
        assert!(overlay.take_pending_clear(), "TTL flags a full clear");
        assert!(!overlay.take_pending_clear(), "the clear flag is one-shot");
    }

    /// SECURITY (parse-failure redaction): the raw parser echoes the rejected
    /// token verbatim, so a mistyped secret (`/sealed <SECRET>`) would land in
    /// scrollback/history. The frontend funnel maps EVERY parse failure to a
    /// fixed, content-free message. Distinguishing inputs: an unknown subcommand
    /// (the token is the whole secret) AND an unknown flag (the token is a flag),
    /// each with a planted sentinel. Precondition: the raw parser error really
    /// does contain the sentinel, so the test can't pass because it was never there.
    #[test]
    fn parse_failures_never_echo_the_typed_token() {
        const SECRET: &str = "SUPER_SECRET_TOKEN_9000";

        // Unknown subcommand: `/sealed <SECRET>`.
        let raw = parse_sealed_command(&[SECRET]).unwrap_err().to_string();
        assert!(
            raw.contains(SECRET),
            "precondition: the raw parser error echoes the token: {raw}"
        );
        let safe = parse_sealed_tokens(&[SECRET]).unwrap_err();
        assert!(
            !safe.contains(SECRET),
            "the frontend message must be content-free: {safe}"
        );
        assert_eq!(safe, SEALED_PARSE_ERROR);

        // Unknown flag on a valid subcommand: `/sealed list <SECRET>`.
        let raw = parse_sealed_command(&["list", SECRET])
            .unwrap_err()
            .to_string();
        assert!(
            raw.contains(SECRET),
            "precondition: the raw parser error echoes the flag token: {raw}"
        );
        let safe = parse_sealed_tokens(&["list", SECRET]).unwrap_err();
        assert!(
            !safe.contains(SECRET),
            "the frontend message must be content-free: {safe}"
        );
    }

    /// Exit/interrupt teardown: a pending WRITE surrenders its capability id (for
    /// a best-effort cancel) AND zeroizes its typed buffer; a recover reveal has
    /// no capability to cancel. Distinguishing: the buffer really held a value
    /// (precondition) and is empty afterward, and the reveal arm returns `None`.
    #[test]
    fn teardown_cancels_pending_write_and_zeroizes() {
        let mut write = SealedOverlay::Write(SealedWriteOverlay::new(
            "cap-teardown".to_string(),
            0,
            SealedWriteDisposition::Rotate,
            "rec".into(),
        ));
        if let SealedOverlay::Write(overlay) = &mut write {
            type_str(overlay, "half-typed-secret");
            assert!(
                !overlay.input.is_empty(),
                "precondition: buffer holds a value"
            );
        }
        let capability = write.take_pending_write_capability();
        assert_eq!(capability.as_deref(), Some("cap-teardown"));
        if let SealedOverlay::Write(overlay) = &write {
            assert!(
                overlay.input.is_empty(),
                "teardown zeroizes the typed buffer"
            );
        }

        // A recover reveal has no live capability to cancel.
        let mut reveal = SealedOverlay::Reveal(SealedRevealOverlay::new(
            "rec".into(),
            Zeroizing::new("secret".to_string()),
        ));
        assert!(reveal.take_pending_write_capability().is_none());
    }

    /// Delete has no landed owner RPC: it fails closed with a message rather than
    /// inventing a wire tag.
    #[test]
    fn delete_is_unsupported_fail_closed() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["delete", &id.to_string(), "--confirm", &id.to_string()])
            .unwrap();
        match plan_dispatch(&cmd, &ctx()) {
            SealedDispatch::Unsupported(msg) => assert!(msg.contains("delete")),
            other => panic!("delete must be unsupported, got {other:?}"),
        }
    }

    /// The metadata commands map to their owner RPCs (not the write/recover flow).
    #[test]
    fn metadata_commands_map_to_owner_rpcs() {
        assert!(matches!(
            plan_dispatch(&parse_sealed_command(&[]).unwrap(), &ctx()),
            SealedDispatch::Metadata(Request::SealedOwnerInventory { .. })
        ));
        assert!(matches!(
            plan_dispatch(&parse_sealed_command(&["action", "list"]).unwrap(), &ctx()),
            SealedDispatch::Metadata(Request::ListSealedActions)
        ));
        let id = SealedRecordId::generate();
        assert!(matches!(
            plan_dispatch(
                &parse_sealed_command(&["edit", &id.to_string(), "--description", "d"]).unwrap(),
                &ctx()
            ),
            SealedDispatch::Metadata(Request::EditSealedOwnerDescription { .. })
        ));
        assert!(matches!(
            plan_dispatch(
                &parse_sealed_command(&["recover", &id.to_string()]).unwrap(),
                &ctx()
            ),
            SealedDispatch::Recover { .. }
        ));
    }

    #[test]
    fn session_controls_map_to_literal_free_owner_begin_requests() {
        let id = SealedRecordId::generate();
        let reset = parse_sealed_command(&["reset", &id.to_string(), "--confirm", &id.to_string()])
            .unwrap();
        match plan_dispatch(&reset, &ctx()) {
            SealedDispatch::Control(plan) => assert!(matches!(
                plan.begin,
                Request::BeginSealedOwnerOperation {
                    ref disposition,
                    record_id: Some(_),
                    name: None,
                    description: None,
                    scope_kind: None,
                    scope_key: None,
                } if disposition == "reset"
            )),
            other => panic!("reset must be a control operation, got {other:?}"),
        }

        let promote =
            parse_sealed_command(&["promote", &id.to_string(), "--scope", "project"]).unwrap();
        match plan_dispatch(&promote, &ctx()) {
            SealedDispatch::Control(plan) => assert!(matches!(
                plan.begin,
                Request::BeginSealedOwnerOperation {
                    ref disposition,
                    record_id: Some(_),
                    name: None,
                    description: None,
                    scope_kind: Some(ref scope_kind),
                    scope_key: Some(ref scope_key),
                } if disposition == "promote" && scope_kind == "project" && scope_key == "project-a"
            )),
            other => panic!("promote must be a control operation, got {other:?}"),
        }
    }
}
