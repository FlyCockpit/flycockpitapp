//! Secure-store choice screen for the onboarding shell.
//!
//! Ported from the former `Dialog::OnboardingSecureStore` modal: the choice
//! of encrypted vault placement (platform keyring, passphrase-protected
//! file, machine-bound file) plus the zeroizing passphrase ingress with
//! confirmation. The screen only produces a redacted
//! [`SecureStoreSubmission`]; the daemon owns vault materialization.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph};

use crate::tui::theme::{BAD, BRASS, DISABLED, FOG, INK, NIGHT, PLACEHOLDER};

/// The sensitive ingress rejects passphrases past this byte length; enforce
/// the same cap *before* buffering so an oversized paste is rejected at
/// ingress instead of after unbounded allocation and comparison.
const MAX_PASSPHRASE_BYTES: usize = cockpit_proto::MAX_SENSITIVE_ONBOARDING_PASSPHRASE_BYTES;

pub struct SecureStoreSubmission {
    pub placement: cockpit_proto::OnboardingSecurePlacement,
    pub passphrase: Option<cockpit_proto::SensitiveOnboardingPassphrase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecureStoreInputPhase {
    Choice,
    Passphrase,
    Confirmation,
}

pub(crate) struct SecureStoreScreen {
    pub(crate) capabilities: cockpit_proto::HostCapabilitySnapshot,
    pub(crate) cursor: usize,
    pub(crate) phase: SecureStoreInputPhase,
    passphrase: zeroize::Zeroizing<String>,
    confirmation: zeroize::Zeroizing<String>,
    pub(crate) submitted: Option<SecureStoreSubmission>,
    pub(crate) status: Option<String>,
    /// Neutral progress of an in-flight submission (set by the app each
    /// frame). A validation `status` takes precedence over it.
    pub(crate) progress: Option<String>,
    revealed: bool,
    password_rect: Rect,
    confirmation_rect: Rect,
}

impl SecureStoreScreen {
    pub(crate) fn new(capabilities: cockpit_proto::HostCapabilitySnapshot) -> Self {
        let mut screen = Self {
            capabilities,
            cursor: 0,
            phase: SecureStoreInputPhase::Choice,
            passphrase: zeroize::Zeroizing::new(String::new()),
            confirmation: zeroize::Zeroizing::new(String::new()),
            submitted: None,
            status: None,
            progress: None,
            revealed: false,
            password_rect: Rect::default(),
            confirmation_rect: Rect::default(),
        };
        if !screen.row_enabled(screen.cursor) {
            screen.move_choice(1);
        }
        screen
    }

    pub(crate) fn set_capabilities(&mut self, capabilities: cockpit_proto::HostCapabilitySnapshot) {
        self.capabilities = capabilities;
        if self.phase == SecureStoreInputPhase::Choice && !self.row_enabled(self.cursor) {
            self.move_choice(1);
        }
    }

    /// The daemon publishes the locked bootstrap before its host probes
    /// settle; until then the snapshot is the probing placeholder
    /// (generation 0, no rows). Every placement is shown as still being
    /// checked rather than unavailable, and none can be chosen yet.
    pub(crate) fn probing(&self) -> bool {
        self.capabilities.generation == 0 && self.capabilities.features.is_empty()
    }

    pub(crate) fn take_submission(&mut self) -> Option<SecureStoreSubmission> {
        self.submitted.take()
    }

    /// Append `text` to the focused passphrase buffer, rejecting the whole
    /// append when it would cross the ingress byte cap (no silent
    /// truncation of secret material).
    fn append_to_focused(&mut self, text: &str) {
        let target = match self.phase {
            SecureStoreInputPhase::Passphrase => &mut self.passphrase,
            SecureStoreInputPhase::Confirmation => &mut self.confirmation,
            SecureStoreInputPhase::Choice => return,
        };
        if target.len().saturating_add(text.len()) > MAX_PASSPHRASE_BYTES {
            self.status =
                Some("Passphrase exceeds the maximum accepted length; input was rejected.".into());
            return;
        }
        target.push_str(text);
    }

    /// Paste into whichever passphrase field is focused (no-op on the
    /// choice list).
    pub(crate) fn paste(&mut self, text: &str) {
        self.append_to_focused(text);
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        match self.phase {
            SecureStoreInputPhase::Choice => match key.code {
                KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                    self.move_choice(-1);
                    self.status = None;
                }
                KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
                    self.move_choice(1);
                    self.status = None;
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.confirm_selection(self.cursor),
                _ => {}
            },
            SecureStoreInputPhase::Passphrase | SecureStoreInputPhase::Confirmation => {
                match key.code {
                    KeyCode::Esc => {
                        self.passphrase.clear();
                        self.confirmation.clear();
                        self.phase = SecureStoreInputPhase::Choice;
                        self.status = None;
                    }
                    KeyCode::Backspace => {
                        let target = if self.phase == SecureStoreInputPhase::Passphrase {
                            &mut self.passphrase
                        } else {
                            &mut self.confirmation
                        };
                        target.pop();
                    }
                    KeyCode::Tab | KeyCode::BackTab => {
                        self.phase = if self.phase == SecureStoreInputPhase::Passphrase {
                            SecureStoreInputPhase::Confirmation
                        } else {
                            SecureStoreInputPhase::Passphrase
                        };
                    }
                    KeyCode::Char('r' | 'R') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.revealed = !self.revealed;
                    }
                    KeyCode::Char(ch) => {
                        let ch = crate::tui::textfield::normalize_shift_char(&key, ch);
                        let mut encoded = [0u8; 4];
                        self.append_to_focused(ch.encode_utf8(&mut encoded));
                    }
                    KeyCode::Enter if self.phase == SecureStoreInputPhase::Passphrase => {
                        if self.passphrase.is_empty() {
                            self.status = Some("Passphrase must not be empty.".into());
                        } else {
                            self.phase = SecureStoreInputPhase::Confirmation;
                            self.status = None;
                        }
                    }
                    KeyCode::Enter => {
                        let value = std::mem::take(&mut *self.passphrase);
                        let confirmation = std::mem::take(&mut *self.confirmation);
                        match cockpit_proto::SensitiveOnboardingPassphrase::confirmed(
                            value,
                            confirmation,
                        ) {
                            Ok(passphrase) => {
                                self.submitted = Some(SecureStoreSubmission {
                                    placement:
                                        cockpit_proto::OnboardingSecurePlacement::PassphraseFile,
                                    passphrase: Some(passphrase),
                                });
                                self.status = None;
                            }
                            Err(error) => {
                                self.status = Some(error.into());
                                self.phase = SecureStoreInputPhase::Passphrase;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) fn move_choice(&mut self, delta: isize) {
        let mut next = self.cursor;
        for _ in 0..3 {
            next = if delta < 0 {
                crate::tui::nav::wrap_prev(next, 3)
            } else {
                crate::tui::nav::wrap_next(next, 3)
            };
            if self.row_enabled(next) {
                self.cursor = next;
                return;
            }
        }
    }

    /// Pointer selection of a placement row or focus of a password field.
    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent, row_rects: &[Rect]) {
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return;
        }
        if self.phase != SecureStoreInputPhase::Choice {
            let pos = (mouse.column, mouse.row).into();
            if self.password_rect.contains(pos) {
                self.phase = SecureStoreInputPhase::Passphrase;
            } else if self.confirmation_rect.contains(pos) {
                self.phase = SecureStoreInputPhase::Confirmation;
            }
            return;
        }
        let Some(index) = row_rects
            .iter()
            .position(|rect| rect.contains((mouse.column, mouse.row).into()))
        else {
            return;
        };
        if !self.row_enabled(index) {
            return;
        }
        if self.cursor == index {
            self.confirm_selection(index);
        } else {
            self.cursor = index;
            self.status = None;
        }
    }

    pub(crate) fn confirm_focused(&mut self) {
        match self.phase {
            SecureStoreInputPhase::Choice => self.confirm_selection(self.cursor),
            SecureStoreInputPhase::Passphrase | SecureStoreInputPhase::Confirmation => {
                self.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            }
        }
    }

    /// The placement and gating capability of a choice row.
    fn row_choice(index: usize) -> (cockpit_proto::OnboardingSecurePlacement, &'static str) {
        match index {
            0 => (
                cockpit_proto::OnboardingSecurePlacement::Automatic,
                "secret_store.keyring",
            ),
            1 => (
                cockpit_proto::OnboardingSecurePlacement::PassphraseFile,
                "secret_store.file",
            ),
            _ => (
                cockpit_proto::OnboardingSecurePlacement::MachineBoundFile,
                "secret_store.file",
            ),
        }
    }

    /// Placement under the cursor while choosing (test observation seam).
    #[cfg(test)]
    pub(crate) fn cursor_placement(&self) -> Option<cockpit_proto::OnboardingSecurePlacement> {
        (self.phase == SecureStoreInputPhase::Choice).then(|| Self::row_choice(self.cursor).0)
    }

    fn confirm_selection(&mut self, cursor: usize) {
        let (placement, capability_id) = Self::row_choice(cursor);
        let Some(capability) = self.capabilities.feature(capability_id) else {
            return;
        };
        if !capability.state.is_available() {
            return;
        }
        if placement == cockpit_proto::OnboardingSecurePlacement::PassphraseFile {
            self.phase = SecureStoreInputPhase::Passphrase;
        } else {
            self.submitted = Some(SecureStoreSubmission {
                placement,
                passphrase: None,
            });
        }
    }

    pub(crate) fn toggle_reveal(&mut self) {
        self.revealed = !self.revealed;
    }

    pub(crate) fn row_enabled(&self, index: usize) -> bool {
        let id = if index == 0 {
            "secret_store.keyring"
        } else {
            "secret_store.file"
        };
        self.capabilities
            .feature(id)
            .is_some_and(|capability| capability.state.is_available())
    }

    fn recommended_choice(&self) -> usize {
        (0..3).find(|index| self.row_enabled(*index)).unwrap_or(0)
    }

    pub(crate) fn detail_lines(&self) -> Vec<Line<'static>> {
        let descriptions = [
            "Use the operating system credential vault. No silent file fallback.",
            "Encrypt credentials with a password you enter after a pre-commit crash.",
            "Use an encrypted credential file tied to this machine.",
        ];
        let mut lines = vec![Line::from(Span::styled(
            descriptions[self.cursor],
            Style::new().fg(FOG),
        ))];
        if self.probing() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Checking what this machine supports…",
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            )));
            return lines;
        }
        if !self.row_enabled(self.cursor) {
            let id = if self.cursor == 0 {
                "secret_store.keyring"
            } else {
                "secret_store.file"
            };
            if let Some(capability) = self.capabilities.feature(id) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    format!("Unavailable: {}", capability.reason),
                    Style::new().fg(DISABLED),
                )));
                if let Some(remedy) = capability
                    .fix_command
                    .as_deref()
                    .or(capability.remedy_text.as_deref())
                {
                    lines.push(Line::from(Span::styled(
                        format!("Fix: {remedy}"),
                        Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                    )));
                }
            }
        }
        lines
    }

    pub(crate) fn lines(&self) -> Vec<Line<'static>> {
        let selected = Style::default().fg(BRASS).add_modifier(Modifier::BOLD);
        let mut lines = Vec::new();
        match self.phase {
            SecureStoreInputPhase::Choice => {
                let choices = [
                    ("Platform keyring", "recommended"),
                    ("Passphrase-protected file", "works without a keyring"),
                    ("Machine-bound encrypted file", "tied to this machine"),
                ];
                let probing = self.probing();
                for (index, (title, available_tagline)) in choices.into_iter().enumerate() {
                    let enabled = self.row_enabled(index);
                    let recommended = enabled && index == self.recommended_choice();
                    let selected_row = self.cursor == index;
                    let row_style = if !enabled {
                        Style::default().fg(DISABLED)
                    } else if selected_row {
                        selected
                    } else {
                        Style::default().fg(INK)
                    };
                    let tag_style = if probing {
                        Style::default().fg(FOG).add_modifier(Modifier::ITALIC)
                    } else if !enabled {
                        Style::default().fg(DISABLED).add_modifier(Modifier::ITALIC)
                    } else if recommended {
                        Style::default().fg(BRASS).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(FOG)
                    };
                    lines.push(Line::from(vec![
                        Span::styled(if selected_row { "◉ " } else { "○ " }, row_style),
                        Span::styled(title, row_style),
                        Span::styled("  —  ", Style::default().fg(NIGHT)),
                        Span::styled(
                            if probing {
                                "checking…"
                            } else if enabled {
                                if recommended {
                                    "recommended"
                                } else {
                                    available_tagline
                                }
                            } else {
                                "unavailable"
                            },
                            tag_style,
                        ),
                    ]));
                }
            }
            SecureStoreInputPhase::Passphrase | SecureStoreInputPhase::Confirmation => {
                // Password fields are rendered as bordered controls by
                // `render_password`; only choice rows use this projection.
            }
        }
        if let Some(status) = self.status.as_deref() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.to_string(), BAD)));
        } else if let Some(progress) = self.progress.as_deref() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                progress.to_string(),
                Style::default().fg(FOG).add_modifier(Modifier::ITALIC),
            )));
        }
        lines
    }

    pub(crate) fn render_password(&mut self, frame: &mut Frame, area: Rect) {
        let rows = ratatui::layout::Layout::vertical([
            ratatui::layout::Constraint::Length(3),
            ratatui::layout::Constraint::Length(3),
            ratatui::layout::Constraint::Length(2),
            ratatui::layout::Constraint::Min(0),
        ])
        .split(area);
        self.password_rect = rows[0];
        self.confirmation_rect = rows[1];
        let password_cursor = self.render_password_field(
            frame,
            rows[0],
            "Password",
            &self.passphrase,
            self.phase == SecureStoreInputPhase::Passphrase,
        );
        let confirmation_cursor = self.render_password_field(
            frame,
            rows[1],
            "Confirm",
            &self.confirmation,
            self.phase == SecureStoreInputPhase::Confirmation,
        );
        let note = self
            .status
            .as_deref()
            .or(self.progress.as_deref())
            .unwrap_or("This password isn't recoverable — losing it means re-adding every secret.");
        let style = if self.status.is_some() {
            Style::new().fg(BAD).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(FOG).add_modifier(Modifier::ITALIC)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(note.to_string(), style))),
            rows[2],
        );
        if let Some(cursor) = if self.phase == SecureStoreInputPhase::Passphrase {
            password_cursor
        } else {
            confirmation_cursor
        } {
            frame.set_cursor_position(cursor);
        }
    }

    fn render_password_field(
        &self,
        frame: &mut Frame,
        area: Rect,
        title: &str,
        value: &str,
        focused: bool,
    ) -> Option<Position> {
        let border = if focused { BRASS } else { NIGHT };
        let block = Block::bordered()
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::new().fg(border))
            .title(Span::styled(format!(" {title} "), Style::new().fg(border)))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let display = if value.is_empty() {
            Span::styled(
                "enter a password",
                Style::new().fg(PLACEHOLDER).add_modifier(Modifier::ITALIC),
            )
        } else if self.revealed {
            Span::styled(value.to_string(), Style::new().fg(INK))
        } else {
            Span::styled("•".repeat(value.chars().count()), Style::new().fg(INK))
        };
        frame.render_widget(Paragraph::new(Line::from(display)), inner);
        if !focused || inner.width == 0 || inner.height == 0 {
            return None;
        }
        let column = value
            .chars()
            .count()
            .min(usize::from(inner.width.saturating_sub(1)));
        Some(Position::new(inner.x + column as u16, inner.y))
    }

    pub(crate) fn return_to_choice(&mut self) {
        self.passphrase.clear();
        self.confirmation.clear();
        self.phase = SecureStoreInputPhase::Choice;
        self.status = None;
        self.revealed = false;
        self.password_rect = Rect::default();
        self.confirmation_rect = Rect::default();
    }

    pub(crate) fn help_text(&self) -> &'static str {
        match self.phase {
            SecureStoreInputPhase::Choice if self.probing() => {
                "checking secure storage on this machine…   esc quit"
            }
            SecureStoreInputPhase::Choice => "↑↓ move   click choose   enter choose   esc quit",
            SecureStoreInputPhase::Passphrase | SecureStoreInputPhase::Confirmation => {
                "type password   tab switch   ctrl-r reveal   enter save   esc back"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::{FeatureCapabilityRow, FeatureCapabilityState, OnboardingSecurePlacement};

    fn capabilities(keyring: FeatureCapabilityState) -> cockpit_proto::HostCapabilitySnapshot {
        let mut snapshot = cockpit_proto::HostCapabilitySnapshot::unpublished();
        snapshot.features = [
            ("secret_store.keyring", keyring),
            ("secret_store.file", FeatureCapabilityState::Available),
        ]
        .into_iter()
        .map(|(id, state)| FeatureCapabilityRow {
            id: id.into(),
            state,
            reason: "test".into(),
            fix_command: None,
            remedy_text: None,
            dependency_ids: Vec::new(),
        })
        .collect();
        snapshot
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// A headless host without a keyring: the cursor starts on the
    /// passphrase file, Enter there only opens passphrase entry (no RPC), and
    /// one Down reaches the machine-bound file, whose Enter submits.
    #[test]
    fn keyring_unavailable_defaults_to_passphrase_and_one_down_submits_machine_bound() {
        let mut screen = SecureStoreScreen::new(capabilities(FeatureCapabilityState::Missing));
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::PassphraseFile)
        );

        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(screen.phase, SecureStoreInputPhase::Passphrase);
        assert!(screen.take_submission().is_none());
        screen.handle_key(key(KeyCode::Esc));
        assert_eq!(screen.phase, SecureStoreInputPhase::Choice);

        screen.handle_key(key(KeyCode::Down));
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::MachineBoundFile)
        );
        // Wrapping skips the disabled keyring row.
        screen.handle_key(key(KeyCode::Down));
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::PassphraseFile)
        );
        screen.handle_key(key(KeyCode::Down));
        screen.handle_key(key(KeyCode::Enter));
        let submission = screen
            .take_submission()
            .expect("machine-bound Enter submits the intent");
        assert_eq!(
            submission.placement,
            OnboardingSecurePlacement::MachineBoundFile
        );
        assert!(submission.passphrase.is_none());
    }

    fn line_text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The locked daemon serves onboarding before its host probes settle:
    /// the probing placeholder renders every placement as being checked (not
    /// unavailable), accepts no choice, and the settled snapshot then enables
    /// the rows and lands the cursor on the recommended placement.
    #[test]
    fn probing_rows_render_as_checking_then_update_when_the_snapshot_settles() {
        let mut screen =
            SecureStoreScreen::new(cockpit_proto::HostCapabilitySnapshot::unpublished());
        assert!(screen.probing());
        let rows = line_text(&screen.lines());
        assert_eq!(rows.matches("checking…").count(), 3, "{rows}");
        assert!(!rows.contains("unavailable"), "{rows}");
        assert!(line_text(&screen.detail_lines()).contains("Checking what this machine supports"),);
        assert!((0..3).all(|index| !screen.row_enabled(index)));
        screen.handle_key(key(KeyCode::Enter));
        assert!(screen.take_submission().is_none());
        assert_eq!(screen.phase, SecureStoreInputPhase::Choice);

        let mut settled = capabilities(FeatureCapabilityState::Available);
        settled.generation = 1;
        screen.set_capabilities(settled);
        assert!(!screen.probing());
        let rows = line_text(&screen.lines());
        assert!(!rows.contains("checking…"), "{rows}");
        assert!(rows.contains("recommended"), "{rows}");
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::Automatic)
        );
        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(
            screen
                .take_submission()
                .map(|submission| submission.placement),
            Some(OnboardingSecurePlacement::Automatic)
        );
    }

    /// A settled snapshot without a keyring moves the cursor off the
    /// keyring row it was parked on while probing.
    #[test]
    fn settled_snapshot_without_keyring_moves_cursor_to_the_file_vault() {
        let mut screen =
            SecureStoreScreen::new(cockpit_proto::HostCapabilitySnapshot::unpublished());
        let mut settled = capabilities(FeatureCapabilityState::Missing);
        settled.generation = 1;
        screen.set_capabilities(settled);
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::PassphraseFile)
        );
        assert!(line_text(&screen.lines()).contains("unavailable"));
    }

    #[test]
    fn keyring_available_defaults_to_the_platform_keyring() {
        let screen = SecureStoreScreen::new(capabilities(FeatureCapabilityState::Available));
        assert_eq!(
            screen.cursor_placement(),
            Some(OnboardingSecurePlacement::Automatic)
        );
    }
}
