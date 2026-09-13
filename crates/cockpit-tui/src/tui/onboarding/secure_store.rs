//! Secure-store choice screen for the onboarding shell.
//!
//! Ported from the former `Dialog::OnboardingSecureStore` modal: the choice
//! of encrypted vault placement (platform keyring, passphrase-protected
//! file, machine-bound file) plus the zeroizing passphrase ingress with
//! confirmation. The screen only produces a redacted
//! [`SecureStoreSubmission`]; the daemon owns vault materialization.

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;

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
}

impl SecureStoreScreen {
    pub(crate) fn new(capabilities: cockpit_proto::HostCapabilitySnapshot) -> Self {
        Self {
            capabilities,
            cursor: 0,
            phase: SecureStoreInputPhase::Choice,
            passphrase: zeroize::Zeroizing::new(String::new()),
            confirmation: zeroize::Zeroizing::new(String::new()),
            submitted: None,
            status: None,
        }
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
                KeyCode::Up => {
                    self.cursor = self.cursor.saturating_sub(1);
                    self.status = None;
                }
                KeyCode::Down => {
                    self.cursor = (self.cursor + 1).min(2);
                    self.status = None;
                }
                KeyCode::Enter => self.confirm_selection(self.cursor),
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

    /// Pointer selection of a placement row (choice phase only).
    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent, row_rects: &[Rect]) {
        if self.phase != SecureStoreInputPhase::Choice {
            return;
        }
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return;
        }
        let Some(index) = row_rects
            .iter()
            .position(|rect| rect.contains((mouse.column, mouse.row).into()))
        else {
            return;
        };
        self.cursor = index;
        self.status = None;
        self.confirm_selection(index);
    }

    fn confirm_selection(&mut self, cursor: usize) {
        let (placement, capability_id) = match cursor {
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
        };
        let Some(capability) = self.capabilities.feature(capability_id) else {
            self.status = Some(
                "Secure-store capability is not ready; retry after the host check completes."
                    .into(),
            );
            return;
        };
        if !capability.state.is_available() {
            self.status = Some(
                capability
                    .fix_command
                    .as_deref()
                    .or(capability.remedy_text.as_deref())
                    .unwrap_or(capability.reason.as_str())
                    .to_string(),
            );
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

    pub(crate) fn lines(&self) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let selected = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let mut lines = vec![
            Line::from("Choose where Cockpit encrypts credentials before adding a provider."),
            Line::from(Span::styled(
                "Automatic means the platform keyring only; a failure requires a new explicit choice.",
                muted,
            )),
            Line::default(),
        ];
        match self.phase {
            SecureStoreInputPhase::Choice => {
                let choices = [
                    ("Platform keyring (recommended)", "No silent file fallback."),
                    (
                        "Passphrase-protected file",
                        "You must enter it again after a pre-commit crash.",
                    ),
                    (
                        "Machine-bound encrypted file",
                        "Explicit fallback tied to this machine.",
                    ),
                ];
                for (index, (label, description)) in choices.into_iter().enumerate() {
                    lines.push(Line::from(vec![
                        Span::raw(if self.cursor == index { "▸ " } else { "  " }),
                        Span::styled(
                            label,
                            if self.cursor == index {
                                selected
                            } else {
                                Style::default()
                            },
                        ),
                        Span::raw("  "),
                        Span::styled(description, muted),
                    ]));
                }
            }
            SecureStoreInputPhase::Passphrase => {
                lines.push(Line::from("Enter a vault passphrase:"));
                lines.push(Line::from("•".repeat(self.passphrase.chars().count())));
            }
            SecureStoreInputPhase::Confirmation => {
                lines.push(Line::from("Confirm the vault passphrase:"));
                lines.push(Line::from("•".repeat(self.confirmation.chars().count())));
            }
        }
        if let Some(status) = self.status.as_deref() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.to_string(), Color::Red)));
        }
        lines
    }

    pub(crate) fn help_text(&self) -> &'static str {
        match self.phase {
            SecureStoreInputPhase::Choice => "↑/↓  enter: select  esc: options",
            SecureStoreInputPhase::Passphrase | SecureStoreInputPhase::Confirmation => {
                "enter: continue  esc: choose again"
            }
        }
    }
}
