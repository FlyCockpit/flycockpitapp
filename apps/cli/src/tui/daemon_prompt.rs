//! "Daemon isn't running — what now?" dialog shown at TUI launch when
//! [`crate::daemon::probe`] returns anything other than `Running`.
//!
//! Choices:
//!   - Start a shared daemon (spawns a detached persistent child at the
//!     canonical socket; survives this window and is managed with
//!     `cockpit daemon {stop,status}`).
//!   - Run a private daemon for this window only (daemonless mode): the
//!     TUI owns a pid+nonce *ephemeral* daemon, isolated from the canonical
//!     daemon and from any other TUI, that is torn down when this window
//!     exits ([`DaemonChoice::ContinueWithout`]).
//!   - Exit.
//!
//! The chosen action is returned to the caller via [`DaemonChoice`].

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::daemon::{DaemonPaths, DaemonStatus};
use crate::tui::theme::MUTED_COLOR_INDEX;

pub const DIALOG_HEIGHT: u16 = 14;

#[derive(Debug, Clone, Copy)]
pub enum DaemonChoice {
    StartAndConnect,
    ContinueWithout,
    Exit,
}

pub struct DaemonPromptDialog {
    status: DaemonStatus,
    paths: DaemonPaths,
    cursor: usize,
    /// Set to `Some` once the user has picked. The caller drains it
    /// and acts on the choice; the dialog is then closed.
    chosen: Option<DaemonChoice>,
    /// Message shown after the user tried to start the daemon but it
    /// failed to come up.
    error: Option<String>,
}

impl DaemonPromptDialog {
    pub fn new(status: DaemonStatus, paths: DaemonPaths) -> Self {
        Self {
            status,
            paths,
            cursor: 0,
            chosen: None,
            error: None,
        }
    }

    pub fn take_choice(&mut self) -> Option<DaemonChoice> {
        self.chosen.take()
    }

    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
    }

    /// Returns true if the dialog wants to close (caller should drain
    /// the chosen action via `take_choice` and act on it).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.chosen = Some(DaemonChoice::Exit);
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                // 3 rows: start+connect / continue-without / exit.
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, 3);
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, 3);
                false
            }
            KeyCode::Enter => {
                self.chosen = Some(match self.cursor {
                    0 => DaemonChoice::StartAndConnect,
                    1 => DaemonChoice::ContinueWithout,
                    _ => DaemonChoice::Exit,
                });
                true
            }
            _ => false,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" cockpit daemon ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            match self.status {
                DaemonStatus::NotRunning => "The cockpit daemon is not running.",
                DaemonStatus::Stale => {
                    "A stale daemon pid file was found, but the socket isn't responding."
                }
                DaemonStatus::LivePidSocketUnreachable => {
                    "A cockpit daemon pid is live, but its recorded socket is unreachable."
                }
                DaemonStatus::Running => "Daemon is running.",
            }
            .to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Start a shared background daemon (persists across windows; stop".to_string(),
            muted,
        )));
        lines.push(Line::from(Span::styled(
            "later with `cockpit daemon stop`), or run a private daemon just".to_string(),
            muted,
        )));
        lines.push(Line::from(Span::styled(
            "for this window that shuts down automatically when you exit.".to_string(),
            muted,
        )));
        lines.push(Line::default());

        let options = [
            "Start a shared daemon and connect (Recommended)",
            "Run a private daemon for this window only",
            "Exit",
        ];
        for (i, label) in options.iter().enumerate() {
            let marker = if i == self.cursor { "▸ " } else { "  " };
            let style = if i == self.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker.to_string()),
                Span::styled((*label).to_string(), style),
            ]));
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!(
                "  pid file: {}    socket: {}",
                self.paths.pid_file.display(),
                self.paths.socket.display()
            ),
            muted,
        )));
        lines.push(Line::from(Span::styled(
            "  stop later with: `cockpit daemon stop`".to_string(),
            muted,
        )));
        if let Some(err) = &self.error {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(err.clone(), red)));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "↑/↓  enter: choose  esc: exit".to_string(),
                muted,
            ))),
            layout[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use std::path::PathBuf;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn fresh() -> DaemonPromptDialog {
        DaemonPromptDialog::new(
            DaemonStatus::NotRunning,
            DaemonPaths {
                pid_file: PathBuf::from("/tmp/cockpit.test.pid"),
                socket: PathBuf::from("/tmp/cockpit.test.sock"),
                ephemeral: false,
            },
        )
    }

    /// Pressing `j`/`k` must move the cursor and signal "don't close".
    /// The caller (App::handle_key) reads the `false` return value and
    /// short-circuits *before* the composer's char-insert path can run.
    #[test]
    fn jk_navigates_and_does_not_close() {
        let mut d = fresh();
        assert_eq!(d.cursor, 0);
        assert!(
            !d.handle_key(press(KeyCode::Char('j'))),
            "j must not close the prompt"
        );
        assert_eq!(d.cursor, 1);
        assert!(
            !d.handle_key(press(KeyCode::Char('k'))),
            "k must not close the prompt"
        );
        assert_eq!(d.cursor, 0);
        assert!(
            d.take_choice().is_none(),
            "navigation must not set a choice"
        );
    }

    /// The 3-row list wraps at both ends like every other selectable
    /// list: Up on the first row lands on the last, Down on the last
    /// lands on the first.
    #[test]
    fn nav_wraps_at_both_ends() {
        let mut d = fresh();
        assert_eq!(d.cursor, 0);
        d.handle_key(press(KeyCode::Up));
        assert_eq!(d.cursor, 2, "Up from first wraps to last");
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.cursor, 0, "Down from last wraps to first");
    }

    #[test]
    fn enter_returns_choice_and_closes() {
        let mut d = fresh();
        assert!(d.handle_key(press(KeyCode::Enter)));
        assert!(matches!(
            d.take_choice(),
            Some(DaemonChoice::StartAndConnect)
        ));
    }

    #[test]
    fn esc_returns_exit_choice() {
        let mut d = fresh();
        assert!(d.handle_key(press(KeyCode::Esc)));
        assert!(matches!(d.take_choice(), Some(DaemonChoice::Exit)));
    }
}
