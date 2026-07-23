use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::tui::dialog::{Answer, DialogOption, DialogOutcome, DialogState, Page};
use crate::tui::theme::{MUTED_COLOR_INDEX, WARNING_TEXT};

pub const DIALOG_HEIGHT: u16 = 9;

const ACTION_SWITCH: &str = "switch";
const ACTION_KEEP: &str = "keep";
const ACTION_PICKER: &str = "picker";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDriftAction {
    SwitchToConfig,
    KeepSession,
    OpenPicker,
}

pub struct ConfigDriftDialog {
    state: DialogState,
    can_switch: bool,
}

impl ConfigDriftDialog {
    pub fn new(can_switch: bool) -> Self {
        let mut options = Vec::new();
        if can_switch {
            options.push(DialogOption::new(ACTION_SWITCH, "Switch to config model"));
        }
        options.push(DialogOption::new(ACTION_KEEP, "Keep session model"));
        options.push(DialogOption::new(ACTION_PICKER, "Open model picker…"));
        let page = Page::select("Model config drift", options).allow_custom(false);
        Self {
            state: DialogState::new(vec![page], DialogState::NO_LOCKOUT),
            can_switch,
        }
    }

    pub fn can_switch(&self) -> bool {
        self.can_switch
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<ConfigDriftAction> {
        match self.state.handle_key(key) {
            DialogOutcome::Continue => None,
            DialogOutcome::Cancel => Some(ConfigDriftAction::KeepSession),
            DialogOutcome::Submit(answers) => action_from_answers(&answers),
        }
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        session_label: &str,
        config_label: &str,
    ) {
        frame.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" model config drift ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let warning = Style::default().fg(WARNING_TEXT);
        let mut lines = vec![
            Line::from(vec![
                Span::styled("session: ".to_string(), muted),
                Span::styled(session_label.to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("config:  ".to_string(), muted),
                Span::styled(config_label.to_string(), warning),
            ]),
            Line::from(Span::styled(
                format!(
                    "This session is running {session_label}, but your config's active model is {config_label}. New sessions will use the config model."
                ),
                muted,
            )),
            Line::default(),
        ];

        let page = &self.state.pages()[0];
        let cursor = self.state.cursor();
        for (idx, option) in page.options.iter().enumerate() {
            let selected = idx == cursor;
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker.to_string()),
                Span::styled(option.label.clone(), style),
            ]));
        }

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

fn action_from_answers(answers: &[Answer]) -> Option<ConfigDriftAction> {
    match answers.first()? {
        Answer::Single { id } if id == ACTION_SWITCH => Some(ConfigDriftAction::SwitchToConfig),
        Answer::Single { id } if id == ACTION_PICKER => Some(ConfigDriftAction::OpenPicker),
        Answer::Single { id } if id == ACTION_KEEP => Some(ConfigDriftAction::KeepSession),
        _ => Some(ConfigDriftAction::KeepSession),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn rendered_text(dialog: &mut ConfigDriftDialog) -> String {
        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dialog.render(
                    frame,
                    Rect::new(0, 0, 80, DIALOG_HEIGHT),
                    "session-p/session-m",
                    "config model unknown",
                );
            })
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn config_drift_dialog_handles_unknown_config_model() {
        let mut dialog = ConfigDriftDialog::new(false);
        let text = rendered_text(&mut dialog);

        assert!(text.contains("config model unknown"), "rendered:\n{text}");
        assert!(
            !text.contains("Switch to config model"),
            "rendered:\n{text}"
        );
        assert!(text.contains("Keep session model"), "rendered:\n{text}");
        assert!(text.contains("Open model picker"), "rendered:\n{text}");
    }
}
