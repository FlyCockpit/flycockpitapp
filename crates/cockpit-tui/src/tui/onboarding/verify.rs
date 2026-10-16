//! Native provider verification step. Network ownership stays in the daemon.

use crossterm::event::{KeyCode, KeyEvent, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use super::{ProviderSettlementEvidence, auth::SPINNER, chrome, ui};
use crate::tui::theme;

/// The verified catalog as the daemon summarized it: the exact `total` plus a
/// bounded preview of ids (the daemon never ships a whole catalog over the
/// verification RPC, #545).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelList {
    pub ids: Vec<String>,
    pub total: usize,
    /// How many of `total` the daemon saved; smaller when it trimmed an
    /// oversized catalog to keep it readable.
    pub kept: usize,
}

impl From<Vec<String>> for ModelList {
    fn from(ids: Vec<String>) -> Self {
        let total = ids.len();
        Self {
            ids,
            total,
            kept: total,
        }
    }
}

impl ModelList {
    /// Rendered rows: every previewed id, then one "…and N more" row when the
    /// preview was truncated.
    fn rows(&self) -> usize {
        self.ids.len() + usize::from(self.total > self.ids.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Models(ModelList),
    NoEndpoint,
    Unauthorized(u16),
    NotFound,
    HttpStatus {
        status: u16,
        snippet: String,
    },
    /// The daemon could not reach the provider (DNS, connect, timeout).
    Network(String),
    Parse(String),
    /// The provider check failed for a reason the daemon already phrased.
    Failed(String),
    /// The Cockpit daemon rejected or failed the verification request itself.
    /// This is a Cockpit-side failure, never a network problem.
    Daemon {
        code: String,
        message: String,
    },
    /// The local Cockpit daemon could not be reached at all.
    DaemonUnreachable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyPhase {
    Fetching,
    Success(ModelList),
    NoEndpoint,
    Error(VerifyOutcome),
}

pub(crate) struct VerifyScreen {
    provider_id: String,
    phase: VerifyPhase,
    spinner: usize,
    offset: usize,
    settlement: Option<ProviderSettlementEvidence>,
}

impl VerifyScreen {
    pub(crate) fn new(provider_id: String) -> Self {
        Self {
            provider_id,
            phase: VerifyPhase::Fetching,
            spinner: 0,
            offset: 0,
            settlement: None,
        }
    }
    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub(crate) fn settlement(&self) -> Option<&ProviderSettlementEvidence> {
        self.settlement.as_ref()
    }
    pub(crate) fn phase(&self) -> &VerifyPhase {
        &self.phase
    }
    pub(crate) fn retry(&mut self) {
        self.phase = VerifyPhase::Fetching;
        self.offset = 0;
    }
    pub(crate) fn apply(
        &mut self,
        outcome: VerifyOutcome,
        settlement: Option<ProviderSettlementEvidence>,
    ) {
        if settlement.is_some() {
            self.settlement = settlement;
        }
        self.phase = match outcome {
            VerifyOutcome::Models(models) => VerifyPhase::Success(models),
            VerifyOutcome::NoEndpoint => VerifyPhase::NoEndpoint,
            error => VerifyPhase::Error(error),
        };
        self.offset = 0;
    }
    pub(crate) fn tick(&mut self) {
        self.spinner = (self.spinner + 1) % SPINNER.len();
    }
    pub(crate) fn title(&self) -> &'static str {
        match self.phase {
            VerifyPhase::Fetching => "Verifying provider",
            VerifyPhase::Success(_) => "✓ Connected",
            VerifyPhase::NoEndpoint => "Credential stored",
            VerifyPhase::Error(_) => "✗ Couldn't verify",
        }
    }
    pub(crate) fn subtitle(&self) -> String {
        match &self.phase {
            VerifyPhase::Fetching => {
                format!("Checking {} through the Cockpit daemon.", self.provider_id)
            }
            VerifyPhase::Success(models) => {
                format!(
                    "{} · {} model(s) available{}",
                    self.provider_id,
                    models.total,
                    cockpit_proto::catalog_trim_note(
                        u32::try_from(models.total).unwrap_or(u32::MAX),
                        u32::try_from(models.kept).unwrap_or(u32::MAX),
                    )
                )
            }
            VerifyPhase::NoEndpoint => {
                format!("{} has no public /models endpoint.", self.provider_id)
            }
            VerifyPhase::Error(error) => error_copy(error).0,
        }
    }
    pub(crate) fn help_text(&self) -> &'static str {
        match self.phase {
            VerifyPhase::Fetching => "esc cancel   ^c quit",
            VerifyPhase::Success(_) | VerifyPhase::NoEndpoint => {
                "↑↓ scroll   a add another   enter done   esc back   ^c quit"
            }
            VerifyPhase::Error(_) => "r retry   esc back   ^c quit",
        }
    }
    pub(crate) fn buttons(&self) -> Vec<chrome::Button<'static>> {
        match self.phase {
            VerifyPhase::Fetching => vec![],
            VerifyPhase::Success(_) | VerifyPhase::NoEndpoint => vec![
                chrome::Button::secondary("Add another"),
                chrome::Button::primary("Done"),
            ],
            VerifyPhase::Error(_) => vec![chrome::Button::primary("Retry")],
        }
    }
    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if let VerifyPhase::Success(models) = &self.phase {
            let max = models.rows().saturating_sub(1);
            match key.code {
                KeyCode::Down => self.offset = (self.offset + 1).min(max),
                KeyCode::Up => self.offset = self.offset.saturating_sub(1),
                _ => {}
            }
        }
    }
    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent) {
        if !matches!(self.phase, VerifyPhase::Success(_)) {
            return;
        }
        let VerifyPhase::Success(models) = &self.phase else {
            return;
        };
        let max = models.rows().saturating_sub(1);
        match mouse.kind {
            MouseEventKind::ScrollUp => self.offset = self.offset.saturating_sub(1),
            MouseEventKind::ScrollDown => self.offset = (self.offset + 1).min(max),
            _ => {}
        }
    }
    pub(crate) fn render(&self, frame: &mut Frame, area: Rect) {
        match &self.phase {
            VerifyPhase::Fetching => frame.render_widget(Paragraph::new(Line::from(vec![Span::styled(format!("{} ", SPINNER[self.spinner]), Style::new().fg(theme::BRASS)), Span::styled("Fetching models from the provider…", Style::new().fg(theme::FOG))])), area),
            VerifyPhase::Success(models) => {
                let block = Block::bordered().border_type(crate::tui::chrome::rounded_border_type()).border_style(Style::new().fg(theme::GOOD)).title(Span::styled(" Models ", Style::new().fg(theme::GOOD)));
                let inner = block.inner(area);
                frame.render_widget(block, area);
                let count = models.rows();
                let view_h = usize::from(inner.height);
                let overflow = count > view_h;
                let row_width = inner.width.saturating_sub(u16::from(overflow));
                for row in 0..view_h {
                    let index = self.offset + row;
                    if index >= count {
                        break;
                    }
                    let rect = Rect {
                        x: inner.x,
                        y: inner.y + row as u16,
                        width: row_width,
                        height: 1,
                    };
                    let line = match models.ids.get(index) {
                        Some(id) => Line::from(vec![
                            Span::styled("✓ ", Style::new().fg(theme::GOOD)),
                            Span::styled(id.clone(), Style::new().fg(theme::INK)),
                        ]),
                        None => Line::from(Span::styled(
                            format!(
                                "  …and {} more",
                                models.total.saturating_sub(models.ids.len())
                            ),
                            Style::new().fg(theme::FOG),
                        )),
                    };
                    frame.render_widget(Paragraph::new(line), rect);
                }
                if overflow {
                    ui::render_scrollbar(
                        frame,
                        Rect {
                            x: inner.right() - 1,
                            y: inner.y,
                            width: 1,
                            height: inner.height,
                        },
                        count,
                        view_h,
                        self.offset,
                        false,
                    );
                }
            }
            VerifyPhase::NoEndpoint => frame.render_widget(
                Paragraph::new(
                    "The credential is stored. This provider does not publish a model catalog, so Cockpit will use configured models.",
                )
                .style(Style::new().fg(theme::FOG))
                .wrap(Wrap { trim: true }),
                area,
            ),
            VerifyPhase::Error(error) => {
                let (_, detail, hint) = error_copy(error);
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::from(Span::styled(detail, Style::new().fg(theme::BAD))),
                        Line::default(),
                        Line::from(Span::styled(
                            hint,
                            Style::new().fg(theme::FOG).add_modifier(Modifier::ITALIC),
                        )),
                    ])
                    .wrap(Wrap { trim: true }),
                    area,
                );
            }
        }
    }
}

fn error_copy(outcome: &VerifyOutcome) -> (String, String, String) {
    match outcome {
        VerifyOutcome::Unauthorized(status) => (
            format!("Credential rejected ({status})"),
            "The provider rejected this credential.".into(),
            "Step back to replace the credential, then retry.".into(),
        ),
        VerifyOutcome::NotFound => (
            "Wrong base URL (404)".into(),
            "The provider did not expose /models at this URL.".into(),
            "Check the base URL (many providers need a /v1 suffix), then retry.".into(),
        ),
        VerifyOutcome::HttpStatus { status, snippet } => (
            format!("Provider returned HTTP {status}"),
            snippet.clone(),
            "Retry, or check the provider status page.".into(),
        ),
        VerifyOutcome::Network(message) => (
            "Couldn't reach the provider".into(),
            message.clone(),
            "Check your network connection, then retry.".into(),
        ),
        VerifyOutcome::Failed(message) => (
            "Couldn't verify the provider".into(),
            message.clone(),
            "Step back to check the provider settings, then retry.".into(),
        ),
        VerifyOutcome::Daemon { code, message } => (
            "Cockpit couldn't run the check".into(),
            format!("{code}: {message}"),
            "This is a Cockpit error, not a network or credential problem. Retry; if it repeats, run `cockpit doctor`.".into(),
        ),
        VerifyOutcome::DaemonUnreachable(message) => (
            "Couldn't reach the Cockpit daemon".into(),
            message.clone(),
            "Run `cockpit daemon restart`, then retry.".into(),
        ),
        VerifyOutcome::Parse(message) => (
            "Couldn't parse the model list".into(),
            message.clone(),
            "The provider returned an unexpected response format.".into(),
        ),
        VerifyOutcome::Models(_) | VerifyOutcome::NoEndpoint => {
            (String::new(), String::new(), String::new())
        }
    }
}
