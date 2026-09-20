//! Native provider verification step. Network ownership stays in the daemon.

use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};

use super::{ProviderSettlementEvidence, auth::SPINNER, chrome, theme};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Models(Vec<String>),
    NoEndpoint,
    Unauthorized(u16),
    NotFound,
    HttpStatus { status: u16, snippet: String },
    Network(String),
    Parse(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyPhase {
    Fetching,
    Success(Vec<String>),
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
    pub(crate) fn update_settlement_generation(&mut self, config_generation: u64) {
        if let Some(settlement) = &mut self.settlement {
            settlement.config_generation = config_generation;
        }
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
                format!("{} · {} model(s) available", self.provider_id, models.len())
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
    pub(super) fn buttons(&self) -> Vec<chrome::Button<'static>> {
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
            let max = models.len().saturating_sub(1);
            match key.code {
                KeyCode::Down => self.offset = (self.offset + 1).min(max),
                KeyCode::Up => self.offset = self.offset.saturating_sub(1),
                _ => {}
            }
        }
    }
    pub(crate) fn handle_mouse(&mut self, _mouse: MouseEvent) {}
    pub(crate) fn render(&self, frame: &mut Frame, area: Rect) {
        match &self.phase {
            VerifyPhase::Fetching => frame.render_widget(Paragraph::new(Line::from(vec![Span::styled(format!("{} ", SPINNER[self.spinner]), Style::new().fg(theme::BRASS)), Span::styled("Fetching models from the provider…", Style::new().fg(theme::FOG))])), area),
            VerifyPhase::Success(models) => {
                let block = Block::bordered().border_type(BorderType::Rounded).border_style(Style::new().fg(theme::GOOD)).title(Span::styled(" Models ", Style::new().fg(theme::GOOD)));
                let inner = block.inner(area); frame.render_widget(block, area);
                let lines = models.iter().skip(self.offset).take(usize::from(inner.height)).map(|model| Line::from(vec![Span::styled("✓ ", Style::new().fg(theme::GOOD)), Span::styled(model.clone(), Style::new().fg(theme::INK))])).collect::<Vec<_>>();
                frame.render_widget(Paragraph::new(lines), inner);
            }
            VerifyPhase::NoEndpoint => frame.render_widget(Paragraph::new("The credential is stored. This provider does not publish a model catalog, so Cockpit will use configured models." ).style(Style::new().fg(theme::FOG)), area),
            VerifyPhase::Error(error) => { let (_, detail, hint) = error_copy(error); frame.render_widget(Paragraph::new(vec![Line::from(Span::styled(detail, Style::new().fg(theme::BAD))), Line::default(), Line::from(Span::styled(hint, Style::new().fg(theme::FOG).add_modifier(Modifier::ITALIC)))]), area); }
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
            "Check DNS, TLS, connectivity, and the base URL, then retry.".into(),
        ),
        VerifyOutcome::Parse(message) => (
            "Unexpected response".into(),
            message.clone(),
            "The endpoint answered, but its model list could not be read.".into(),
        ),
        _ => (
            "Verification failed".into(),
            "The provider could not be verified.".into(),
            "Retry or step back.".into(),
        ),
    }
}
