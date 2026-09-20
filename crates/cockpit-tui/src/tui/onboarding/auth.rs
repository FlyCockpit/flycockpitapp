//! Native provider authentication step for first-run onboarding.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph, Wrap};

use super::{chrome, theme, ui};
use crate::tui::settings::{
    OAuthBeginResult, OAuthFlowRequest, OAuthFlowState, OAuthPresentationResult, OAuthProvider,
};
use crate::tui::textfield::TextField;
use cockpit_core::providers::ProviderTemplate;

pub(crate) const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthPhase {
    Acknowledge,
    DeviceIdle,
    DevicePolling,
    PasteCallback,
    ApiKey,
}

#[derive(Debug)]
pub(crate) enum AuthSubmission {
    ApiKey {
        provider_id: String,
        base_url: String,
        key: zeroize::Zeroizing<String>,
    },
    Environment {
        provider_id: String,
        base_url: String,
        variable: String,
    },
    OAuth {
        provider_id: String,
        base_url: String,
    },
    NoCredential {
        provider_id: String,
        base_url: String,
    },
}

impl AuthSubmission {
    pub(crate) fn provider_id(&self) -> &str {
        match self {
            Self::ApiKey { provider_id, .. }
            | Self::Environment { provider_id, .. }
            | Self::OAuth { provider_id, .. }
            | Self::NoCredential { provider_id, .. } => provider_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    ProviderId,
    BaseUrl,
    Key,
}

pub(crate) struct AuthScreen {
    template: &'static ProviderTemplate,
    phase: AuthPhase,
    provider_id: TextField,
    base_url: TextField,
    key: TextField,
    callback: TextField,
    oauth: Option<OAuthFlowState>,
    pending_oauth_action: Option<OAuthFlowRequest>,
    focus: Focus,
    reveal: bool,
    spinner: usize,
    poll_ticks: u64,
    user_code: String,
    authorize_url: String,
    detected_env: Option<String>,
    error: Option<String>,
    provider_id_rect: Rect,
    base_rect: Rect,
    key_rect: Rect,
    callback_rect: Rect,
}

impl AuthScreen {
    pub(crate) fn new(template: &'static ProviderTemplate) -> Self {
        let uses_oauth = matches!(
            template.auth,
            cockpit_config::config::providers::AuthKind::OAuth
        );
        let oauth = uses_oauth.then(|| {
            OAuthFlowState::new(if template.id == "codex-oauth" {
                OAuthProvider::Codex
            } else {
                OAuthProvider::Grok
            })
        });
        let custom = template.id == "openai-compatible";
        let mut provider_id = TextField::default();
        provider_id.set(if template.use_id_as_default {
            template.id
        } else {
            ""
        });
        let mut base_url = TextField::default();
        base_url.set(template.url);
        Self {
            template,
            phase: if uses_oauth {
                AuthPhase::Acknowledge
            } else {
                AuthPhase::ApiKey
            },
            provider_id,
            base_url,
            key: TextField::default(),
            callback: TextField::default(),
            oauth,
            pending_oauth_action: None,
            focus: if custom {
                Focus::ProviderId
            } else {
                Focus::Key
            },
            reveal: false,
            spinner: 0,
            poll_ticks: 0,
            user_code: "---- ----".to_string(),
            authorize_url: template
                .hint
                .unwrap_or("Open the provider sign-in page.")
                .to_string(),
            detected_env: cockpit_core::providers::detected_env_var(template)
                .map(str::to_string)
                .or_else(|| {
                    (custom && std::env::var_os("API_KEY").is_some()).then(|| "API_KEY".into())
                }),
            error: None,
            provider_id_rect: Rect::default(),
            base_rect: Rect::default(),
            key_rect: Rect::default(),
            callback_rect: Rect::default(),
        }
    }

    pub(crate) fn template(&self) -> &'static ProviderTemplate {
        self.template
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_phase_for_golden(&mut self, phase: AuthPhase) {
        self.phase = phase;
        if matches!(phase, AuthPhase::DeviceIdle | AuthPhase::DevicePolling) {
            self.authorize_url = "https://auth.openai.com/codex/device".into();
            self.user_code = "ABCD-EFGH".into();
        }
    }
    pub(crate) fn title(&self) -> &'static str {
        match self.phase {
            AuthPhase::Acknowledge => "Acknowledge the risk",
            AuthPhase::DeviceIdle | AuthPhase::DevicePolling | AuthPhase::PasteCallback => {
                "Sign in to your subscription"
            }
            AuthPhase::ApiKey => "Add your API key",
        }
    }
    pub(crate) fn subtitle(&self) -> String {
        match self.phase {
            AuthPhase::Acknowledge => {
                format!("{} signs in with your subscription.", self.template.display)
            }
            AuthPhase::DeviceIdle | AuthPhase::DevicePolling => {
                "A device code links this client to your account.".into()
            }
            AuthPhase::PasteCallback => {
                "Approve access in the browser, then paste the result back.".into()
            }
            AuthPhase::ApiKey => format!("Paste a key for {}.", self.template.display),
        }
    }

    fn is_device(&self) -> bool {
        self.template.id == "codex-oauth" || self.template.id == "github-copilot"
    }
    fn needs_base_url(&self) -> bool {
        self.template.id == "openai-compatible"
    }

    pub(crate) fn help_text(&self) -> &'static str {
        match self.phase {
            AuthPhase::Acknowledge => "enter acknowledge   esc back   ^c quit",
            AuthPhase::DeviceIdle => "enter open & poll   esc back   ^c quit",
            AuthPhase::DevicePolling => "esc cancel   ^c quit",
            AuthPhase::PasteCallback => "paste callback   enter continue   esc back   ^c quit",
            AuthPhase::ApiKey => "tab next field   ^r reveal   ^e env var   esc back   ^c quit",
        }
    }

    pub(super) fn buttons(&self) -> Vec<chrome::Button<'static>> {
        match self.phase {
            AuthPhase::Acknowledge => vec![chrome::Button::primary("I acknowledge")],
            AuthPhase::DeviceIdle => vec![chrome::Button::primary("Open & poll")],
            AuthPhase::DevicePolling => vec![
                chrome::Button::secondary("Cancel"),
                chrome::Button::primary("Approve now"),
            ],
            AuthPhase::PasteCallback => vec![chrome::Button::primary("Continue")],
            AuthPhase::ApiKey => {
                let mut out = vec![chrome::Button::secondary(if self.reveal {
                    "Mask"
                } else {
                    "Reveal"
                })];
                if self.detected_env.is_some() {
                    out.push(chrome::Button::secondary("Use env var"));
                }
                out.push(chrome::Button::primary("Continue"));
                out
            }
        }
    }

    pub(crate) fn action(&mut self, index: usize) -> Option<AuthSubmission> {
        match self.phase {
            AuthPhase::Acknowledge if index == 0 => {
                self.pending_oauth_action = self
                    .oauth
                    .as_mut()
                    .map(OAuthFlowState::onboarding_acknowledge);
                None
            }
            AuthPhase::DeviceIdle if index == 0 => {
                self.phase = AuthPhase::DevicePolling;
                self.poll_ticks = 0;
                if self.pending_oauth_action.is_none() {
                    self.pending_oauth_action =
                        self.oauth.as_mut().map(OAuthFlowState::onboarding_begin);
                }
                None
            }
            AuthPhase::DevicePolling if index == 0 => {
                self.pending_oauth_action =
                    self.oauth.as_mut().map(OAuthFlowState::onboarding_cancel);
                None
            }
            AuthPhase::DevicePolling if index == 1 => {
                self.pending_oauth_action = self
                    .oauth
                    .as_mut()
                    .and_then(OAuthFlowState::onboarding_poll);
                None
            }
            AuthPhase::PasteCallback if index == 0 => {
                let input = self.callback.text().trim().to_string();
                if input.is_empty() {
                    self.error = Some("Paste the callback URL or authorization code first.".into());
                } else {
                    self.pending_oauth_action = self.oauth.as_mut().and_then(|state| {
                        state.onboarding_complete(zeroize::Zeroizing::new(input))
                    });
                }
                None
            }
            AuthPhase::ApiKey if index == 0 => {
                self.reveal = !self.reveal;
                None
            }
            AuthPhase::ApiKey if self.detected_env.is_some() && index == 1 => self.submit_env(),
            AuthPhase::ApiKey if index == self.buttons().len().saturating_sub(1) => {
                self.submit_key()
            }
            _ => None,
        }
    }

    fn validate_identity(&mut self) -> Option<(String, String)> {
        let id = self.provider_id.text().trim().to_string();
        let url = self
            .base_url
            .text()
            .trim()
            .trim_end_matches('/')
            .to_string();
        if id.is_empty() {
            self.error = Some("Enter a unique provider id.".into());
            return None;
        }
        if self.needs_base_url() && !(url.starts_with("https://") || url.starts_with("http://")) {
            self.error = Some("Base URL must start with http:// or https://.".into());
            return None;
        }
        Some((id, url))
    }

    fn submit_key(&mut self) -> Option<AuthSubmission> {
        let (provider_id, base_url) = self.validate_identity()?;
        let key = self.key.text().trim().to_string();
        if key.is_empty() {
            self.error = Some("Paste a non-empty API key or use an environment variable.".into());
            return None;
        }
        Some(AuthSubmission::ApiKey {
            provider_id,
            base_url,
            key: zeroize::Zeroizing::new(key),
        })
    }
    fn submit_env(&mut self) -> Option<AuthSubmission> {
        let variable = self.detected_env.clone()?;
        let (provider_id, base_url) = self.validate_identity()?;
        Some(AuthSubmission::Environment {
            provider_id,
            base_url,
            variable,
        })
    }

    pub(crate) fn take_oauth_action(&mut self) -> Option<OAuthFlowRequest> {
        self.pending_oauth_action.take()
    }

    pub(crate) fn cancel_oauth(&mut self) -> Option<OAuthFlowRequest> {
        if self.phase == AuthPhase::Acknowledge {
            None
        } else {
            self.oauth.as_mut().map(OAuthFlowState::onboarding_cancel)
        }
    }

    pub(crate) fn oauth_provider(&self) -> Option<OAuthProvider> {
        self.oauth.as_ref().map(|state| state.provider)
    }

    fn oauth_submission(&self) -> AuthSubmission {
        AuthSubmission::OAuth {
            provider_id: self.template.id.to_string(),
            base_url: self.template.url.to_string(),
        }
    }

    pub(crate) fn apply_oauth_acknowledgement(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<(), String>,
    ) -> Option<OAuthFlowRequest> {
        let device = self.is_device();
        let state = self.oauth.as_mut()?;
        if !state.accepts_result(client_flow_id, operation_id) {
            return None;
        }
        let succeeded = result.is_ok();
        state.apply_acknowledgement(result);
        if succeeded {
            self.phase = if device {
                AuthPhase::DevicePolling
            } else {
                AuthPhase::PasteCallback
            };
            Some(state.onboarding_begin())
        } else {
            self.error = state
                .status
                .as_ref()
                .and_then(|status| status.as_ref().err())
                .cloned();
            None
        }
    }

    pub(crate) fn apply_oauth_begin(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: OAuthBeginResult,
    ) -> Option<OAuthFlowRequest> {
        let device = self.is_device();
        let state = self.oauth.as_mut()?;
        if !state.accepts_result(client_flow_id, operation_id) {
            return None;
        }
        let next = state.apply_begin_deferred(result);
        if let Some((url, code)) = state.onboarding_device_login() {
            self.authorize_url = url.to_string();
            self.user_code = code.to_string();
            self.phase = AuthPhase::DeviceIdle;
            self.pending_oauth_action = next;
            return None;
        } else if let Some(url) = state.onboarding_authorize_url() {
            self.authorize_url = url.to_string();
            self.phase = AuthPhase::PasteCallback;
        } else if next.is_none() {
            self.error = state
                .status
                .as_ref()
                .and_then(|status| status.as_ref().err())
                .cloned();
            self.phase = if device {
                AuthPhase::DeviceIdle
            } else {
                AuthPhase::PasteCallback
            };
        }
        next
    }

    pub(crate) fn apply_oauth_present(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<OAuthPresentationResult, String>,
    ) -> Option<OAuthFlowRequest> {
        let state = self.oauth.as_mut()?;
        if !state.accepts_result(client_flow_id, operation_id) {
            return None;
        }
        state.apply_present(result)
    }

    pub(crate) fn apply_oauth_complete(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<bool, String>,
    ) -> Option<AuthSubmission> {
        let state = self.oauth.as_mut()?;
        if !state.accepts_result(client_flow_id, operation_id) {
            return None;
        }
        state.apply_complete(result);
        if state.logged_in {
            Some(self.oauth_submission())
        } else {
            self.error = state
                .status
                .as_ref()
                .and_then(|status| status.as_ref().err())
                .cloned();
            None
        }
    }

    pub(crate) fn apply_oauth_cancel(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        result: Result<bool, String>,
    ) {
        let Some(state) = self.oauth.as_mut() else {
            return;
        };
        if state.accepts_result(client_flow_id, operation_id) {
            state.apply_cancel(result);
            self.phase = AuthPhase::DeviceIdle;
        }
    }

    pub(crate) fn apply_oauth_settlement_unknown(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        error: String,
        acknowledgement: bool,
    ) {
        let Some(state) = self.oauth.as_mut() else {
            return;
        };
        if state.accepts_result(client_flow_id, operation_id) {
            if acknowledgement {
                state.apply_acknowledgement_settlement_unknown(error);
            } else {
                state.apply_settlement_unknown(error);
            }
        }
    }

    pub(crate) fn apply_oauth_cancel_authoritative_failure(
        &mut self,
        client_flow_id: crate::tui::settings::OAuthFlowId,
        operation_id: crate::tui::settings::PointerOperationId,
        error: String,
    ) {
        let Some(state) = self.oauth.as_mut() else {
            return;
        };
        if state.accepts_result(client_flow_id, operation_id) {
            state.apply_cancel_authoritative_failure(error);
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<AuthSubmission> {
        match self.phase {
            AuthPhase::Acknowledge if key.code == KeyCode::Enter => self.action(0),
            AuthPhase::DeviceIdle if key.code == KeyCode::Enter => self.action(0),
            AuthPhase::DevicePolling if key.code == KeyCode::Esc => self.action(0),
            AuthPhase::PasteCallback if key.code == KeyCode::Enter => self.action(0),
            AuthPhase::PasteCallback => {
                self.callback.handle_key(key);
                None
            }
            AuthPhase::ApiKey => match key.code {
                KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.reveal = !self.reveal;
                    None
                }
                KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.submit_env()
                }
                KeyCode::Tab if self.needs_base_url() => {
                    self.focus = match self.focus {
                        Focus::ProviderId => Focus::BaseUrl,
                        Focus::BaseUrl => Focus::Key,
                        Focus::Key => Focus::ProviderId,
                    };
                    None
                }
                KeyCode::BackTab if self.needs_base_url() => {
                    self.focus = match self.focus {
                        Focus::ProviderId => Focus::Key,
                        Focus::BaseUrl => Focus::ProviderId,
                        Focus::Key => Focus::BaseUrl,
                    };
                    None
                }
                KeyCode::Enter => self.submit_key(),
                _ => {
                    match self.focus {
                        Focus::ProviderId if self.needs_base_url() => {
                            self.provider_id.handle_key(key);
                        }
                        Focus::BaseUrl if self.needs_base_url() => {
                            self.base_url.handle_key(key);
                        }
                        _ => {
                            self.key.handle_key(key);
                        }
                    }
                    self.error = None;
                    None
                }
            },
            _ => None,
        }
    }

    pub(crate) fn paste(&mut self, text: &str) {
        match self.phase {
            AuthPhase::PasteCallback => self.callback.paste(text),
            AuthPhase::ApiKey => match self.focus {
                Focus::ProviderId if self.needs_base_url() => self.provider_id.paste(text),
                Focus::BaseUrl if self.needs_base_url() => self.base_url.paste(text),
                _ => self.key.paste(text),
            },
            _ => {}
        }
    }
    pub(crate) fn tick(&mut self) {
        self.spinner = (self.spinner + 1) % SPINNER.len();
        if self.phase == AuthPhase::DevicePolling {
            self.poll_ticks = self.poll_ticks.saturating_add(1);
        }
    }
    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent) {
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return;
        }
        let pos = Position::new(mouse.column, mouse.row);
        if chrome::hit(self.provider_id_rect, pos) {
            self.focus = Focus::ProviderId;
        }
        if chrome::hit(self.base_rect, pos) {
            self.focus = Focus::BaseUrl;
        }
        if chrome::hit(self.key_rect, pos) {
            self.focus = Focus::Key;
        }
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        match self.phase {
            AuthPhase::Acknowledge => frame.render_widget(Paragraph::new(vec![
                Line::from(Span::styled("Using subscription credentials from a third-party client may violate the provider's terms of service and could get your account suspended.", Style::new().fg(theme::BAD))),
                Line::default(),
                Line::from(Span::styled("Press Enter to acknowledge and continue, or Esc to go back.", Style::new().fg(theme::FOG).add_modifier(Modifier::ITALIC))),
            ]).wrap(Wrap { trim: true }), area),
            AuthPhase::DeviceIdle | AuthPhase::DevicePolling => self.render_device(frame, area),
            AuthPhase::PasteCallback => self.render_callback(frame, area),
            AuthPhase::ApiKey => self.render_api_key(frame, area),
        }
    }

    fn render_device(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new("Open this URL in a browser and enter the code:"),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.authorize_url.clone(),
                Style::new()
                    .fg(theme::BRASS)
                    .add_modifier(Modifier::UNDERLINED),
            ))),
            rows[1],
        );
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(theme::NIGHT))
            .title(" One-time code ");
        let inner = block.inner(rows[3]);
        frame.render_widget(block, rows[3]);
        frame.render_widget(Paragraph::new(self.user_code.clone()).centered(), inner);
        let status = if let Some(error) = &self.error {
            error.clone()
        } else if self.phase == AuthPhase::DevicePolling {
            let elapsed_seconds = self.poll_ticks / 10;
            format!(
                "{} Waiting for approval… {:02}:{:02}",
                SPINNER[self.spinner],
                elapsed_seconds / 60,
                elapsed_seconds % 60
            )
        } else {
            "Press Enter once you've opened the page to start polling.".into()
        };
        frame.render_widget(
            Paragraph::new(status).style(Style::new().fg(theme::FOG)),
            rows[4],
        );
    }
    fn render_callback(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);
        frame.render_widget(Paragraph::new("Open this URL and approve access:"), rows[0]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.authorize_url.clone(),
                Style::new()
                    .fg(theme::BRASS)
                    .add_modifier(Modifier::UNDERLINED),
            ))),
            rows[1],
        );
        self.callback_rect = rows[3];
        if let Some(caret) = ui::render_field(
            frame,
            rows[3],
            "Callback URL or code",
            &self.callback,
            true,
            "Paste callback",
        ) {
            frame.set_cursor_position(caret);
        }
    }
    fn render_api_key(&mut self, frame: &mut Frame, area: Rect) {
        let identity = if self.needs_base_url() { 6 } else { 0 };
        let rows = Layout::vertical([
            Constraint::Length(identity),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(area);
        self.key_rect = rows[1];
        let mut caret = None;
        if self.needs_base_url() {
            let identity_rows =
                Layout::vertical([Constraint::Length(3), Constraint::Length(3)]).split(rows[0]);
            self.provider_id_rect = identity_rows[0];
            self.base_rect = identity_rows[1];
            caret = ui::render_field(
                frame,
                identity_rows[0],
                "Provider id",
                &self.provider_id,
                self.focus == Focus::ProviderId,
                "my-provider",
            );
            let base_caret = ui::render_field(
                frame,
                identity_rows[1],
                "Base URL",
                &self.base_url,
                self.focus == Focus::BaseUrl,
                "https://api.example.com/v1",
            );
            if self.focus == Focus::BaseUrl {
                caret = base_caret;
            }
        } else {
            self.provider_id_rect = Rect::default();
            self.base_rect = Rect::default();
        }
        let key_caret = ui::render_field_masked(
            frame,
            rows[1],
            "API key",
            &self.key,
            self.focus == Focus::Key,
            if self.reveal {
                "Paste API key"
            } else {
                "••••••••"
            },
            !self.reveal,
        );
        if self.focus == Focus::Key {
            caret = key_caret;
        }
        let note = self
            .error
            .clone()
            .or_else(|| {
                self.detected_env
                    .as_ref()
                    .map(|v| format!("Found ${v} in your environment — press ^E to use it."))
            })
            .unwrap_or_else(|| "Input is masked (^R to reveal).".into());
        frame.render_widget(
            Paragraph::new(note).style(Style::new().fg(if self.error.is_some() {
                theme::BAD
            } else {
                theme::FOG
            })),
            rows[2],
        );
        if let Some(caret) = caret {
            frame.set_cursor_position(caret);
        }
    }
}
