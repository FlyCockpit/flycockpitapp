//! Step three of onboarding: authenticate with the provider the picker chose.
//!
//! The screen shape follows the credential kind, mirroring
//! `cockpit_core`'s wizard branches:
//!
//! - **OAuth** providers first show the subscription-risk acknowledgement
//!   (`subscription_ack.rs`), then a login screen. `codex-oauth` uses a
//!   device-code page (`auth.openai.com/codex/device`): we display a URL and a
//!   one-time code and spin while "polling" for approval. `grok-oauth` uses a
//!   browser callback: we show the authorize URL and take the pasted callback.
//!   This reference cannot complete real third-party OAuth, so approval is
//!   simulated — the point is the shape of the flow, not a live token.
//! - **API-key** providers show a masked key field. When the provider ships a
//!   default environment variable and it is set, we offer to use it instead of
//!   pasting. `openai-compatible` also asks for the base URL, since it has none
//!   baked in.
//!
//! The credential handed back drives [`super::verify`], which probes
//! `{base_url}/models` for real (API key) or with a canned result (OAuth).

use std::io::Stdout;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph, Wrap};

use super::chrome;
use super::field::TextField;
use super::providers::{Kind, Provider};

const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);
const WARN: Color = Color::Rgb(0xD8, 0x8A, 0x5A);
const GOOD: Color = Color::Rgb(0x7F, 0xC9, 0x8A);

/// Redraw cadence, fast enough for a smooth spinner during OAuth polling.
const FRAME: Duration = Duration::from_millis(100);
/// Braille spinner frames for the "waiting for approval" state.
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// How long the simulated device-code approval "takes" before it lands.
const APPROVAL_AFTER: Duration = Duration::from_millis(2400);

/// Where a stored API key came from. Env-sourced keys echo the variable name
/// in the final summary, matching how the product records `$VAR` references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum KeySource {
    Pasted,
    Env(String),
}

/// The credential the flow produced, consumed by [`super::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Credential {
    ApiKey {
        /// The actual secret to send when probing `/models`. Empty means the
        /// request is made anonymously (some providers publish a public list).
        value: String,
        source: KeySource,
        /// Resolved base URL — the provider's, or the one typed for
        /// `openai-compatible`.
        base_url: String,
    },
    /// A simulated subscription login. Carries no real token.
    OAuth { note: String },
}

impl Credential {
    /// One-line description for the post-onboarding summary.
    pub(super) fn summary(&self) -> String {
        match self {
            Credential::ApiKey {
                source: KeySource::Pasted,
                value,
                ..
            } if value.is_empty() => "no key (anonymous)".to_string(),
            Credential::ApiKey {
                source: KeySource::Pasted,
                ..
            } => "API key (pasted)".to_string(),
            Credential::ApiKey {
                source: KeySource::Env(var),
                ..
            } => format!("API key (${var})"),
            Credential::OAuth { .. } => "OAuth login (simulated)".to_string(),
        }
    }
}

/// How the auth step finished. `Back` returns to the provider picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    Ready(Credential),
    Back,
    Quit,
}

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    provider: &'static Provider,
) -> Result<Outcome> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, provider);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    provider: &'static Provider,
) -> Result<Outcome> {
    let mut screen = Screen::new(provider);
    let mut last = Instant::now();
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        let timeout = FRAME.saturating_sub(last.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                    match screen.handle_key(key) {
                        Step::Stay => {}
                        Step::Back => return Ok(Outcome::Back),
                        Step::Quit => return Ok(Outcome::Quit),
                        Step::Done(cred) => return Ok(Outcome::Ready(cred)),
                    }
                }
                Event::Mouse(mouse) => match screen.handle_mouse(mouse) {
                    None | Some(Step::Stay) => {}
                    Some(Step::Back) => return Ok(Outcome::Back),
                    Some(Step::Quit) => return Ok(Outcome::Quit),
                    Some(Step::Done(cred)) => return Ok(Outcome::Ready(cred)),
                },
                Event::Paste(text) => screen.paste(&text),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        let now = Instant::now();
        if now.saturating_duration_since(last) >= FRAME {
            last = now;
            if let Some(cred) = screen.tick() {
                return Ok(Outcome::Ready(cred));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Stay,
    Back,
    Quit,
    Done(Credential),
}

/// Which sub-screen is showing. OAuth providers walk `Acknowledge` → login;
/// API-key providers sit in `ApiKey` the whole time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Acknowledge,
    DeviceIdle,
    DevicePolling,
    PasteCallback,
    ApiKey,
}

/// Focus target on the API-key screen when a base URL is also required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiFocus {
    BaseUrl,
    Key,
}

struct Screen {
    provider: &'static Provider,
    phase: Phase,
    /// Device-code one-time code, shown for `codex-oauth`.
    user_code: String,
    /// When the current polling run started, for the simulated approval timer.
    polling_since: Option<Instant>,
    spinner: usize,
    /// Grok's pasted callback URL/code.
    callback: TextField,
    /// API-key entry, and the base URL when the provider needs one.
    key: TextField,
    base_url: TextField,
    focus: ApiFocus,
    reveal: bool,
    /// Detected environment variable holding a key, if any.
    detected_env: Option<(String, String)>,
    error: Option<String>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
    /// Field rects for click-to-focus on the API-key screen.
    base_rect: Rect,
    key_rect: Rect,
}

/// A clickable action on one of the auth sub-screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Btn {
    Acknowledge,
    StartPoll,
    CancelPoll,
    ApproveNow,
    SubmitCallback,
    ToggleReveal,
    UseEnv,
    SubmitKey,
}

impl Screen {
    fn new(provider: &'static Provider) -> Self {
        let phase = match provider.kind {
            Kind::OAuth => Phase::Acknowledge,
            Kind::ApiKey => Phase::ApiKey,
        };
        let focus = if provider.known_base_url().is_none() {
            ApiFocus::BaseUrl
        } else {
            ApiFocus::Key
        };
        let mut base_url = TextField::new();
        if let Some(url) = provider.known_base_url() {
            base_url.set(url);
        }
        Self {
            provider,
            phase,
            user_code: generate_user_code(),
            polling_since: None,
            spinner: 0,
            callback: TextField::new(),
            key: TextField::new(),
            base_url,
            focus,
            reveal: false,
            detected_env: detect_env(provider),
            error: None,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
            base_rect: Rect::default(),
            key_rect: Rect::default(),
        }
    }

    /// The clickable buttons for the current phase, paired with their action.
    /// The render pass and the click handler both read this, so the on-screen
    /// order and the hit-test order can never drift apart.
    fn action_buttons(&self) -> Vec<(chrome::Button<'static>, Btn)> {
        match self.phase {
            Phase::Acknowledge => {
                vec![(chrome::Button::primary("I acknowledge"), Btn::Acknowledge)]
            }
            Phase::DeviceIdle => vec![(chrome::Button::primary("Open & poll"), Btn::StartPoll)],
            Phase::DevicePolling => vec![
                (chrome::Button::secondary("Cancel"), Btn::CancelPoll),
                (chrome::Button::primary("Approve now"), Btn::ApproveNow),
            ],
            Phase::PasteCallback => {
                vec![(chrome::Button::primary("Continue"), Btn::SubmitCallback)]
            }
            Phase::ApiKey => {
                let mut buttons = vec![(chrome::Button::secondary("Reveal"), Btn::ToggleReveal)];
                if self.detected_env.is_some() {
                    buttons.push((chrome::Button::secondary("Use env var"), Btn::UseEnv));
                }
                buttons.push((chrome::Button::primary("Continue"), Btn::SubmitKey));
                buttons
            }
        }
    }

    /// Render the current phase's buttons on the `help` row and remember their
    /// rects for hit-testing.
    fn render_actions(&mut self, frame: &mut Frame, help: Rect) {
        let specs = self.action_buttons();
        let buttons: Vec<chrome::Button<'_>> = specs
            .iter()
            .map(|(b, _)| chrome::Button {
                label: b.label,
                enabled: b.enabled,
                primary: b.primary,
            })
            .collect();
        self.actions.render(frame, help, &buttons);
    }

    fn run_button(&mut self, button: Btn) -> Step {
        match button {
            Btn::Acknowledge => self.advance_from_acknowledge(),
            Btn::StartPoll => self.start_polling(),
            Btn::CancelPoll => {
                self.phase = Phase::DeviceIdle;
                self.polling_since = None;
                Step::Stay
            }
            Btn::ApproveNow => Step::Done(self.oauth_credential()),
            Btn::SubmitCallback => self.submit_callback(),
            Btn::ToggleReveal => {
                self.reveal = !self.reveal;
                Step::Stay
            }
            Btn::UseEnv => self.use_detected_env(),
            Btn::SubmitKey => self.submit_api_key(),
        }
    }

    /// True when this provider also needs a base URL typed in (only
    /// `openai-compatible`).
    fn needs_base_url(&self) -> bool {
        self.provider.known_base_url().is_none()
    }

    fn resolved_base_url(&self) -> String {
        self.base_url.trimmed().trim_end_matches('/').to_string()
    }

    fn device_code_provider(&self) -> bool {
        // Codex uses the device-code page; other OAuth providers (Grok) paste
        // a browser callback.
        self.provider.id == "codex-oauth"
    }

    fn tick(&mut self) -> Option<Credential> {
        self.spinner = (self.spinner + 1) % SPINNER.len();
        if self.phase == Phase::DevicePolling
            && let Some(since) = self.polling_since
            && since.elapsed() >= APPROVAL_AFTER
        {
            return Some(self.oauth_credential());
        }
        None
    }

    fn oauth_credential(&self) -> Credential {
        Credential::OAuth {
            note: format!(
                "{} subscription (simulated approval)",
                self.provider.display
            ),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Step {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Step::Quit;
        }
        match self.phase {
            Phase::Acknowledge => self.handle_acknowledge(key),
            Phase::DeviceIdle => self.handle_device_idle(key),
            Phase::DevicePolling => self.handle_device_polling(key),
            Phase::PasteCallback => self.handle_paste_callback(key),
            Phase::ApiKey => self.handle_api_key(key),
        }
    }

    fn advance_from_acknowledge(&mut self) -> Step {
        self.phase = if self.device_code_provider() {
            Phase::DeviceIdle
        } else {
            Phase::PasteCallback
        };
        Step::Stay
    }

    fn start_polling(&mut self) -> Step {
        self.phase = Phase::DevicePolling;
        self.polling_since = Some(Instant::now());
        Step::Stay
    }

    fn handle_acknowledge(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Esc => Step::Back,
            KeyCode::Enter => self.advance_from_acknowledge(),
            _ => Step::Stay,
        }
    }

    fn handle_device_idle(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Esc => Step::Back,
            KeyCode::Enter | KeyCode::Char('o') | KeyCode::Char('O') => self.start_polling(),
            _ => Step::Stay,
        }
    }

    fn handle_device_polling(&mut self, key: KeyEvent) -> Step {
        match key.code {
            // Esc cancels the wait and returns to the code screen.
            KeyCode::Esc => {
                self.phase = Phase::DeviceIdle;
                self.polling_since = None;
                Step::Stay
            }
            // Enter short-circuits the simulated approval.
            KeyCode::Enter => Step::Done(self.oauth_credential()),
            _ => Step::Stay,
        }
    }

    fn submit_callback(&mut self) -> Step {
        if self.callback.trimmed().is_empty() {
            self.error = Some("Paste the callback URL or code first.".to_string());
            Step::Stay
        } else {
            Step::Done(self.oauth_credential())
        }
    }

    fn handle_paste_callback(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Esc => Step::Back,
            KeyCode::Enter => self.submit_callback(),
            _ => {
                if self.callback.handle_key(key) {
                    self.error = None;
                }
                Step::Stay
            }
        }
    }

    fn handle_api_key(&mut self, key: KeyEvent) -> Step {
        match key.code {
            KeyCode::Esc => Step::Back,
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.reveal = !self.reveal;
                Step::Stay
            }
            KeyCode::Char('e') | KeyCode::Char('E')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.use_detected_env()
            }
            KeyCode::Tab | KeyCode::BackTab if self.needs_base_url() => {
                self.focus = match self.focus {
                    ApiFocus::BaseUrl => ApiFocus::Key,
                    ApiFocus::Key => ApiFocus::BaseUrl,
                };
                Step::Stay
            }
            KeyCode::Enter => self.submit_api_key(),
            _ => {
                let field = match self.focus {
                    ApiFocus::BaseUrl if self.needs_base_url() => &mut self.base_url,
                    _ => &mut self.key,
                };
                if field.handle_key(key) {
                    self.error = None;
                }
                Step::Stay
            }
        }
    }

    fn use_detected_env(&mut self) -> Step {
        let Some((var, value)) = self.detected_env.clone() else {
            return Step::Stay;
        };
        if self.needs_base_url() && self.resolved_base_url().is_empty() {
            self.error = Some("Enter the base URL before using an env var.".to_string());
            self.focus = ApiFocus::BaseUrl;
            return Step::Stay;
        }
        Step::Done(Credential::ApiKey {
            value,
            source: KeySource::Env(var),
            base_url: self.resolved_base_url(),
        })
    }

    fn submit_api_key(&mut self) -> Step {
        if self.needs_base_url() {
            let url = self.resolved_base_url();
            if url.is_empty() {
                self.error = Some("Enter the provider's base URL.".to_string());
                self.focus = ApiFocus::BaseUrl;
                return Step::Stay;
            }
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                self.error = Some("Base URL must start with http:// or https://.".to_string());
                self.focus = ApiFocus::BaseUrl;
                return Step::Stay;
            }
        }
        Step::Done(Credential::ApiKey {
            value: self.key.trimmed().to_string(),
            source: KeySource::Pasted,
            base_url: self.resolved_base_url(),
        })
    }

    fn paste(&mut self, text: &str) {
        match self.phase {
            Phase::PasteCallback => {
                self.callback.paste(text);
                self.error = None;
            }
            Phase::ApiKey => {
                match self.focus {
                    ApiFocus::BaseUrl if self.needs_base_url() => self.base_url.paste(text),
                    _ => self.key.paste(text),
                }
                self.error = None;
            }
            _ => {}
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Step> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.actions.track(pos);
            return None;
        }
        if !matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
            return None;
        }
        if chrome::hit(self.back_rect, pos) {
            return Some(Step::Back);
        }
        if let Some(index) = self.actions.clicked(pos) {
            let specs = self.action_buttons();
            if let Some((_, button)) = specs.get(index) {
                return Some(self.run_button(*button));
            }
        }
        // Click a field to focus it on the API-key screen.
        if self.phase == Phase::ApiKey {
            if chrome::hit(self.key_rect, pos) {
                self.focus = ApiFocus::Key;
            } else if self.needs_base_url() && chrome::hit(self.base_rect, pos) {
                self.focus = ApiFocus::BaseUrl;
            }
        }
        None
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        // Every auth screen can step back to the picker.
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = column(area);
        match self.phase {
            Phase::Acknowledge => self.render_acknowledge(frame, col),
            Phase::DeviceIdle | Phase::DevicePolling => self.render_device(frame, col),
            Phase::PasteCallback => self.render_paste(frame, col),
            Phase::ApiKey => self.render_api_key(frame, col),
        }
    }

    fn render_acknowledge(&mut self, frame: &mut Frame, area: Rect) {
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(1),
        ]);
        let [header, _, body, help] = area.layout(&layout);
        render_header(
            frame,
            header,
            "Acknowledge the risk",
            &format!("{} signs in with your subscription.", self.provider.display),
        );
        let lines = vec![
            Line::from(Span::styled(
                "Using subscription credentials from a third-party client may violate the provider's terms of service and could get your account suspended.",
                Style::new().fg(WARN),
            )),
            Line::raw(""),
            Line::from(Span::styled(
                "Press Enter to acknowledge and continue, or Esc to go back.",
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            )),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), body);
        render_help(frame, help, "enter I acknowledge   esc back   ^c quit");
        self.render_actions(frame, help);
    }

    fn render_device(&mut self, frame: &mut Frame, area: Rect) {
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(2), // "open this URL"
            Constraint::Length(1), // url
            Constraint::Length(1), // spacer
            Constraint::Length(3), // code box
            Constraint::Length(2), // status / spinner
            Constraint::Min(0),
            Constraint::Length(1),
        ]);
        let [header, _, prompt, url, _, code, status, _, help] = area.layout(&layout);
        render_header(
            frame,
            header,
            "Sign in to your subscription",
            "A device code links this client to your account.",
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Open this URL in a browser and enter the code:",
                Style::new().fg(INK),
            ))),
            prompt,
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.provider.oauth_url,
                Style::new().fg(BRASS).add_modifier(Modifier::UNDERLINED),
            ))),
            url,
        );
        let code_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(" One-time code ", Style::new().fg(FOG)));
        let code_inner = code_block.inner(code);
        frame.render_widget(&code_block, code);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.user_code.clone(),
                Style::new().fg(INK).add_modifier(Modifier::BOLD),
            )))
            .centered(),
            code_inner,
        );

        if self.phase == Phase::DevicePolling {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", SPINNER[self.spinner]),
                        Style::new().fg(BRASS),
                    ),
                    Span::styled(
                        "Waiting for approval… (simulated for this demo)",
                        Style::new().fg(FOG),
                    ),
                ])),
                status,
            );
            render_help(frame, help, "enter approve now   esc cancel   ^c quit");
        } else {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "Press Enter once you've opened the page to start polling.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                ))),
                status,
            );
            render_help(frame, help, "enter open & poll   esc back   ^c quit");
        }
        self.render_actions(frame, help);
    }

    fn render_paste(&mut self, frame: &mut Frame, area: Rect) {
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(2), // instructions
            Constraint::Length(1), // url
            Constraint::Length(1), // spacer
            Constraint::Length(3), // callback field
            Constraint::Length(2), // error/hint
            Constraint::Min(0),
            Constraint::Length(1),
        ]);
        let [header, _, prompt, url, _, field, note, _, help] = area.layout(&layout);
        render_header(
            frame,
            header,
            "Sign in to your subscription",
            "Approve access in the browser, then paste the result back.",
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Open this URL and approve access:",
                Style::new().fg(INK),
            ))),
            prompt,
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.provider.oauth_url,
                Style::new().fg(BRASS).add_modifier(Modifier::UNDERLINED),
            ))),
            url,
        );
        let caret = render_field(
            frame,
            field,
            "Callback URL or code",
            &self.callback,
            true,
            false,
        );
        self.render_note(
            frame,
            note,
            "Paste the callback URL, ?code=…&state=…, or a bare code.",
        );
        render_help(
            frame,
            help,
            "paste callback   enter continue   esc back   ^c quit",
        );
        self.render_actions(frame, help);
        if let Some(pos) = caret {
            frame.set_cursor_position(pos);
        }
    }

    fn render_api_key(&mut self, frame: &mut Frame, area: Rect) {
        let base_rows = if self.needs_base_url() { 3 } else { 0 };
        let layout = Layout::vertical([
            Constraint::Length(3),         // header
            Constraint::Length(1),         // spacer
            Constraint::Length(base_rows), // base URL (optional)
            Constraint::Length(3),         // key field
            Constraint::Length(2),         // env hint / error
            Constraint::Min(0),
            Constraint::Length(1),
        ]);
        let [header, _, base, key, note, _, help] = area.layout(&layout);
        self.base_rect = if self.needs_base_url() {
            base
        } else {
            Rect::default()
        };
        self.key_rect = key;
        render_header(
            frame,
            header,
            "Add your API key",
            &format!("Paste a key for {}.", self.provider.display),
        );

        let mut caret = None;
        if self.needs_base_url() {
            let c = render_field(
                frame,
                base,
                "Base URL",
                &self.base_url,
                self.focus == ApiFocus::BaseUrl,
                false,
            );
            if self.focus == ApiFocus::BaseUrl {
                caret = c;
            }
        }
        let key_caret = render_field(
            frame,
            key,
            "API key",
            &self.key,
            self.focus == ApiFocus::Key,
            !self.reveal,
        );
        if self.focus == ApiFocus::Key {
            caret = key_caret;
        }

        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    error.clone(),
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                ))),
                note,
            );
        } else if let Some((var, _)) = &self.detected_env {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("● ", Style::new().fg(GOOD)),
                    Span::styled(
                        format!("Found ${var} in your environment — press ^E to use it."),
                        Style::new().fg(FOG),
                    ),
                ])),
                note,
            );
        } else {
            let hint = if self.provider.id == "openrouter" {
                "OpenRouter's /models list is public — leave this blank to verify anonymously."
            } else {
                "Input is masked (^R to reveal). Leave blank only if the provider needs no key."
            };
            self.render_note(frame, note, hint);
        }

        let help_text = if self.needs_base_url() {
            "type   tab switch field   ^r reveal   enter continue   esc back"
        } else if self.detected_env.is_some() {
            "type key   ^e use env var   ^r reveal   enter continue   esc back"
        } else {
            "type key   ^r reveal   enter continue   esc back   ^c quit"
        };
        render_help(frame, help, help_text);
        self.render_actions(frame, help);

        if let Some(pos) = caret {
            frame.set_cursor_position(pos);
        }
    }

    fn render_note(&self, frame: &mut Frame, area: Rect, text: &str) {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text.to_string(),
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            )))
            .wrap(Wrap { trim: true }),
            area,
        );
    }
}

/// Detect a usable key in the environment for this provider's default var.
fn detect_env(provider: &Provider) -> Option<(String, String)> {
    let var = provider.env_var?;
    let value = std::env::var(var).ok()?;
    (!value.trim().is_empty()).then(|| (var.to_string(), value))
}

/// A pseudo-random `XXXX-XXXX` device code. Not cryptographic — it only needs
/// to look like the real thing on screen.
fn generate_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut state = seed | 1;
    let mut next = || {
        // xorshift64* — plenty for a display code.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        ALPHABET[((state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as usize) % ALPHABET.len()]
            as char
    };
    let mut code = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        code.push(next());
    }
    code
}

/// Draw a bordered single-line field and return the caret position when it is
/// focused, so the caller can place the real terminal cursor there.
fn render_field(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    field: &TextField,
    focused: bool,
    mask: bool,
) -> Option<Position> {
    let border = if focused { BRASS } else { NIGHT };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border))
        .title(Span::styled(format!(" {title} "), Style::new().fg(border)))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let placeholder = if mask {
        "paste your key"
    } else {
        "https://…"
    };
    let (line, _) = field.render(inner.width, mask, placeholder, INK, PLACEHOLDER);
    frame.render_widget(Paragraph::new(line), inner);

    focused.then(|| field.caret_position(inner)).flatten()
}

fn render_header(frame: &mut Frame, area: Rect, title: &str, subtitle: &str) {
    let rule = "─".repeat(28.min(usize::from(area.width)));
    let lines = vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::new().fg(INK).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(subtitle.to_string(), Style::new().fg(FOG))),
        Line::from(Span::styled(rule, Style::new().fg(BRASS))),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_help(frame: &mut Frame, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_string(),
            Style::new().fg(FOG),
        ))),
        area,
    );
}

fn column(area: Rect) -> Rect {
    area.inner(Margin::new(2, 1))
        .centered(Constraint::Max(86), Constraint::Fill(1))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::onboard::providers::PROVIDERS;

    fn provider(id: &str) -> &'static Provider {
        PROVIDERS.iter().find(|p| p.id == id).unwrap()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn ctrl(ch: char) -> KeyEvent {
        let mut key = KeyEvent::from(KeyCode::Char(ch));
        key.modifiers = KeyModifiers::CONTROL;
        key
    }

    fn type_text(screen: &mut Screen, text: &str) {
        for ch in text.chars() {
            screen.handle_key(key(KeyCode::Char(ch)));
        }
    }

    fn mouse(kind: MouseEventKind, pos: Position) -> MouseEvent {
        MouseEvent {
            kind,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        }
    }

    /// First on-screen position of `needle`, for clicking rendered buttons.
    fn find(backend: &TestBackend, needle: &str) -> Position {
        let buf = backend.buffer();
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            if let Some(col) = row.find(needle) {
                return Position::new(col as u16, y);
            }
        }
        panic!("{needle:?} not found on screen");
    }

    fn click(backend: &TestBackend, screen: &mut Screen, needle: &str) -> Option<Step> {
        let pos = find(backend, needle);
        screen.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos))
    }

    fn draw(screen: &mut Screen, width: u16, height: u16) -> (TestBackend, bool) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area()))
            .unwrap();
        let visible = terminal.backend().cursor_visible();
        (terminal.backend().clone(), visible)
    }

    fn text_of(backend: &TestBackend) -> String {
        let buf = backend.buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn api_key_provider_lands_on_the_key_screen() {
        let screen = Screen::new(provider("openai"));
        assert_eq!(screen.phase, Phase::ApiKey);
        assert_eq!(screen.focus, ApiFocus::Key);
        assert!(!screen.needs_base_url());
    }

    #[test]
    fn oauth_provider_starts_with_the_acknowledgement() {
        let screen = Screen::new(provider("codex-oauth"));
        assert_eq!(screen.phase, Phase::Acknowledge);
    }

    #[test]
    fn esc_from_the_first_screen_steps_back_to_the_picker() {
        let mut screen = Screen::new(provider("openai"));
        assert_eq!(screen.handle_key(key(KeyCode::Esc)), Step::Back);
        let mut oauth = Screen::new(provider("codex-oauth"));
        assert_eq!(oauth.handle_key(key(KeyCode::Esc)), Step::Back);
    }

    #[test]
    fn ctrl_c_quits_from_any_screen() {
        let mut screen = Screen::new(provider("openai"));
        assert_eq!(screen.handle_key(ctrl('c')), Step::Quit);
    }

    #[test]
    fn pasting_a_key_and_pressing_enter_returns_a_pasted_credential() {
        let mut screen = Screen::new(provider("openai"));
        type_text(&mut screen, "sk-live-123");
        let step = screen.handle_key(key(KeyCode::Enter));
        assert_eq!(
            step,
            Step::Done(Credential::ApiKey {
                value: "sk-live-123".to_string(),
                source: KeySource::Pasted,
                base_url: "https://api.openai.com/v1".to_string(),
            })
        );
    }

    #[test]
    fn an_empty_key_is_allowed_for_anonymous_verification() {
        let mut screen = Screen::new(provider("openrouter"));
        let step = screen.handle_key(key(KeyCode::Enter));
        assert_eq!(
            step,
            Step::Done(Credential::ApiKey {
                value: String::new(),
                source: KeySource::Pasted,
                base_url: "https://openrouter.ai/api/v1".to_string(),
            })
        );
    }

    #[test]
    fn openai_compatible_requires_a_valid_base_url() {
        let mut screen = Screen::new(provider("openai-compatible"));
        assert!(screen.needs_base_url());
        assert_eq!(screen.focus, ApiFocus::BaseUrl);
        // Empty base URL is rejected.
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Step::Stay);
        assert!(screen.error.is_some());
        // A bare host without a scheme is rejected.
        type_text(&mut screen, "example.test/v1");
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Step::Stay);
        assert!(screen.error.as_deref().unwrap().contains("http"));
    }

    #[test]
    fn openai_compatible_base_url_and_key_produce_a_credential() {
        let mut screen = Screen::new(provider("openai-compatible"));
        type_text(&mut screen, "https://host.test/v1/");
        screen.handle_key(key(KeyCode::Tab));
        assert_eq!(screen.focus, ApiFocus::Key);
        type_text(&mut screen, "abc");
        assert_eq!(
            screen.handle_key(key(KeyCode::Enter)),
            Step::Done(Credential::ApiKey {
                value: "abc".to_string(),
                source: KeySource::Pasted,
                // Trailing slash is trimmed so the probe hits `…/v1/models`.
                base_url: "https://host.test/v1".to_string(),
            })
        );
    }

    #[test]
    fn ctrl_r_toggles_masking() {
        let mut screen = Screen::new(provider("openai"));
        type_text(&mut screen, "topsecret");
        let (masked, _) = draw(&mut screen, 80, 24);
        assert!(text_of(&masked).contains("•••••••••"));
        assert!(!text_of(&masked).contains("topsecret"));
        screen.handle_key(ctrl('r'));
        let (revealed, _) = draw(&mut screen, 80, 24);
        assert!(text_of(&revealed).contains("topsecret"));
    }

    #[test]
    fn detected_env_var_is_offered_and_ctrl_e_uses_it() {
        // SAFETY: single-threaded test; we set and clear the var ourselves.
        unsafe {
            std::env::set_var("OPENAI_API_KEY", "sk-env-key");
        }
        let mut screen = Screen::new(provider("openai"));
        assert_eq!(
            screen.detected_env,
            Some(("OPENAI_API_KEY".to_string(), "sk-env-key".to_string()))
        );
        let (backend, _) = draw(&mut screen, 80, 24);
        assert!(text_of(&backend).contains("Found $OPENAI_API_KEY"));
        let step = screen.handle_key(ctrl('e'));
        assert_eq!(
            step,
            Step::Done(Credential::ApiKey {
                value: "sk-env-key".to_string(),
                source: KeySource::Env("OPENAI_API_KEY".to_string()),
                base_url: "https://api.openai.com/v1".to_string(),
            })
        );
        unsafe {
            std::env::remove_var("OPENAI_API_KEY");
        }
    }

    #[test]
    fn codex_walks_acknowledge_then_device_code_then_approves() {
        let mut screen = Screen::new(provider("codex-oauth"));
        assert_eq!(screen.phase, Phase::Acknowledge);
        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(screen.phase, Phase::DeviceIdle);
        assert!(screen.device_code_provider());
        // Starting the login begins polling.
        screen.handle_key(key(KeyCode::Enter));
        assert_eq!(screen.phase, Phase::DevicePolling);
        assert!(screen.polling_since.is_some());
        // Enter short-circuits the simulated approval.
        match screen.handle_key(key(KeyCode::Enter)) {
            Step::Done(Credential::OAuth { note }) => assert!(note.contains("Codex")),
            other => panic!("expected an OAuth credential, got {other:?}"),
        }
    }

    #[test]
    fn device_code_screen_shows_the_url_and_a_code() {
        let mut screen = Screen::new(provider("codex-oauth"));
        screen.handle_key(key(KeyCode::Enter)); // acknowledge
        let (backend, _) = draw(&mut screen, 80, 24);
        let text = text_of(&backend);
        assert!(text.contains("auth.openai.com/codex/device"), "{text}");
        assert!(text.contains(&screen.user_code), "{text}");
    }

    #[test]
    fn grok_uses_a_paste_callback_screen() {
        let mut screen = Screen::new(provider("grok-oauth"));
        screen.handle_key(key(KeyCode::Enter)); // acknowledge
        assert_eq!(screen.phase, Phase::PasteCallback);
        assert!(!screen.device_code_provider());
        // Empty paste is rejected.
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Step::Stay);
        assert!(screen.error.is_some());
        type_text(&mut screen, "http://127.0.0.1/callback?code=abc&state=xyz");
        match screen.handle_key(key(KeyCode::Enter)) {
            Step::Done(Credential::OAuth { .. }) => {}
            other => panic!("expected OAuth credential, got {other:?}"),
        }
    }

    #[test]
    fn simulated_device_approval_lands_after_the_timer() {
        let mut screen = Screen::new(provider("codex-oauth"));
        screen.handle_key(key(KeyCode::Enter)); // acknowledge
        screen.handle_key(key(KeyCode::Enter)); // start polling
        // Before the timer elapses, tick keeps waiting.
        assert!(screen.tick().is_none());
        // Force the clock past the approval window.
        screen.polling_since = Some(Instant::now() - APPROVAL_AFTER - Duration::from_millis(1));
        assert!(matches!(screen.tick(), Some(Credential::OAuth { .. })));
    }

    #[test]
    fn generated_codes_look_like_device_codes() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        assert!(
            code.chars()
                .filter(|&c| c != '-')
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn clicking_the_acknowledge_button_advances() {
        let mut screen = Screen::new(provider("codex-oauth"));
        let (backend, _) = draw(&mut screen, 80, 24);
        assert_eq!(screen.phase, Phase::Acknowledge);
        assert_eq!(
            click(&backend, &mut screen, "[ I acknowledge ]"),
            Some(Step::Stay)
        );
        assert_eq!(screen.phase, Phase::DeviceIdle);
    }

    #[test]
    fn clicking_continue_submits_the_api_key() {
        let mut screen = Screen::new(provider("openai"));
        type_text(&mut screen, "sk-live-1");
        let (backend, _) = draw(&mut screen, 80, 24);
        assert_eq!(
            click(&backend, &mut screen, "[ Continue ]"),
            Some(Step::Done(Credential::ApiKey {
                value: "sk-live-1".to_string(),
                source: KeySource::Pasted,
                base_url: "https://api.openai.com/v1".to_string(),
            }))
        );
    }

    #[test]
    fn clicking_reveal_button_toggles_masking() {
        let mut screen = Screen::new(provider("openai"));
        type_text(&mut screen, "topsecret");
        let (backend, _) = draw(&mut screen, 80, 24);
        assert!(!screen.reveal);
        assert_eq!(click(&backend, &mut screen, "[ Reveal ]"), Some(Step::Stay));
        assert!(screen.reveal);
    }

    #[test]
    fn clicking_a_field_moves_focus() {
        let mut screen = Screen::new(provider("openai-compatible"));
        assert_eq!(screen.focus, ApiFocus::BaseUrl);
        let (backend, _) = draw(&mut screen, 80, 24);
        // The key field shows this placeholder while empty; it sits inside the
        // key field's rect, so clicking it must move focus there.
        let pos = find(&backend, "paste your key");
        screen.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos));
        assert_eq!(screen.focus, ApiFocus::Key);
    }

    #[test]
    fn credential_summaries_read_clearly() {
        assert_eq!(
            Credential::ApiKey {
                value: "k".into(),
                source: KeySource::Pasted,
                base_url: "u".into()
            }
            .summary(),
            "API key (pasted)"
        );
        assert_eq!(
            Credential::ApiKey {
                value: String::new(),
                source: KeySource::Pasted,
                base_url: "u".into()
            }
            .summary(),
            "no key (anonymous)"
        );
        assert_eq!(
            Credential::ApiKey {
                value: "k".into(),
                source: KeySource::Env("OPENAI_API_KEY".into()),
                base_url: "u".into()
            }
            .summary(),
            "API key ($OPENAI_API_KEY)"
        );
        assert_eq!(
            Credential::OAuth { note: "x".into() }.summary(),
            "OAuth login (simulated)"
        );
    }
}
