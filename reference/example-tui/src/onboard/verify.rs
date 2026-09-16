//! Step four of onboarding: prove the credential works by fetching `/models`.
//!
//! This mirrors `cockpit_core::providers::models_fetch`: probe
//! `GET {base_url}/models` with the resolved auth header and turn the response
//! into either a model list or a categorized error (rejected credentials,
//! missing endpoint, transport failure, unparsable body).
//!
//! Two things are deliberately faithful to the product:
//!
//! - The probe is **owned off the UI thread**. In Cockpit the daemon runs it;
//!   here a worker thread does, and the event loop shows a spinner and keeps
//!   handling input while it runs. [`Screen`] itself holds no threads, so it is
//!   fully unit-testable — [`run`] owns the worker and feeds outcomes in.
//! - Providers with no `/models` endpoint (`z-ai`, `nous-research`) skip the
//!   probe instead of surfacing a spurious 404.
//!
//! API-key providers hit the network for real. OAuth logins are simulated (see
//! [`super::auth`]), so their verification returns a representative catalog
//! rather than a live call with a token this reference never obtained.

use std::io::Stdout;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};

use super::auth::Credential;
use super::chrome;
use super::providers::{AuthStyle, Provider};

const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
const GOOD: Color = Color::Rgb(0x7F, 0xC9, 0x8A);
const BAD: Color = Color::Rgb(0xE0, 0x6C, 0x6C);

const FRAME: Duration = Duration::from_millis(100);
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// How long the simulated OAuth probe "runs" before its canned list lands, so
/// the spinner reads as real work rather than a flash.
const SIM_DELAY: Duration = Duration::from_millis(900);
/// HTTP timeout for the live probe.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Cap on error-body snippets shown to the user.
const SNIPPET_MAX: usize = 200;

/// A model as understood from a `/models` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModelEntry {
    pub id: String,
    pub display: Option<String>,
}

impl ModelEntry {
    fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display: None,
        }
    }

    fn with_display(id: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display: Some(display.into()),
        }
    }
}

/// The result of one probe attempt, produced by the worker (or simulated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FetchOutcome {
    Models(Vec<ModelEntry>),
    /// 401/403 — the credential was rejected.
    Unauthorized(u16),
    /// 404 — a provider we expected to answer had no model list at that URL
    /// (usually a wrong base URL). Surfaced as an error, not a benign skip.
    NotFound,
    /// Any other non-success status, with a body snippet.
    HttpStatus {
        status: u16,
        snippet: String,
    },
    /// The request never completed (DNS, TLS, connection, timeout).
    Network(String),
    /// The response arrived but could not be parsed as a model list.
    Parse(String),
}

/// How verification concluded, recorded for the post-onboarding summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verification {
    Models(usize),
    NoEndpoint,
}

impl Verification {
    pub(super) fn summary(self) -> String {
        match self {
            Verification::Models(n) => format!("{n} models verified"),
            Verification::NoEndpoint => "no /models endpoint (skipped)".to_string(),
        }
    }
}

/// How the verify step finished. `Next` records the result and either loops
/// back to the picker (`add_another`) or advances to agent creation. The
/// verified model list rides along so the agent step can offer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Done {
    Next {
        verification: Verification,
        models: Vec<ModelEntry>,
        add_another: bool,
    },
    Back,
    Quit,
}

/// What the worker should do to verify this credential.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// No `/models` endpoint; nothing to probe.
    Skip,
    /// OAuth login: return this canned catalog after a short delay.
    Simulated(FetchOutcome),
    /// API key: probe this URL with these headers on a worker thread.
    Live {
        url: String,
        headers: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Fetching,
    Success {
        models: Vec<ModelEntry>,
        offset: usize,
    },
    NoEndpoint,
    Error(FetchOutcome),
}

/// Navigation intent from a key press, resolved by [`run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nav {
    Stay,
    Back,
    Quit,
    Retry,
    Next { add_another: bool },
}

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    provider: &'static Provider,
    credential: &Credential,
) -> Result<Done> {
    let _ = execute_mouse(terminal, true);
    let result = run_loop(terminal, provider, credential);
    let _ = execute_mouse(terminal, false);
    result
}

fn execute_mouse(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    on: bool,
) -> std::io::Result<()> {
    use crossterm::execute;
    if on {
        execute!(terminal.backend_mut(), crossterm::event::EnableMouseCapture)
    } else {
        execute!(
            terminal.backend_mut(),
            crossterm::event::DisableMouseCapture
        )
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    provider: &'static Provider,
    credential: &Credential,
) -> Result<Done> {
    let mut screen = Screen::new(provider, credential);
    let mut worker = Worker::kickoff(&screen.plan);
    let mut last = Instant::now();
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        let timeout = FRAME.saturating_sub(last.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                    match screen.handle_key(key) {
                        Nav::Stay => {}
                        Nav::Back => return Ok(Done::Back),
                        Nav::Quit => return Ok(Done::Quit),
                        Nav::Next { add_another } => {
                            return Ok(Done::Next {
                                verification: screen.verification(),
                                models: screen.verified_models(),
                                add_another,
                            });
                        }
                        Nav::Retry => {
                            screen.retry();
                            worker = Worker::kickoff(&screen.plan);
                        }
                    }
                }
                Event::Mouse(mouse) => match screen.handle_mouse(mouse) {
                    None | Some(Nav::Stay) => {}
                    Some(Nav::Back) => return Ok(Done::Back),
                    Some(Nav::Quit) => return Ok(Done::Quit),
                    Some(Nav::Next { add_another }) => {
                        return Ok(Done::Next {
                            verification: screen.verification(),
                            models: screen.verified_models(),
                            add_another,
                        });
                    }
                    Some(Nav::Retry) => {
                        screen.retry();
                        worker = Worker::kickoff(&screen.plan);
                    }
                },
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        let now = Instant::now();
        if now.saturating_duration_since(last) >= FRAME {
            last = now;
            screen.tick_spinner();
            if screen.is_fetching()
                && let Some(outcome) = worker.poll()
            {
                screen.apply(outcome);
            }
        }
    }
}

/// Owns the pending probe: a live worker thread, or a simulated deadline.
enum Worker {
    Idle,
    Live(Receiver<FetchOutcome>),
    Simulated {
        outcome: FetchOutcome,
        ready_at: Instant,
    },
}

impl Worker {
    fn kickoff(plan: &Plan) -> Self {
        match plan {
            Plan::Skip => Worker::Idle,
            Plan::Simulated(outcome) => Worker::Simulated {
                outcome: outcome.clone(),
                ready_at: Instant::now() + SIM_DELAY,
            },
            Plan::Live { url, headers } => {
                let (tx, rx) = std::sync::mpsc::channel();
                let url = url.clone();
                let headers = headers.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(fetch_models(&url, &headers));
                });
                Worker::Live(rx)
            }
        }
    }

    /// Non-blocking: the outcome once it is ready, else `None`.
    fn poll(&mut self) -> Option<FetchOutcome> {
        match self {
            Worker::Idle => None,
            Worker::Simulated { outcome, ready_at } => {
                (Instant::now() >= *ready_at).then(|| outcome.clone())
            }
            Worker::Live(rx) => match rx.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(FetchOutcome::Network(
                    "probe worker stopped unexpectedly".to_string(),
                )),
            },
        }
    }
}

struct Screen {
    provider: &'static Provider,
    plan: Plan,
    phase: Phase,
    spinner: usize,
    /// Inner list height from the last draw, for paging.
    view_h: usize,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new(provider: &'static Provider, credential: &Credential) -> Self {
        let plan = build_plan(provider, credential);
        let phase = match &plan {
            Plan::Skip => Phase::NoEndpoint,
            _ => Phase::Fetching,
        };
        Self {
            provider,
            plan,
            phase,
            spinner: 0,
            view_h: 8,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    /// Buttons for the current phase, paired with the nav they trigger.
    fn action_buttons(&self) -> Vec<(chrome::Button<'static>, Nav)> {
        match &self.phase {
            Phase::Fetching => Vec::new(),
            Phase::Success { .. } | Phase::NoEndpoint => vec![
                (
                    chrome::Button::secondary("Add another"),
                    Nav::Next { add_another: true },
                ),
                (
                    chrome::Button::primary("Done"),
                    Nav::Next { add_another: false },
                ),
            ],
            Phase::Error(_) => vec![(chrome::Button::primary("Retry"), Nav::Retry)],
        }
    }

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

    fn is_fetching(&self) -> bool {
        self.phase == Phase::Fetching
    }

    fn tick_spinner(&mut self) {
        if self.is_fetching() {
            self.spinner = (self.spinner + 1) % SPINNER.len();
        }
    }

    fn apply(&mut self, outcome: FetchOutcome) {
        // Providers that genuinely have no `/models` endpoint are `Plan::Skip`
        // and land on `NoEndpoint` at construction. A live probe only reaches
        // here for a provider we expected to answer, so a 404 is a real error
        // (usually a wrong base URL), not a benign "no endpoint" outcome.
        self.phase = match outcome {
            FetchOutcome::Models(models) => Phase::Success { models, offset: 0 },
            other => Phase::Error(other),
        };
    }

    fn retry(&mut self) {
        if !matches!(self.plan, Plan::Skip) {
            self.phase = Phase::Fetching;
            self.spinner = 0;
        }
    }

    fn verification(&self) -> Verification {
        match &self.phase {
            Phase::Success { models, .. } => Verification::Models(models.len()),
            _ => Verification::NoEndpoint,
        }
    }

    /// The model list to hand forward to agent creation. Empty unless the
    /// probe (live or simulated) actually returned a catalog.
    fn verified_models(&self) -> Vec<ModelEntry> {
        match &self.phase {
            Phase::Success { models, .. } => models.clone(),
            _ => Vec::new(),
        }
    }

    /// The URL shown while probing / on error.
    fn probe_url(&self) -> String {
        match &self.plan {
            Plan::Live { url, .. } => url.clone(),
            _ => format!("{}/models", self.provider.base_url.trim_end_matches('/')),
        }
    }

    fn scroll(&mut self, delta: isize) {
        // Clamp so the last page stays full: stopping at `len - 1` would let
        // the list scroll until a single model sits above blank rows.
        let view_h = self.view_h;
        if let Phase::Success { models, offset } = &mut self.phase {
            let max = models.len().saturating_sub(view_h);
            let next = (*offset as isize + delta).clamp(0, max as isize);
            *offset = next as usize;
        }
    }

    fn page(&mut self, down: bool) {
        let step = self.view_h.max(1) as isize;
        self.scroll(if down { step } else { -step });
    }

    fn handle_key(&mut self, key: KeyEvent) -> Nav {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Nav::Quit;
        }
        match &self.phase {
            Phase::Fetching => match key.code {
                KeyCode::Esc => Nav::Back,
                _ => Nav::Stay,
            },
            Phase::Success { .. } => match key.code {
                KeyCode::Esc => Nav::Back,
                KeyCode::Char('a') | KeyCode::Char('A') => Nav::Next { add_another: true },
                KeyCode::Enter => Nav::Next { add_another: false },
                KeyCode::Up | KeyCode::Char('k') => {
                    self.scroll(-1);
                    Nav::Stay
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.scroll(1);
                    Nav::Stay
                }
                KeyCode::PageUp => {
                    self.page(false);
                    Nav::Stay
                }
                KeyCode::PageDown => {
                    self.page(true);
                    Nav::Stay
                }
                KeyCode::Home => {
                    self.scroll(isize::MIN / 2);
                    Nav::Stay
                }
                KeyCode::End => {
                    self.scroll(isize::MAX / 2);
                    Nav::Stay
                }
                _ => Nav::Stay,
            },
            Phase::NoEndpoint => match key.code {
                KeyCode::Esc => Nav::Back,
                KeyCode::Char('a') | KeyCode::Char('A') => Nav::Next { add_another: true },
                KeyCode::Enter => Nav::Next { add_another: false },
                _ => Nav::Stay,
            },
            Phase::Error(_) => match key.code {
                KeyCode::Esc => Nav::Back,
                KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => Nav::Retry,
                _ => Nav::Stay,
            },
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        match event.kind {
            MouseEventKind::ScrollUp => self.scroll(-1),
            MouseEventKind::ScrollDown => self.scroll(1),
            MouseEventKind::Moved | MouseEventKind::Drag(_) => self.actions.track(pos),
            MouseEventKind::Down(MouseButton::Left) => {
                if chrome::hit(self.back_rect, pos) {
                    return Some(Nav::Back);
                }
                if let Some(index) = self.actions.clicked(pos) {
                    let specs = self.action_buttons();
                    if let Some((_, nav)) = specs.get(index) {
                        return Some(*nav);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = column(area);
        match &self.phase {
            Phase::Fetching => self.render_fetching(frame, col),
            Phase::Success { .. } => self.render_success(frame, col),
            Phase::NoEndpoint => self.render_no_endpoint(frame, col),
            Phase::Error(_) => self.render_error(frame, col),
        }
    }

    fn render_fetching(&self, frame: &mut Frame, area: Rect) {
        let [header, _, body, help] = area.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(1),
        ]));
        render_header(
            frame,
            header,
            "Verifying your credential",
            &format!("Checking {}.", self.provider.display),
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("{} ", SPINNER[self.spinner]),
                        Style::new().fg(BRASS),
                    ),
                    Span::styled("Fetching ", Style::new().fg(INK)),
                    Span::styled(self.probe_url(), Style::new().fg(FOG)),
                ]),
                Line::raw(""),
                Line::from(Span::styled(
                    "This talks to the provider directly and only reads the model list.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                )),
            ])
            .wrap(Wrap { trim: true }),
            body,
        );
        render_help(frame, help, "esc cancel   ^c quit");
    }

    fn render_success(&mut self, frame: &mut Frame, area: Rect) {
        let Phase::Success { models, offset } = &self.phase else {
            return;
        };
        let [header, _, list, help] = area.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ]));
        let count = models.len();
        render_header(
            frame,
            header,
            "✓ Connected",
            &format!(
                "{} · {count} model{} available",
                self.provider.display,
                if count == 1 { "" } else { "s" }
            ),
        );

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(GOOD))
            .title(Span::styled(" Models ", Style::new().fg(GOOD)));
        let inner = block.inner(list);
        frame.render_widget(&block, list);
        self.view_h = usize::from(inner.height).max(1);

        let offset = (*offset).min(count.saturating_sub(usize::from(inner.height)));
        let overflow = count > usize::from(inner.height);
        let (rows_area, bar_area) = if overflow && inner.width >= 2 {
            let [rows, bar] = inner.layout(&Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(1),
            ]));
            (rows, Some(bar))
        } else {
            (inner, None)
        };

        let lines: Vec<Line> = models
            .iter()
            .skip(offset)
            .take(usize::from(rows_area.height))
            .map(|model| {
                let mut spans = vec![
                    Span::styled("• ", Style::new().fg(GOOD)),
                    Span::styled(model.id.clone(), Style::new().fg(INK)),
                ];
                if let Some(display) = &model.display {
                    spans.push(Span::styled(format!("  {display}"), Style::new().fg(FOG)));
                }
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), rows_area);

        if let Some(bar_area) = bar_area {
            render_scrollbar(
                frame,
                bar_area,
                count,
                usize::from(rows_area.height),
                offset,
            );
        }

        render_help(
            frame,
            help,
            "↑↓ scroll   a add another   enter done   esc back   ^c quit",
        );
        self.render_actions(frame, help);
    }

    fn render_no_endpoint(&mut self, frame: &mut Frame, area: Rect) {
        let [header, _, body, help] = area.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(1),
        ]));
        render_header(
            frame,
            header,
            "Credential stored",
            &format!("{} has no public /models endpoint.", self.provider.display),
        );
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "There is no model list to fetch, so the live check is skipped. Cockpit would confirm this credential with a minimal chat request instead.",
                    Style::new().fg(FOG),
                )),
                Line::raw(""),
                Line::from(Span::styled(
                    "The credential is saved and ready to use.",
                    Style::new().fg(GOOD),
                )),
            ])
            .wrap(Wrap { trim: true }),
            body,
        );
        render_help(
            frame,
            help,
            "a add another   enter done   esc back   ^c quit",
        );
        self.render_actions(frame, help);
    }

    fn render_error(&mut self, frame: &mut Frame, area: Rect) {
        let Phase::Error(outcome) = &self.phase else {
            return;
        };
        let [header, _, body, help] = area.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ]));
        let (title, detail, remedy) = describe_error(outcome, &self.probe_url());
        render_header_colored(frame, header, "✗ Couldn't verify", &title, BAD);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(detail, Style::new().fg(INK))),
                Line::raw(""),
                Line::from(Span::styled(
                    remedy,
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                )),
            ])
            .wrap(Wrap { trim: true }),
            body,
        );
        render_help(frame, help, "r retry   esc back   ^c quit");
        self.render_actions(frame, help);
    }
}

/// Turn a failure into a headline, a one-line detail, and a remedy hint.
fn describe_error(outcome: &FetchOutcome, url: &str) -> (String, String, String) {
    match outcome {
        FetchOutcome::Unauthorized(status) => (
            format!("Credentials rejected ({status})"),
            format!("{url} refused the request."),
            "Check the API key, OAuth login, and any required headers, then retry.".to_string(),
        ),
        FetchOutcome::HttpStatus { status, snippet } => (
            format!("Provider returned {status}"),
            if snippet.is_empty() {
                format!("{url} responded with HTTP {status}.")
            } else {
                format!("{url} responded with HTTP {status}: {snippet}")
            },
            "This is usually a transient or upstream issue — retry in a moment.".to_string(),
        ),
        FetchOutcome::Network(message) => (
            "Couldn't reach the provider".to_string(),
            format!("The request to {url} never completed: {message}"),
            "Check your network connection and the base URL, then retry.".to_string(),
        ),
        FetchOutcome::Parse(message) => (
            "Unexpected response".to_string(),
            format!("{url} replied, but the model list couldn't be read: {message}"),
            "The endpoint may not be OpenAI-compatible. Verify the base URL, then retry."
                .to_string(),
        ),
        FetchOutcome::NotFound => (
            "No model list at that URL (404)".to_string(),
            format!("{url} returned 404 — the base URL is likely wrong or missing its API path."),
            "Check the base URL (many providers need a /v1 suffix), then retry.".to_string(),
        ),
        // Success never reaches the error screen.
        FetchOutcome::Models(_) => (
            "Verification failed".to_string(),
            format!("{url} could not be verified."),
            "Retry, or step back and adjust the credential.".to_string(),
        ),
    }
}

/// Build the verification plan from the provider and the entered credential.
fn build_plan(provider: &Provider, credential: &Credential) -> Plan {
    if !provider.supports_models {
        return Plan::Skip;
    }
    match credential {
        // OAuth is simulated end to end (see `auth`), so return a canned list.
        Credential::OAuth { .. } => {
            Plan::Simulated(FetchOutcome::Models(simulated_catalog(provider)))
        }
        Credential::ApiKey {
            value, base_url, ..
        } => {
            let base = if base_url.is_empty() {
                provider.base_url
            } else {
                base_url.as_str()
            };
            let url = format!("{}/models", base.trim_end_matches('/'));
            Plan::Live {
                url,
                headers: auth_headers(provider.auth_style, value),
            }
        }
    }
}

/// Auth headers for the probe, matching the provider's wire style. An empty
/// key means an anonymous request (some `/models` lists are public).
fn auth_headers(style: AuthStyle, key: &str) -> Vec<(String, String)> {
    let key = key.trim();
    match style {
        AuthStyle::Bearer => {
            if key.is_empty() {
                Vec::new()
            } else {
                vec![("Authorization".to_string(), format!("Bearer {key}"))]
            }
        }
        AuthStyle::Anthropic => {
            let mut headers = vec![("anthropic-version".to_string(), "2023-06-01".to_string())];
            if !key.is_empty() {
                headers.push(("x-api-key".to_string(), key.to_string()));
            }
            headers
        }
    }
}

/// The live probe. Runs on a worker thread; never touches the UI.
fn fetch_models(url: &str, headers: &[(String, String)]) -> FetchOutcome {
    let agent = ureq::AgentBuilder::new().timeout(HTTP_TIMEOUT).build();
    let mut request = agent
        .get(url)
        .set("Accept", "application/json")
        .set("User-Agent", "excoc-onboarding-example");
    for (name, value) in headers {
        request = request.set(name, value);
    }
    match request.call() {
        Ok(response) => match response.into_string() {
            Ok(body) => match parse_models_body(&body) {
                Ok(models) => FetchOutcome::Models(models),
                Err(message) => FetchOutcome::Parse(message),
            },
            Err(error) => FetchOutcome::Network(error.to_string()),
        },
        Err(ureq::Error::Status(status, response)) => {
            let snippet = response
                .into_string()
                .map(|body| snippet(&body))
                .unwrap_or_default();
            match status {
                401 | 403 => FetchOutcome::Unauthorized(status),
                404 => FetchOutcome::NotFound,
                _ => FetchOutcome::HttpStatus { status, snippet },
            }
        }
        Err(ureq::Error::Transport(transport)) => FetchOutcome::Network(transport.to_string()),
    }
}

/// Parse an OpenAI-compatible `/models` body: a bare array, or an object with
/// a `data` or `models` array. Each entry is a string id or an object carrying
/// `id`/`slug` and optionally a display name.
fn parse_models_body(body: &str) -> Result<Vec<ModelEntry>, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("invalid JSON ({error})"))?;
    let array = value
        .as_array()
        .or_else(|| value.get("data").and_then(|d| d.as_array()))
        .or_else(|| value.get("models").and_then(|m| m.as_array()))
        .ok_or_else(|| "no model array in response".to_string())?;

    let mut models = Vec::new();
    for entry in array {
        if let Some(id) = entry.as_str() {
            models.push(ModelEntry::new(id));
            continue;
        }
        let Some(id) = entry
            .get("id")
            .or_else(|| entry.get("slug"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let display = entry
            .get("display_name")
            .or_else(|| entry.get("name"))
            .and_then(|v| v.as_str())
            .filter(|name| *name != id)
            .map(str::to_string);
        models.push(match display {
            Some(display) => ModelEntry::with_display(id, display),
            None => ModelEntry::new(id),
        });
    }

    if models.is_empty() {
        return Err("the response listed no models".to_string());
    }
    Ok(models)
}

/// Representative catalogs for the simulated OAuth logins.
fn simulated_catalog(provider: &Provider) -> Vec<ModelEntry> {
    match provider.id {
        "codex-oauth" => vec![
            ModelEntry::with_display("gpt-5.5", "GPT-5.5"),
            ModelEntry::with_display("gpt-5.4", "GPT-5.4"),
            ModelEntry::with_display("gpt-5.4-mini", "GPT-5.4 mini"),
        ],
        "grok-oauth" => vec![
            ModelEntry::with_display("grok-4", "Grok 4"),
            ModelEntry::with_display("grok-4-fast", "Grok 4 Fast"),
            ModelEntry::with_display("grok-code-fast-1", "Grok Code Fast 1"),
        ],
        _ => vec![ModelEntry::new("default")],
    }
}

fn snippet(body: &str) -> String {
    let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > SNIPPET_MAX {
        let mut cut: String = flat.chars().take(SNIPPET_MAX).collect();
        cut.push('…');
        cut
    } else {
        flat
    }
}

/// Hand-drawn scrollbar thumb, sized to the visible fraction of the list.
fn render_scrollbar(frame: &mut Frame, area: Rect, total: usize, view_h: usize, offset: usize) {
    let track = usize::from(area.height);
    if track == 0 {
        return;
    }
    let (start, len) = if total <= view_h {
        (0, track)
    } else {
        let len = ((track * view_h + total / 2) / total).clamp(1, track.saturating_sub(1).max(1));
        let travel = track - len;
        let max_offset = total - view_h;
        (offset.min(max_offset) * travel / max_offset, len)
    };
    let buf = frame.buffer_mut();
    for row in 0..track {
        let (symbol, style) = if (start..start + len).contains(&row) {
            ("█", Style::new().fg(BRASS))
        } else {
            ("│", Style::new().fg(NIGHT))
        };
        buf.set_string(area.x, area.y + row as u16, symbol, style);
    }
}

fn render_header(frame: &mut Frame, area: Rect, title: &str, subtitle: &str) {
    render_header_colored(frame, area, title, subtitle, INK);
}

fn render_header_colored(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    subtitle: &str,
    title_fg: Color,
) {
    let rule = "─".repeat(28.min(usize::from(area.width)));
    let lines = vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::new().fg(title_fg).add_modifier(Modifier::BOLD),
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
    use crate::onboard::auth::KeySource;
    use crate::onboard::providers::PROVIDERS;

    fn provider(id: &str) -> &'static Provider {
        PROVIDERS.iter().find(|p| p.id == id).unwrap()
    }

    fn api_key(value: &str, base_url: &str) -> Credential {
        Credential::ApiKey {
            value: value.to_string(),
            source: KeySource::Pasted,
            base_url: base_url.to_string(),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn mouse(kind: MouseEventKind, pos: Position) -> MouseEvent {
        MouseEvent {
            kind,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        }
    }

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

    fn click(backend: &TestBackend, screen: &mut Screen, needle: &str) -> Option<Nav> {
        let pos = find(backend, needle);
        screen.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos))
    }

    fn draw(screen: &mut Screen, width: u16, height: u16) -> TestBackend {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area()))
            .unwrap();
        terminal.backend().clone()
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
    fn parses_openai_style_data_object() {
        let body = r#"{"object":"list","data":[{"id":"gpt-5"},{"id":"o4-mini"}]}"#;
        let models = parse_models_body(body).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "gpt-5");
        assert_eq!(models[1].id, "o4-mini");
    }

    #[test]
    fn parses_a_bare_array_and_string_entries() {
        let models = parse_models_body(r#"["a","b","c"]"#).unwrap();
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn parses_a_models_array_with_display_names_and_slugs() {
        let body =
            r#"{"models":[{"slug":"claude","display_name":"Claude"},{"id":"x","name":"x"}]}"#;
        let models = parse_models_body(body).unwrap();
        assert_eq!(models[0].id, "claude");
        assert_eq!(models[0].display.as_deref(), Some("Claude"));
        // A name equal to the id is not a useful display string.
        assert_eq!(models[1].id, "x");
        assert_eq!(models[1].display, None);
    }

    #[test]
    fn rejects_invalid_json_and_empty_lists() {
        assert!(parse_models_body("not json").unwrap_err().contains("JSON"));
        assert!(parse_models_body(r#"{"data":[]}"#).is_err());
        assert!(
            parse_models_body(r#"{"nope":1}"#)
                .unwrap_err()
                .contains("model array")
        );
    }

    #[test]
    fn bearer_header_is_omitted_when_the_key_is_empty() {
        assert_eq!(auth_headers(AuthStyle::Bearer, ""), Vec::new());
        assert_eq!(
            auth_headers(AuthStyle::Bearer, "sk-123"),
            vec![("Authorization".to_string(), "Bearer sk-123".to_string())]
        );
    }

    #[test]
    fn anthropic_headers_always_pin_the_version() {
        let headers = auth_headers(AuthStyle::Anthropic, "key");
        assert!(headers.contains(&("anthropic-version".to_string(), "2023-06-01".to_string())));
        assert!(headers.contains(&("x-api-key".to_string(), "key".to_string())));
        // Without a key, only the version header is sent.
        assert_eq!(
            auth_headers(AuthStyle::Anthropic, ""),
            vec![("anthropic-version".to_string(), "2023-06-01".to_string())]
        );
    }

    #[test]
    fn api_key_provider_plans_a_live_probe_at_models() {
        let screen = Screen::new(provider("openai"), &api_key("sk-1", ""));
        assert!(matches!(
            &screen.plan,
            Plan::Live { url, .. } if url == "https://api.openai.com/v1/models"
        ));
        assert_eq!(screen.phase, Phase::Fetching);
    }

    #[test]
    fn openai_compatible_uses_the_typed_base_url() {
        let screen = Screen::new(
            provider("openai-compatible"),
            &api_key("k", "https://host.test/v1"),
        );
        assert!(matches!(
            &screen.plan,
            Plan::Live { url, .. } if url == "https://host.test/v1/models"
        ));
    }

    #[test]
    fn providers_without_models_skip_straight_to_no_endpoint() {
        let screen = Screen::new(provider("nous-research"), &api_key("k", ""));
        assert_eq!(screen.plan, Plan::Skip);
        assert_eq!(screen.phase, Phase::NoEndpoint);
    }

    #[test]
    fn oauth_credentials_plan_a_simulated_catalog() {
        let cred = Credential::OAuth {
            note: "x".to_string(),
        };
        let screen = Screen::new(provider("codex-oauth"), &cred);
        match &screen.plan {
            Plan::Simulated(FetchOutcome::Models(models)) => {
                assert!(models.iter().any(|m| m.id == "gpt-5.5"));
            }
            other => panic!("expected a simulated catalog, got {other:?}"),
        }
    }

    #[test]
    fn success_screen_lists_models_and_offers_next_steps() {
        let mut screen = Screen::new(provider("openai"), &api_key("sk", ""));
        screen.apply(FetchOutcome::Models(vec![
            ModelEntry::new("gpt-5"),
            ModelEntry::with_display("o4-mini", "o4 mini"),
        ]));
        let backend = draw(&mut screen, 80, 24);
        let text = text_of(&backend);
        assert!(text.contains("✓ Connected"), "{text}");
        assert!(text.contains("2 models available"), "{text}");
        assert!(text.contains("gpt-5"), "{text}");
        assert!(text.contains("o4 mini"), "{text}");
        assert_eq!(screen.verification(), Verification::Models(2));
    }

    #[test]
    fn enter_finishes_and_a_adds_another_from_success() {
        let mut screen = Screen::new(provider("openai"), &api_key("sk", ""));
        screen.apply(FetchOutcome::Models(vec![ModelEntry::new("m")]));
        assert_eq!(
            screen.handle_key(key(KeyCode::Enter)),
            Nav::Next { add_another: false }
        );
        assert_eq!(
            screen.handle_key(key(KeyCode::Char('a'))),
            Nav::Next { add_another: true }
        );
    }

    #[test]
    fn clicking_done_and_add_another_finish_from_success() {
        let mut screen = Screen::new(provider("openai"), &api_key("sk", ""));
        screen.apply(FetchOutcome::Models(vec![ModelEntry::new("m")]));
        let backend = draw(&mut screen, 80, 24);
        assert_eq!(
            click(&backend, &mut screen, "[ Done ]"),
            Some(Nav::Next { add_another: false })
        );
        assert_eq!(
            click(&backend, &mut screen, "[ Add another ]"),
            Some(Nav::Next { add_another: true })
        );
    }

    #[test]
    fn clicking_retry_restarts_the_probe() {
        let mut screen = Screen::new(provider("openai"), &api_key("bad", ""));
        screen.apply(FetchOutcome::Unauthorized(401));
        let backend = draw(&mut screen, 80, 24);
        assert_eq!(click(&backend, &mut screen, "[ Retry ]"), Some(Nav::Retry));
    }

    #[test]
    fn unauthorized_shows_a_rejected_message_and_retry() {
        let mut screen = Screen::new(provider("openai"), &api_key("bad", ""));
        screen.apply(FetchOutcome::Unauthorized(401));
        let backend = draw(&mut screen, 80, 24);
        let text = text_of(&backend);
        assert!(text.contains("✗ Couldn't verify"), "{text}");
        assert!(text.contains("Credentials rejected (401)"), "{text}");
        assert!(text.contains("retry"), "{text}");
        // Enter and 'r' both retry, returning to the fetching phase.
        assert_eq!(screen.handle_key(key(KeyCode::Char('r'))), Nav::Retry);
        screen.retry();
        assert_eq!(screen.phase, Phase::Fetching);
    }

    #[test]
    fn network_and_parse_errors_read_clearly() {
        let mut screen = Screen::new(provider("openai"), &api_key("k", ""));
        screen.apply(FetchOutcome::Network("dns error".to_string()));
        assert!(text_of(&draw(&mut screen, 80, 24)).contains("Couldn't reach the provider"));
        screen.apply(FetchOutcome::Parse("invalid JSON".to_string()));
        assert!(text_of(&draw(&mut screen, 80, 24)).contains("Unexpected response"));
    }

    #[test]
    fn live_404_is_an_error_not_a_skip() {
        // `openai` supports models, so a 404 from its live probe means the URL
        // was wrong — surface it as an error the user can fix, not a stored
        // "no endpoint" success.
        let mut screen = Screen::new(provider("openai"), &api_key("k", ""));
        screen.apply(FetchOutcome::NotFound);
        assert!(matches!(
            &screen.phase,
            Phase::Error(FetchOutcome::NotFound)
        ));
        let backend = draw(&mut screen, 80, 24);
        assert!(text_of(&backend).contains("404"));
    }

    #[test]
    fn scrolling_stays_within_the_model_list() {
        let mut screen = Screen::new(provider("openai"), &api_key("k", ""));
        // Default view height is 8, so 20 models leave a max offset of 12 and
        // the final page stays full rather than scrolling to a lone last row.
        assert_eq!(screen.view_h, 8);
        let models: Vec<ModelEntry> = (0..20).map(|i| ModelEntry::new(format!("m{i}"))).collect();
        screen.apply(FetchOutcome::Models(models));
        screen.scroll(-1);
        assert!(matches!(&screen.phase, Phase::Success { offset: 0, .. }));
        screen.scroll(5);
        assert!(matches!(&screen.phase, Phase::Success { offset: 5, .. }));
        screen.scroll(1000);
        assert!(matches!(&screen.phase, Phase::Success { offset: 12, .. }));
    }

    #[test]
    fn esc_steps_back_from_any_phase() {
        let mut screen = Screen::new(provider("openai"), &api_key("k", ""));
        assert_eq!(screen.handle_key(key(KeyCode::Esc)), Nav::Back); // fetching
        screen.apply(FetchOutcome::Unauthorized(401));
        assert_eq!(screen.handle_key(key(KeyCode::Esc)), Nav::Back); // error
    }

    #[test]
    fn no_endpoint_screen_lets_you_continue() {
        let mut screen = Screen::new(provider("z-ai"), &api_key("k", ""));
        let backend = draw(&mut screen, 80, 24);
        assert!(text_of(&backend).contains("no public /models endpoint"));
        assert_eq!(
            screen.handle_key(key(KeyCode::Enter)),
            Nav::Next { add_another: false }
        );
    }

    #[test]
    fn snippet_flattens_and_truncates() {
        let long = "x ".repeat(300);
        let out = snippet(&long);
        assert!(out.chars().count() <= SNIPPET_MAX + 1);
        assert!(out.ends_with('…'));
        assert_eq!(snippet("  a\n  b  "), "a b");
    }

    #[test]
    fn worker_simulated_delivers_after_its_delay() {
        let mut worker = Worker::Simulated {
            outcome: FetchOutcome::Models(vec![ModelEntry::new("m")]),
            ready_at: Instant::now() - Duration::from_millis(1),
        };
        assert!(matches!(worker.poll(), Some(FetchOutcome::Models(_))));
    }

    #[test]
    fn worker_skip_never_delivers() {
        let mut worker = Worker::kickoff(&Plan::Skip);
        assert!(worker.poll().is_none());
    }
}
