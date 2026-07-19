use super::*;

pub(super) fn render_copilot_body(lines: &mut Vec<Line<'static>>, s: &CopilotSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let green = Style::default().fg(Color::Green);
    let cyan = Style::default().fg(Color::Cyan);

    if let Some(outcome) = &s.outcome {
        match outcome {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), green))),
            Err(e) => lines.push(Line::from(Span::styled(format!("Failed: {e}"), red))),
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Press Enter to continue.".to_string(),
            muted,
        )));
        return;
    }

    match (s.shell, &s.rc_path, s.already_configured) {
        (Some(shell), Some(rc_path), false) => {
            lines.push(Line::from(Span::styled(
                format!("Detected shell: {}", shell.name()),
                muted,
            )));
            lines.push(Line::from(vec![
                Span::styled("Will append to: ".to_string(), muted),
                Span::styled(rc_path.display().to_string(), cyan),
            ]));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Lines to be added:".to_string(),
                muted,
            )));
            for line in copilot_setup::append_block(shell).lines() {
                if line.is_empty() {
                    lines.push(Line::default());
                } else {
                    lines.push(Line::from(Span::styled(format!("    {line}"), cyan)));
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "We'll also run `gh auth token` once and set GH_TOKEN in this cockpit session so Copilot works without restarting.".to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter to apply, Esc to cancel.".to_string(),
                yellow,
            )));
        }
        (Some(shell), Some(rc_path), true) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "{} already contains the cockpit Copilot-auth export.",
                    rc_path.display()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!(
                    "To re-apply: remove the marker block from your {} and try again.",
                    shell.rc_filename()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
        _ => {
            lines.push(Line::from(Span::styled(
                "Couldn't detect a supported shell ($SHELL is unset, or it's not zsh/bash/fish). Set GH_TOKEN manually with one of:".to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  POSIX shell (zsh/bash/sh):".to_string(),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                "    export GH_TOKEN=$(gh auth token)".to_string(),
                cyan,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("  fish:".to_string(), muted)));
            lines.push(Line::from(Span::styled(
                "    set -Ux GH_TOKEN (gh auth token)".to_string(),
                cyan,
            )));
            if cfg!(windows) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  Windows PowerShell ($PROFILE):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    $env:GH_TOKEN = (gh auth token)".to_string(),
                    cyan,
                )));
                lines.push(Line::from(Span::styled(
                    "  Windows persistent (User scope):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    [Environment]::SetEnvironmentVariable(\"GH_TOKEN\", (gh auth token), \"User\")".to_string(),
                    cyan,
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthProvider {
    Grok,
    Codex,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthFlowRequest {
    pub(crate) provider: OAuthProvider,
    pub(crate) op: OAuthFlowOp,
}

#[derive(Debug, Clone)]
pub(crate) enum OAuthFlowOp {
    Begin,
    Poll(codex_oauth::DeviceLogin),
    Complete {
        login: xai_oauth::ManualLogin,
        input: String,
    },
    Cancel,
}

#[derive(Debug, Clone)]
pub(crate) enum OAuthBeginResult {
    Device(Result<codex_oauth::DeviceLogin, String>),
    Browser(Result<OAuthBrowserBegin, String>),
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthBrowserBegin {
    pub(crate) login: xai_oauth::ManualLogin,
    listening: bool,
    browser_error: Option<String>,
    listener_error: Option<String>,
    ssh: bool,
}

pub(crate) struct GrokBrowserStart {
    pub(crate) begin: OAuthBrowserBegin,
    pub(crate) listener: Option<tokio::net::TcpListener>,
}

#[derive(Clone, Copy)]
pub(crate) struct OAuthEffects {
    pub(super) copy: fn(&str) -> Result<crate::clipboard::CopyOutcome, crate::clipboard::CopyError>,
    pub(super) is_ssh: fn() -> bool,
    pub(super) open: fn(&str) -> anyhow::Result<()>,
    pub(super) bind: fn(u16) -> anyhow::Result<tokio::net::TcpListener>,
}

impl OAuthEffects {
    pub(crate) fn production() -> Self {
        Self {
            copy: crate::clipboard::copy_plain,
            is_ssh: crate::clipboard::is_ssh,
            open: crate::browser::open,
            bind: crate::auth::xai_oauth::bind_callback_listener,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OAuthHost {
    Standalone,
    AddWizard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OAuthNav {
    Stay,
    Back,
    Confirm,
}

#[derive(Debug, Clone)]
pub(super) struct OAuthKeyOutcome {
    pub(super) nav: OAuthNav,
    pub(super) action: Option<OAuthFlowRequest>,
}

impl OAuthKeyOutcome {
    fn stay(action: Option<OAuthFlowRequest>) -> Self {
        Self {
            nav: OAuthNav::Stay,
            action,
        }
    }

    fn back(action: Option<OAuthFlowRequest>) -> Self {
        Self {
            nav: OAuthNav::Back,
            action,
        }
    }

    fn confirm() -> Self {
        Self {
            nav: OAuthNav::Confirm,
            action: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthOption {
    Login,
    ManualPaste,
    Poll,
    SkipContinue,
    Continue,
}

impl OAuthOption {
    fn label(self) -> &'static str {
        match self {
            OAuthOption::Login => "log in",
            OAuthOption::ManualPaste => "manual paste",
            OAuthOption::Poll => "poll for approval",
            OAuthOption::SkipContinue => "skip / continue",
            OAuthOption::Continue => "continue",
        }
    }
}

pub(crate) fn prepare_grok_browser_start(
    login: xai_oauth::ManualLogin,
    effects: OAuthEffects,
    port: u16,
) -> GrokBrowserStart {
    let ssh = (effects.is_ssh)();
    if ssh {
        return GrokBrowserStart {
            begin: OAuthBrowserBegin {
                login,
                listening: false,
                browser_error: None,
                listener_error: None,
                ssh: true,
            },
            listener: None,
        };
    }

    // The loopback socket must exist before opening the browser: an already
    // authorized xAI session can redirect immediately.
    let (listener, listener_error) = match (effects.bind)(port) {
        Ok(listener) => (Some(listener), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let browser_error = (effects.open)(&login.authorize_url)
        .err()
        .map(|error| error.to_string());
    GrokBrowserStart {
        begin: OAuthBrowserBegin {
            login,
            listening: listener.is_some(),
            browser_error,
            listener_error,
            ssh: false,
        },
        listener,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowShape {
    BrowserCallback,
    DeviceCode,
}

enum OAuthSession {
    None,
    Browser {
        login: xai_oauth::ManualLogin,
        authorize_url: String,
    },
    Device(codex_oauth::DeviceLogin),
}

pub(crate) struct OAuthFlowState {
    pub(crate) provider: OAuthProvider,
    shape: FlowShape,
    pub(crate) cursor: usize,
    pub(crate) logged_in: bool,
    pub(crate) status: Option<Result<String, String>>,
    pub(crate) paste_focused: bool,
    pub(crate) manual_input: TextField,
    session: OAuthSession,
    pub(crate) pending: bool,
    pub(crate) polling: bool,
    pub(crate) ssh: bool,
    pub(crate) spinner_tick: usize,
}

impl OAuthFlowState {
    pub(crate) fn new(provider: OAuthProvider) -> Self {
        Self::new_with_effects(provider, OAuthEffects::production())
    }

    #[cfg(test)]
    pub(crate) fn set_browser_session_for_test(&mut self, authorize_url: &str) {
        self.logged_in = false;
        let login = xai_oauth::ManualLogin::for_test(authorize_url);
        self.session = OAuthSession::Browser {
            authorize_url: authorize_url.to_string(),
            login,
        };
    }

    #[cfg(test)]
    pub(crate) fn browser_state_for_test(&self) -> Option<&str> {
        match &self.session {
            OAuthSession::Browser { login, .. } => Some(login.state_for_test()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_device_login_for_test(&mut self, login: codex_oauth::DeviceLogin) {
        self.logged_in = false;
        self.session = OAuthSession::Device(login);
    }

    pub(super) fn new_with_effects(provider: OAuthProvider, effects: OAuthEffects) -> Self {
        let (shape, logged_in) = match provider {
            OAuthProvider::Grok => (FlowShape::BrowserCallback, xai_oauth::is_logged_in()),
            OAuthProvider::Codex => (FlowShape::DeviceCode, codex_oauth::is_logged_in()),
        };
        Self {
            provider,
            shape,
            cursor: 0,
            logged_in,
            status: None,
            paste_focused: false,
            manual_input: TextField::default(),
            session: OAuthSession::None,
            pending: false,
            polling: false,
            ssh: (effects.is_ssh)(),
            spinner_tick: 0,
        }
    }

    pub(super) fn confirming(&self) -> bool {
        match self.shape {
            FlowShape::BrowserCallback => {
                oauth_setup_confirming_logged_in(self.logged_in, self.pending, self.paste_focused)
            }
            FlowShape::DeviceCode => {
                oauth_setup_confirming_logged_in(self.logged_in, self.polling, false)
            }
        }
    }

    pub(super) fn option_count(&self, host: OAuthHost) -> usize {
        oauth_options(self, host).len()
    }

    pub(super) fn authorize_url(&self) -> Option<&str> {
        match &self.session {
            OAuthSession::Browser { authorize_url, .. } if !self.confirming() => {
                Some(authorize_url)
            }
            _ => None,
        }
    }

    pub(super) fn has_browser_session(&self) -> bool {
        matches!(self.session, OAuthSession::Browser { .. })
    }

    pub(super) fn device_login(&self) -> Option<&codex_oauth::DeviceLogin> {
        match &self.session {
            OAuthSession::Device(login) if !self.confirming() => Some(login),
            _ => None,
        }
    }

    pub(crate) fn apply_begin(
        &mut self,
        result: OAuthBeginResult,
        effects: OAuthEffects,
    ) -> Option<OAuthFlowRequest> {
        match (self.provider, result) {
            (OAuthProvider::Codex, OAuthBeginResult::Device(Ok(login))) => {
                let copied = (effects.copy)(&login.user_code).is_ok();
                let ssh = (effects.is_ssh)();
                self.ssh = ssh;
                let opened = ssh || (effects.open)(&login.verification_uri).is_ok();
                let status = if ssh {
                    if copied {
                        "Code copied. Open the link and enter the code. Waiting for approval..."
                    } else {
                        "Open the link and enter the code. Waiting for approval (code copy failed)."
                    }
                } else if copied && opened {
                    "Opened browser; code copied. Waiting for approval..."
                } else if opened {
                    "Opened browser. Waiting for approval (code copy failed)."
                } else if copied {
                    "Code copied. Open the link manually. Waiting for approval..."
                } else {
                    "Open the link manually. Waiting for approval (code copy failed)."
                };
                self.polling = true;
                self.status = Some(Ok(status.to_string()));
                self.session = OAuthSession::Device(login.clone());
                Some(OAuthFlowRequest {
                    provider: OAuthProvider::Codex,
                    op: OAuthFlowOp::Poll(login),
                })
            }
            (OAuthProvider::Codex, OAuthBeginResult::Device(Err(e))) => {
                self.polling = false;
                self.status = Some(Err(e));
                None
            }
            (OAuthProvider::Grok, OAuthBeginResult::Browser(Ok(begin))) => {
                let OAuthBrowserBegin {
                    login,
                    listening,
                    browser_error,
                    listener_error,
                    ssh,
                } = begin;
                self.session = OAuthSession::Browser {
                    authorize_url: login.authorize_url.clone(),
                    login,
                };
                self.ssh = ssh;
                self.paste_focused = false;
                self.pending = listening;
                self.status = Some(Ok(match (listener_error, browser_error, ssh) {
                    (Some(listener), Some(browser), _) => format!(
                        "Could not listen for callback ({listener}); could not open browser ({browser}). Open the URL manually and paste callback URL or code."
                    ),
                    (Some(listener), None, _) => format!(
                        "Could not listen for callback ({listener}). Complete authorization and paste callback URL or code."
                    ),
                    (None, Some(browser), false) => format!(
                        "Could not open browser ({browser}); open the URL manually. Waiting for callback; paste callback/code here if needed."
                    ),
                    (None, None, false) if listening => {
                        "Opened browser; waiting for callback. Paste callback/code here if needed."
                            .to_string()
                    }
                    _ => "SSH detected; open the URL manually and paste callback/code.".to_string(),
                }));
                None
            }
            (OAuthProvider::Grok, OAuthBeginResult::Browser(Err(e))) => {
                self.pending = false;
                self.status = Some(Err(e));
                None
            }
            _ => {
                self.status = Some(Err("unexpected OAuth response".to_string()));
                None
            }
        }
    }

    pub(crate) fn apply_complete(&mut self, result: Result<bool, String>) {
        match self.provider {
            OAuthProvider::Codex => {
                self.polling = false;
                self.logged_in = result.as_ref().copied().unwrap_or(false)
                    || crate::auth::codex_oauth::is_logged_in();
                self.status = Some(result.map(|_| "Codex OAuth login complete".to_string()));
                if self.logged_in {
                    self.session = OAuthSession::None;
                }
            }
            OAuthProvider::Grok => {
                self.pending = false;
                self.logged_in = result.as_ref().copied().unwrap_or(false)
                    || crate::auth::xai_oauth::is_logged_in();
                self.status = Some(result.map(|_| "xAI OAuth login complete".to_string()));
                if self.logged_in {
                    self.paste_focused = false;
                    self.manual_input.set("");
                    self.session = OAuthSession::None;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum OAuthFlowView<'a> {
    Copilot(&'a CopilotSetupState),
    OAuth(&'a OAuthFlowState),
}

impl OAuthFlowView<'_> {
    pub(super) fn confirming(self) -> bool {
        match self {
            OAuthFlowView::Copilot(_) => false,
            OAuthFlowView::OAuth(s) => s.confirming(),
        }
    }
}

pub(super) fn oauth_setup_lines(flow: OAuthFlowView<'_>, host: OAuthHost) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let title = match flow {
        OAuthFlowView::Copilot(_) => "Set up GitHub Copilot auth",
        OAuthFlowView::OAuth(s) => match s.provider {
            OAuthProvider::Grok => "Set up Grok subscription auth",
            OAuthProvider::Codex => "Set up Codex subscription auth",
        },
    };
    lines.push(Line::from(Span::styled(
        title.to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());
    render_oauth_body(&mut lines, flow, host);
    lines
}

pub(super) fn render_oauth_body(
    lines: &mut Vec<Line<'static>>,
    flow: OAuthFlowView<'_>,
    host: OAuthHost,
) {
    match flow {
        OAuthFlowView::Copilot(s) => render_copilot_body(lines, s),
        OAuthFlowView::OAuth(s) => render_provider_oauth(lines, s, host),
    }
}

pub(super) fn handle_oauth_flow_key(
    key: KeyEvent,
    s: &mut OAuthFlowState,
    host: OAuthHost,
) -> OAuthKeyOutcome {
    handle_oauth_flow_key_with(key, s, host, OAuthEffects::production())
}

pub(super) fn handle_oauth_flow_key_with(
    key: KeyEvent,
    s: &mut OAuthFlowState,
    host: OAuthHost,
    effects: OAuthEffects,
) -> OAuthKeyOutcome {
    if s.provider == OAuthProvider::Grok && s.paste_focused {
        match key.code {
            KeyCode::Esc => {
                s.paste_focused = false;
                return OAuthKeyOutcome::stay(None);
            }
            KeyCode::Enter => {
                let OAuthSession::Browser { login, .. } = &s.session else {
                    s.status = Some(Err("manual OAuth session was not initialized".into()));
                    s.paste_focused = false;
                    return OAuthKeyOutcome::stay(None);
                };
                let input = s.manual_input.text().to_string();
                if input.trim().is_empty() {
                    s.status = Some(Err("paste callback URL or code first".to_string()));
                    return OAuthKeyOutcome::stay(None);
                }
                s.pending = true;
                s.status = Some(Ok("Completing xAI OAuth login...".to_string()));
                return OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                    provider: OAuthProvider::Grok,
                    op: OAuthFlowOp::Complete {
                        login: login.clone(),
                        input,
                    },
                }));
            }
            _ => {
                s.manual_input.handle_key(key);
                return OAuthKeyOutcome::stay(None);
            }
        }
    }

    match (s.provider, key.code) {
        (OAuthProvider::Grok, KeyCode::Char('c')) => {
            let url = s.authorize_url().map(ToOwned::to_owned);
            copy_oauth_url_with(url.as_deref(), &mut s.status, effects.copy);
            return OAuthKeyOutcome::stay(None);
        }
        (OAuthProvider::Codex, KeyCode::Char('c')) => {
            if s.ssh {
                let url = s.device_login().map(|login| login.verification_uri.clone());
                copy_oauth_url_with(url.as_deref(), &mut s.status, effects.copy);
            } else {
                let (code, url) = match s.device_login() {
                    Some(login) => (
                        Some(login.user_code.clone()),
                        Some(login.verification_uri.clone()),
                    ),
                    None => (None, None),
                };
                copy_oauth_url_with(code.as_deref(), &mut s.status, effects.copy);
                if let Some(url) = url
                    && let Err(e) = (effects.open)(&url)
                {
                    s.status = Some(Err(e.to_string()));
                }
            }
            return OAuthKeyOutcome::stay(None);
        }
        (OAuthProvider::Codex, KeyCode::Char('y')) => {
            let code = s.device_login().map(|login| login.user_code.clone());
            copy_oauth_url_with(code.as_deref(), &mut s.status, effects.copy);
            return OAuthKeyOutcome::stay(None);
        }
        _ => {}
    }

    if s.provider == OAuthProvider::Grok && s.pending && matches!(key.code, KeyCode::Esc) {
        s.pending = false;
        s.status = Some(Ok("OAuth login cancelled".to_string()));
        return OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
            provider: OAuthProvider::Grok,
            op: OAuthFlowOp::Cancel,
        }));
    }
    if s.provider == OAuthProvider::Codex && s.polling && matches!(key.code, KeyCode::Esc) {
        s.polling = false;
        s.status = Some(Ok("Codex OAuth polling cancelled".to_string()));
        return OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
            provider: OAuthProvider::Codex,
            op: OAuthFlowOp::Cancel,
        }));
    }

    match key.code {
        KeyCode::Esc => OAuthKeyOutcome::back(Some(OAuthFlowRequest {
            provider: s.provider,
            op: OAuthFlowOp::Cancel,
        })),
        KeyCode::Up | KeyCode::Char('k') => {
            s.cursor = oauth_option_cursor_prev(s.cursor, s.option_count(host));
            OAuthKeyOutcome::stay(None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            s.cursor = oauth_option_cursor_next(s.cursor, s.option_count(host));
            OAuthKeyOutcome::stay(None)
        }
        KeyCode::Enter => handle_oauth_enter(s, host),
        KeyCode::Char('s') if host == OAuthHost::AddWizard => OAuthKeyOutcome::confirm(),
        _ => OAuthKeyOutcome::stay(None),
    }
}

fn handle_oauth_enter(s: &mut OAuthFlowState, host: OAuthHost) -> OAuthKeyOutcome {
    let Some(option) = selected_oauth_option(s, host) else {
        s.cursor = 0;
        return OAuthKeyOutcome::stay(None);
    };

    match (s.provider, option) {
        (_, OAuthOption::Continue | OAuthOption::SkipContinue) => OAuthKeyOutcome::confirm(),
        (OAuthProvider::Grok, OAuthOption::ManualPaste) => {
            s.paste_focused = true;
            s.manual_input.set("");
            OAuthKeyOutcome::stay(None)
        }
        (OAuthProvider::Grok, OAuthOption::Login) => {
            s.pending = true;
            s.paste_focused = false;
            s.manual_input.set("");
            s.status = Some(Ok(if s.cursor == 0 && !s.ssh {
                "Preparing xAI OAuth login...".to_string()
            } else if s.ssh {
                "SSH detected; browser auto-open is unavailable here".to_string()
            } else {
                "Preparing manual xAI OAuth login...".to_string()
            }));
            OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                provider: OAuthProvider::Grok,
                op: OAuthFlowOp::Begin,
            }))
        }
        (OAuthProvider::Codex, OAuthOption::Login) => {
            s.polling = true;
            s.status = Some(Ok("Requesting Codex device code...".to_string()));
            OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                provider: OAuthProvider::Codex,
                op: OAuthFlowOp::Begin,
            }))
        }
        (OAuthProvider::Codex, OAuthOption::Poll) => {
            let Some(login) = s.device_login().cloned() else {
                s.polling = true;
                s.status = Some(Ok("Requesting Codex device code...".to_string()));
                return OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                    provider: OAuthProvider::Codex,
                    op: OAuthFlowOp::Begin,
                }));
            };
            s.polling = true;
            s.status = Some(Ok("Waiting for Codex approval...".to_string()));
            OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                provider: OAuthProvider::Codex,
                op: OAuthFlowOp::Poll(login),
            }))
        }
        _ => OAuthKeyOutcome::stay(None),
    }
}

fn selected_oauth_option(s: &mut OAuthFlowState, host: OAuthHost) -> Option<OAuthOption> {
    let count = s.option_count(host);
    if count == 0 {
        s.cursor = 0;
        return None;
    }
    if s.cursor >= count {
        s.cursor = count - 1;
    }
    oauth_options(s, host).get(s.cursor).copied()
}

fn oauth_options(s: &OAuthFlowState, host: OAuthHost) -> Vec<OAuthOption> {
    let mut opts = Vec::new();
    if s.confirming() {
        opts.push(OAuthOption::Continue);
        return opts;
    }
    match s.provider {
        OAuthProvider::Grok => {
            if s.pending {
                opts.push(OAuthOption::ManualPaste);
            } else {
                opts.push(OAuthOption::Login);
                opts.push(OAuthOption::ManualPaste);
            }
        }
        OAuthProvider::Codex => {
            if s.device_login().is_some() {
                opts.push(OAuthOption::Poll);
            } else {
                opts.push(OAuthOption::Login);
            }
        }
    }
    if host == OAuthHost::AddWizard {
        opts.push(OAuthOption::SkipContinue);
    }
    opts
}

fn rendered_cursor(s: &OAuthFlowState, host: OAuthHost) -> usize {
    s.cursor.min(s.option_count(host).saturating_sub(1))
}

pub(super) fn oauth_help_legend(host: OAuthHost, s: &OAuthFlowState) -> &'static str {
    if s.provider == OAuthProvider::Grok && s.paste_focused {
        return "type/paste code  enter: submit  esc: options";
    }
    match (
        host,
        s.provider,
        s.confirming(),
        s.pending,
        s.polling,
        s.authorize_url().is_some(),
        s.device_login().is_some(),
    ) {
        (OAuthHost::Standalone, OAuthProvider::Grok, true, _, _, _, _) => {
            "enter: continue  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Grok, true, _, _, _, _) => {
            "enter: continue  s: skip/continue  esc: back"
        }
        (OAuthHost::Standalone, OAuthProvider::Codex, true, _, _, _, _) => {
            "enter: continue  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Codex, true, _, _, _, _) => {
            "enter: continue  s: skip/continue  esc: back"
        }
        (OAuthHost::Standalone, OAuthProvider::Grok, false, true, _, true, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy URL  esc: cancel login"
        }
        (OAuthHost::Standalone, OAuthProvider::Grok, false, true, _, false, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  esc: cancel login"
        }
        (OAuthHost::AddWizard, OAuthProvider::Grok, false, true, _, true, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy URL  s: skip/continue  esc: cancel login"
        }
        (OAuthHost::AddWizard, OAuthProvider::Grok, false, true, _, false, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  s: skip/continue  esc: cancel login"
        }
        (OAuthHost::Standalone, OAuthProvider::Grok, false, false, _, true, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy URL  esc: back"
        }
        (OAuthHost::Standalone, OAuthProvider::Grok, false, false, _, false, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Grok, false, false, _, true, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy URL  s: skip/continue  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Grok, false, false, _, false, _) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  s: skip/continue  esc: back"
        }
        (OAuthHost::Standalone, OAuthProvider::Codex, false, _, true, _, true) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy  y: copy code  esc: cancel login"
        }
        (OAuthHost::Standalone, OAuthProvider::Codex, false, _, true, _, false) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  esc: cancel login"
        }
        (OAuthHost::AddWizard, OAuthProvider::Codex, false, _, true, _, true) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy  y: copy code  s: skip/continue  esc: cancel login"
        }
        (OAuthHost::AddWizard, OAuthProvider::Codex, false, _, true, _, false) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  s: skip/continue  esc: cancel login"
        }
        (OAuthHost::Standalone, OAuthProvider::Codex, false, _, false, _, true) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy  y: copy code  esc: back"
        }
        (OAuthHost::Standalone, OAuthProvider::Codex, false, _, false, _, false) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Codex, false, _, false, _, true) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  c: copy  y: copy code  s: skip/continue  esc: back"
        }
        (OAuthHost::AddWizard, OAuthProvider::Codex, false, _, false, _, false) => {
            "↑/↓/Tab/Shift+Tab  enter: choose  s: skip/continue  esc: back"
        }
    }
}

fn render_provider_oauth(lines: &mut Vec<Line<'static>>, s: &OAuthFlowState, host: OAuthHost) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let cyan = Style::default().fg(Color::Cyan);

    lines.push(Line::from(vec![
        Span::styled("Status: ", muted),
        Span::styled(
            if s.logged_in {
                "logged in"
            } else {
                "not logged in"
            }
            .to_string(),
            if s.logged_in { green } else { red },
        ),
    ]));
    match s.provider {
        OAuthProvider::Grok => {
            lines.push(Line::from(Span::styled(
                "Uses your SuperGrok subscription quota via xAI's sanctioned OAuth flow."
                    .to_string(),
                muted,
            )));
        }
        OAuthProvider::Codex => {
            lines.push(Line::from(Span::styled(
                "Uses your ChatGPT Plus/Pro subscription quota via OpenAI's documented Codex agent login.".to_string(),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                "Separate from the Codex CLI credential store; re-login if CLI use causes refresh-token contention.".to_string(),
                muted,
            )));
        }
    }
    lines.push(Line::default());
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }

    match s.provider {
        OAuthProvider::Grok => render_browser_callback_session(lines, s, muted, yellow, cyan),
        OAuthProvider::Codex => render_device_code_session(lines, s, muted, yellow, cyan),
    }

    if s.paste_focused {
        lines.push(Line::from(Span::styled(
            "Paste callback URL, ?code=...&state=..., or bare code:".to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled(s.manual_input.text().to_string(), cyan),
            crate::tui::settings::shell::cursor_marker_span(),
        ]));
        return;
    }

    let cursor = rendered_cursor(s, host);
    for (i, option) in oauth_options(s, host).iter().enumerate() {
        let label = option.label();
        let marker = if i == cursor { "▸ " } else { "  " };
        let style = if i == cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("[{label}]"), style),
        ]));
    }
}

fn render_browser_callback_session(
    lines: &mut Vec<Line<'static>>,
    s: &OAuthFlowState,
    muted: Style,
    yellow: Style,
    _cyan: Style,
) {
    if s.pending {
        lines.push(Line::from(Span::styled(
            format!(
                "{} Waiting for OAuth response...",
                spinner_glyph(s.spinner_tick)
            ),
            yellow,
        )));
        lines.push(Line::default());
    }
    if s.authorize_url().is_some() {
        lines.push(Line::from(Span::styled(
            "Open this URL in a browser, then paste the callback URL or code below.".to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(
                "open xai.com authorization page",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
        lines.push(Line::from(Span::styled("c copy URL".to_string(), muted)));
        lines.push(Line::default());
    }
}

fn render_device_code_session(
    lines: &mut Vec<Line<'static>>,
    s: &OAuthFlowState,
    muted: Style,
    yellow: Style,
    _cyan: Style,
) {
    if let Some(login) = s.device_login() {
        lines.push(Line::from(Span::styled(
            "Open this URL in any browser, including a different machine from this terminal."
                .to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(
                login.verification_uri.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Code: ", muted),
            Span::styled(login.user_code.clone(), yellow.add_modifier(Modifier::BOLD)),
        ]));
        let hint = if s.ssh {
            "Polling starts automatically. c copies the URL; y copies the user code."
        } else {
            "Polling starts automatically. c copies the user code and reopens the browser; y copies the user code."
        };
        lines.push(Line::from(Span::styled(hint.to_string(), muted)));
        lines.push(Line::default());
    }
    if s.polling {
        lines.push(Line::from(Span::styled(
            format!("{} Waiting for approval...", spinner_glyph(s.spinner_tick)),
            yellow,
        )));
        lines.push(Line::default());
    }
}
