use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_OAUTH_FLOW_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OAuthFlowId(pub u64);

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
                "We'll also run `gh auth token` once and store its token in Cockpit credentials so Copilot works without restarting.".to_string(),
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

#[cfg(test)]
impl OAuthBrowserBegin {
    pub(crate) fn for_test(listening: bool, ssh: bool) -> Self {
        Self {
            login: xai_oauth::ManualLogin::for_test("https://example.test/oauth"),
            listening,
            browser_error: None,
            listener_error: None,
            ssh,
        }
    }
}

pub(crate) struct GrokBrowserStart {
    pub(crate) begin: OAuthBrowserBegin,
    pub(crate) listener: Option<tokio::net::TcpListener>,
}

#[derive(Clone, Copy)]
pub(crate) struct OAuthEffects {
    pub(super) copy:
        fn(&str) -> Result<crate::clipboard::DeliveryResult, crate::clipboard::CopyError>,
    pub(super) is_ssh: fn() -> bool,
    pub(super) open: fn(&str) -> anyhow::Result<()>,
    pub(super) bind: fn(u16) -> anyhow::Result<tokio::net::TcpListener>,
}

/// Deliberate, not an oversight: this is always
/// [`crate::clipboard::ClipboardRecovery::Off`], never the user's
/// persisted `tui.clipboard_recovery` setting.
///
/// Two things justify it, not one:
/// 1. What actually flows through `OAuthEffects.copy` here is never a
///    bearer credential — it is a device-flow pairing `user_code` (e.g.
///    `login.user_code` in `apply_begin`) or a public authorize/
///    verification URL (`copy_oauth_url_with`). A pairing code is
///    short-lived and useless without also completing the flow in a
///    browser; a URL is not a secret at all. This is a materially lower
///    sensitivity bar than the doc comment this replaced implied.
/// 2. `OAuthEffects` is constructed at four call sites
///    (`settings/mod.rs::apply_oauth_begin`, `async_actions.rs`'s
///    `oauth.grok.begin` handler, `OAuthFlowState::new`, and
///    `handle_oauth_flow_key`), two of which — `OAuthFlowState::new` and
///    the free function `handle_oauth_flow_key` — are general
///    constructors/dispatchers with no `App`/config access at all today.
///    Threading a real `ClipboardRecovery` through honestly would mean
///    adding that parameter to all four and every one of their own
///    callers, not a local change — a real refactor, not a one-line fix,
///    and not proportionate to content this low-sensitivity.
///
/// If a future prompt gives OAuth flow state routine access to the
/// session's config (rather than this static effect table), revisit this.
fn copy_plain_no_recovery(
    text: &str,
) -> Result<crate::clipboard::DeliveryResult, crate::clipboard::CopyError> {
    crate::clipboard::copy_plain(text, crate::clipboard::ClipboardRecovery::Off)
}

impl OAuthEffects {
    pub(crate) fn production() -> Self {
        Self {
            copy: copy_plain_no_recovery,
            is_ssh: cockpit_core::sysinfo::is_ssh,
            open: cockpit_core::browser::open,
            bind: cockpit_core::auth::xai_oauth::bind_callback_listener,
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
pub(crate) enum OAuthOption {
    Login,
    ManualPaste,
    Poll,
    SkipContinue,
    Continue,
    Acknowledge,
}

impl OAuthOption {
    fn label(self) -> &'static str {
        match self {
            OAuthOption::Login => "log in",
            OAuthOption::ManualPaste => "manual paste",
            OAuthOption::Poll => "poll for approval",
            OAuthOption::SkipContinue => "skip / continue",
            OAuthOption::Continue => "continue",
            OAuthOption::Acknowledge => "I acknowledge the risk",
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
    pub(crate) flow_id: OAuthFlowId,
    pub(crate) provider: OAuthProvider,
    shape: FlowShape,
    pub(crate) cursor: usize,
    pub(crate) logged_in: bool,
    pub(crate) status: Option<Result<String, String>>,
    pub(crate) paste_focused: bool,
    pub(crate) manual_input: TextField,
    session: OAuthSession,
    pub(crate) pending: bool,
    focus_paste_after_begin: bool,
    pub(crate) polling: bool,
    pub(crate) ssh: bool,
    pub(crate) spinner_tick: usize,
    acknowledgement_required: bool,
    copy_operation: super::super::shell::PointerOperationGate,
}

impl OAuthFlowState {
    #[cfg(test)]
    pub(crate) fn new_without_acknowledgement_for_test(provider: OAuthProvider) -> Self {
        let mut state = Self::new(provider);
        state.acknowledgement_required = false;
        state
    }

    #[cfg(test)]
    pub(crate) fn new_with_acknowledgement_for_test(provider: OAuthProvider) -> Self {
        let mut state = Self::new(provider);
        state.acknowledgement_required = true;
        state
    }

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
            flow_id: OAuthFlowId(NEXT_OAUTH_FLOW_ID.fetch_add(1, Ordering::Relaxed)),
            provider,
            shape,
            cursor: 0,
            logged_in,
            status: None,
            paste_focused: false,
            manual_input: TextField::default(),
            session: OAuthSession::None,
            pending: false,
            focus_paste_after_begin: false,
            polling: false,
            ssh: (effects.is_ssh)(),
            spinner_tick: 0,
            acknowledgement_required: acknowledgement_required(provider),
            copy_operation: super::super::shell::PointerOperationGate::default(),
        }
    }

    pub(super) fn complete_copy(
        &mut self,
        flow_id: OAuthFlowId,
        operation_id: super::super::shell::PointerOperationId,
        result: Result<String, String>,
    ) {
        if self.flow_id == flow_id && self.copy_operation.complete(operation_id) {
            self.status = Some(result);
        }
    }

    fn submit_copy(
        &mut self,
        value: Option<&str>,
        open_after_copy: Option<&str>,
        effects: OAuthEffects,
    ) {
        if self.copy_operation.pending().is_some() {
            return;
        }
        let flow_id = self.flow_id;
        let operation_id = self.copy_operation.begin();
        let mut result = None;
        copy_oauth_url_with(value, &mut result, effects.copy);
        if let Some(url) = open_after_copy
            && let Err(error) = (effects.open)(url)
        {
            result = Some(Err(error.to_string()));
        }
        self.complete_copy(
            flow_id,
            operation_id,
            result.unwrap_or_else(|| Err("OAuth copy effect returned no result".into())),
        );
    }

    pub(super) fn cancel_copy_effect(&mut self) {
        self.copy_operation.cancel();
    }

    #[cfg(test)]
    pub(super) fn begin_copy_for_test(
        &mut self,
    ) -> (OAuthFlowId, super::super::shell::PointerOperationId) {
        (self.flow_id, self.copy_operation.begin())
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
                let copy_result = (effects.copy)(&login.user_code);
                let copied = copy_result.is_ok();
                // `copied` alone used to collapse Confirmed and Unverified
                // into the same "Code copied" wording — the same gap
                // `describe_delivered` exists to close for the toast-based
                // copy paths elsewhere in the crate. This status line has
                // no toast/`ToastKind` of its own, so the fix here is a
                // wording qualifier rather than a shared helper; the code
                // itself is also always rendered on screen (see the
                // `Span::styled(login.user_code...)` a few lines below in
                // the render path), so an unverified copy still leaves the
                // user able to read and type it, unlike the chat-copy
                // toast paths where the clipboard is the only way out.
                let unverified = copy_result
                    .as_ref()
                    .is_ok_and(|r| crate::clipboard::feedback::classify(r).is_unverified());
                let ssh = (effects.is_ssh)();
                self.ssh = ssh;
                let opened = ssh || (effects.open)(&login.verification_uri).is_ok();
                let copied_suffix = if unverified {
                    " (unverified — also shown above if the paste doesn't work)"
                } else {
                    ""
                };
                let status = if ssh {
                    if copied {
                        format!(
                            "Code copied{copied_suffix}. Open the link and enter the code. Waiting for approval..."
                        )
                    } else {
                        "Open the link and enter the code. Waiting for approval (code copy failed)."
                            .to_string()
                    }
                } else if copied && opened {
                    format!("Opened browser; code copied{copied_suffix}. Waiting for approval...")
                } else if opened {
                    "Opened browser. Waiting for approval (code copy failed).".to_string()
                } else if copied {
                    format!(
                        "Code copied{copied_suffix}. Open the link manually. Waiting for approval..."
                    )
                } else {
                    "Open the link manually. Waiting for approval (code copy failed).".to_string()
                };
                self.polling = true;
                self.status = Some(Ok(status));
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
                let focus_paste_after_begin = std::mem::take(&mut self.focus_paste_after_begin);
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
                self.paste_focused = focus_paste_after_begin || !listening;
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
                self.focus_paste_after_begin = false;
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
                    || cockpit_core::auth::codex_oauth::is_logged_in();
                self.status = Some(result.map(|_| "Codex OAuth login complete".to_string()));
                if self.logged_in {
                    self.session = OAuthSession::None;
                }
            }
            OAuthProvider::Grok => {
                self.pending = false;
                self.logged_in = result.as_ref().copied().unwrap_or(false)
                    || cockpit_core::auth::xai_oauth::is_logged_in();
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
    oauth_setup_lines_with_controls(flow, host).0
}

pub(super) fn oauth_setup_lines_with_controls(
    flow: OAuthFlowView<'_>,
    host: OAuthHost,
) -> (Vec<Line<'static>>, Vec<(usize, usize)>) {
    let mut lines = Vec::new();
    let mut controls = Vec::new();
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
    match flow {
        OAuthFlowView::Copilot(s) => render_copilot_body(&mut lines, s),
        OAuthFlowView::OAuth(s) => render_provider_oauth(&mut lines, s, host, Some(&mut controls)),
    }
    (lines, controls)
}

pub(super) fn render_oauth_body(
    lines: &mut Vec<Line<'static>>,
    flow: OAuthFlowView<'_>,
    host: OAuthHost,
) {
    match flow {
        OAuthFlowView::Copilot(s) => render_copilot_body(lines, s),
        OAuthFlowView::OAuth(s) => render_provider_oauth(lines, s, host, None),
    }
}

pub(super) fn render_oauth_body_with_controls(
    lines: &mut Vec<Line<'static>>,
    flow: OAuthFlowView<'_>,
    host: OAuthHost,
) -> Vec<(usize, usize)> {
    let mut controls = Vec::new();
    match flow {
        OAuthFlowView::Copilot(s) => render_copilot_body(lines, s),
        OAuthFlowView::OAuth(s) => render_provider_oauth(lines, s, host, Some(&mut controls)),
    }
    controls
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
    if !matches!(key.code, KeyCode::Char('c') | KeyCode::Char('y')) {
        // Any option/focus/navigation change invalidates an outstanding copy
        // completion for this flow generation.
        s.cancel_copy_effect();
    }
    if s.provider == OAuthProvider::Grok && s.paste_focused {
        match key.code {
            KeyCode::Esc => {
                s.paste_focused = false;
                return OAuthKeyOutcome::stay(None);
            }
            KeyCode::Enter => {
                let OAuthSession::Browser { login, .. } = &s.session else {
                    s.status = Some(Err(
                        "start login or manual paste first so a PKCE session can be created".into(),
                    ));
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
            s.submit_copy(url.as_deref(), None, effects);
            return OAuthKeyOutcome::stay(None);
        }
        (OAuthProvider::Codex, KeyCode::Char('c')) => {
            if s.ssh {
                let url = s.device_login().map(|login| login.verification_uri.clone());
                s.submit_copy(url.as_deref(), None, effects);
            } else {
                let (code, url) = match s.device_login() {
                    Some(login) => (
                        Some(login.user_code.clone()),
                        Some(login.verification_uri.clone()),
                    ),
                    None => (None, None),
                };
                s.submit_copy(code.as_deref(), url.as_deref(), effects);
            }
            return OAuthKeyOutcome::stay(None);
        }
        (OAuthProvider::Codex, KeyCode::Char('y')) => {
            let code = s.device_login().map(|login| login.user_code.clone());
            s.submit_copy(code.as_deref(), None, effects);
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
        KeyCode::Char('s') if host == OAuthHost::AddWizard && !s.acknowledgement_required => {
            OAuthKeyOutcome::confirm()
        }
        _ => OAuthKeyOutcome::stay(None),
    }
}

fn handle_oauth_enter(s: &mut OAuthFlowState, host: OAuthHost) -> OAuthKeyOutcome {
    let Some(option) = selected_oauth_option(s, host) else {
        s.cursor = 0;
        return OAuthKeyOutcome::stay(None);
    };

    match (s.provider, option) {
        (_, OAuthOption::Acknowledge) => {
            match cockpit_core::auth::subscription_ack::record(oauth_acknowledgement_provider(
                s.provider,
            )) {
                Ok(()) => {
                    s.acknowledgement_required = false;
                    s.status = Some(Ok("Subscription OAuth risk acknowledged.".to_string()));
                }
                Err(error) => {
                    s.status = Some(Err(format!("Could not record acknowledgement: {error}")));
                }
            }
            OAuthKeyOutcome::stay(None)
        }
        (_, OAuthOption::Continue | OAuthOption::SkipContinue) => OAuthKeyOutcome::confirm(),
        (OAuthProvider::Grok, OAuthOption::ManualPaste) => {
            if s.has_browser_session() {
                s.paste_focused = true;
                OAuthKeyOutcome::stay(None)
            } else {
                s.pending = true;
                s.focus_paste_after_begin = true;
                s.status = Some(Ok("Preparing xAI OAuth login...".to_string()));
                OAuthKeyOutcome::stay(Some(OAuthFlowRequest {
                    provider: OAuthProvider::Grok,
                    op: OAuthFlowOp::Begin,
                }))
            }
        }
        (OAuthProvider::Grok, OAuthOption::Login) => {
            s.pending = true;
            s.paste_focused = false;
            s.focus_paste_after_begin = false;
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

fn oauth_acknowledgement_provider(provider: OAuthProvider) -> &'static str {
    match provider {
        OAuthProvider::Grok => cockpit_core::auth::subscription_ack::GROK_OAUTH_PROVIDER,
        OAuthProvider::Codex => cockpit_core::auth::subscription_ack::CODEX_OAUTH_PROVIDER,
    }
}

fn acknowledgement_required(provider: OAuthProvider) -> bool {
    !cockpit_core::auth::subscription_ack::acknowledged(oauth_acknowledgement_provider(provider))
        .unwrap_or(false)
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

pub(crate) fn oauth_options(s: &OAuthFlowState, host: OAuthHost) -> Vec<OAuthOption> {
    if s.acknowledgement_required {
        return vec![OAuthOption::Acknowledge];
    }

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
    if s.acknowledgement_required {
        return "enter: acknowledge  esc: back";
    }
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

fn render_provider_oauth(
    lines: &mut Vec<Line<'static>>,
    s: &OAuthFlowState,
    host: OAuthHost,
    mut controls: Option<&mut Vec<(usize, usize)>>,
) {
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
    if s.acknowledgement_required {
        lines.push(Line::from(Span::styled(
            cockpit_core::auth::subscription_ack::ACKNOWLEDGEMENT_TEXT.to_string(),
            yellow,
        )));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Choose [I acknowledge the risk] to start subscription OAuth.".to_string(),
            muted,
        )));
        lines.push(Line::default());
    }
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }

    if s.acknowledgement_required {
        let cursor = rendered_cursor(s, host);
        for (i, option) in oauth_options(s, host).iter().enumerate() {
            let marker = if i == cursor { "▸ " } else { "  " };
            let style = if i == cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            if let Some(controls) = controls.as_deref_mut() {
                controls.push((lines.len(), i));
            }
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("[{}]", option.label()), style),
            ]));
        }
        return;
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
        if let Some(controls) = controls.as_deref_mut() {
            controls.push((lines.len(), i));
        }
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
        lines.push(Line::from(Span::styled(
            if s.paste_focused {
                "esc: options (c copies URL)"
            } else {
                "c copy URL"
            }
            .to_string(),
            muted,
        )));
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
