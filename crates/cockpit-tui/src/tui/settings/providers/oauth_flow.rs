use super::super::pointer_actions::OAuthFlowId;
use super::*;
#[cfg(test)]
use cockpit_core::auth::{codex_oauth, xai_oauth};

pub(super) fn render_copilot_body(lines: &mut Vec<Line<'static>>, s: &CopilotSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let red = Style::default().fg(Color::Red);
    let green = Style::default().fg(Color::Green);

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

    lines.push(Line::from(Span::styled(
        "Copilot authentication is managed by the Cockpit daemon.".to_string(),
        muted,
    )));
    lines.push(Line::from(Span::styled(
        "The TUI does not inspect or copy credentials and never edits shell startup files."
            .to_string(),
        muted,
    )));
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Ensure the daemon's environment already contains the approved Copilot credential, then retry the provider request.".to_string(),
        muted,
    )));
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Press Enter or Esc to return.".to_string(),
        muted,
    )));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OAuthProvider {
    Grok,
    Codex,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthFlowRequest {
    pub(crate) provider: OAuthProvider,
    pub(crate) client_flow_id: OAuthFlowId,
    pub(crate) operation_id: super::super::shell::PointerOperationId,
    pub(crate) op: OAuthFlowOp,
}

#[derive(Debug, Clone)]
pub(crate) enum OAuthFlowOp {
    Acknowledge,
    Begin,
    Poll {
        flow_id: String,
    },
    Complete {
        flow_id: String,
        input: zeroize::Zeroizing<String>,
    },
    Present {
        authorize_url: String,
        user_code: Option<String>,
        open_browser: bool,
        advance_flow: bool,
    },
    Cancel {
        flow_id: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum OAuthBeginResult {
    Public(Result<OAuthPublicBegin, String>),
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthPublicBegin {
    pub(crate) flow_id: String,
    pub(crate) authorize_url: String,
    pub(crate) user_code: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthPresentationResult {
    pub(crate) copied: bool,
    pub(crate) copy_unverified: bool,
    pub(crate) opened: bool,
    pub(crate) advance_flow: bool,
}

impl OAuthPresentationResult {
    fn status(&self, device_code: bool) -> String {
        let subject = if device_code {
            "device code"
        } else {
            "OAuth URL"
        };
        let copied = if self.copied {
            if self.copy_unverified {
                format!("{subject} copied (unverified)")
            } else {
                format!("{subject} copied")
            }
        } else {
            format!("{subject} copy failed")
        };
        if self.opened {
            format!("Opened browser; {copied}. Waiting for approval...")
        } else {
            format!("{copied}. Open the displayed link manually; waiting for approval...")
        }
    }
}

/// Run justified host-UI integration away from the synchronous input/reducer
/// path. The caller must bind the returned value to the originating OAuth
/// flow and operation before displaying it.
pub(crate) fn present_oauth_on_blocking_worker(
    authorize_url: String,
    user_code: Option<String>,
    open_browser: bool,
    advance_flow: bool,
) -> Result<OAuthPresentationResult, String> {
    let effects = OAuthEffects::production();
    let copy_value = user_code.as_deref().unwrap_or(&authorize_url);
    let copy = (effects.copy)(copy_value);
    let copied = copy.is_ok();
    let copy_unverified = copy
        .as_ref()
        .is_ok_and(|result| crate::clipboard::feedback::classify(result).is_unverified());
    let opened = open_browser && (effects.open)(&authorize_url).is_ok();
    Ok(OAuthPresentationResult {
        copied,
        copy_unverified,
        opened,
        advance_flow,
    })
}

#[derive(Debug, Clone)]
#[cfg(test)]
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

#[cfg(test)]
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
    #[cfg(test)]
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
            is_ssh: cockpit_host::sysinfo::is_ssh,
            open: cockpit_core::browser::open,
            #[cfg(test)]
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

    fn stay_present(
        state: &mut OAuthFlowState,
        action: Option<OAuthFlowRequest>,
        effects: OAuthEffects,
    ) -> Self {
        let Some(request) = action else {
            return Self::stay(None);
        };
        let OAuthFlowOp::Present {
            authorize_url,
            user_code,
            open_browser,
            advance_flow,
        } = request.op
        else {
            return Self::stay(Some(request));
        };
        let value = user_code.as_deref().unwrap_or(&authorize_url);
        let copy = (effects.copy)(value);
        let presentation = OAuthPresentationResult {
            copied: copy.is_ok(),
            copy_unverified: copy
                .as_ref()
                .is_ok_and(|result| crate::clipboard::feedback::classify(result).is_unverified()),
            opened: open_browser && (effects.open)(&authorize_url).is_ok(),
            advance_flow,
        };
        Self::stay(state.apply_present(Ok(presentation)))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OAuthOption {
    Login,
    ManualPaste,
    Poll,
    SkipContinue,
    Continue,
    Acknowledge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CodexOAuthOption {
    Login,
    Poll,
    SkipContinue,
    Continue,
    Acknowledge,
}

impl From<CodexOAuthOption> for OAuthOption {
    fn from(option: CodexOAuthOption) -> Self {
        match option {
            CodexOAuthOption::Login => Self::Login,
            CodexOAuthOption::Poll => Self::Poll,
            CodexOAuthOption::SkipContinue => Self::SkipContinue,
            CodexOAuthOption::Continue => Self::Continue,
            CodexOAuthOption::Acknowledge => Self::Acknowledge,
        }
    }
}

impl TryFrom<OAuthOption> for CodexOAuthOption {
    type Error = ();

    fn try_from(option: OAuthOption) -> Result<Self, Self::Error> {
        match option {
            OAuthOption::Login => Ok(Self::Login),
            OAuthOption::Poll => Ok(Self::Poll),
            OAuthOption::SkipContinue => Ok(Self::SkipContinue),
            OAuthOption::Continue => Ok(Self::Continue),
            OAuthOption::Acknowledge => Ok(Self::Acknowledge),
            OAuthOption::ManualPaste => Err(()),
        }
    }
}

impl OAuthOption {
    pub(super) fn label(self) -> &'static str {
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

#[cfg(test)]
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
        flow_id: String,
        authorize_url: String,
    },
    Device {
        flow_id: String,
        verification_uri: String,
        user_code: String,
    },
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
    /// A durable acknowledgement mutation has been submitted and this pane
    /// still owns its authority. This is deliberately independent of the
    /// transport action gate: an ambiguous result completes one transport
    /// attempt but must not release navigation or permit the pane to close.
    acknowledgement_authority_pending: bool,
    copy_operation: super::super::shell::PointerOperationGate,
    action_operation: super::super::shell::PointerOperationGate,
}

impl OAuthFlowState {
    #[cfg(test)]
    pub(crate) fn new_without_acknowledgement_for_test(provider: OAuthProvider) -> Self {
        let mut state = Self::new(provider);
        state.acknowledgement_required = false;
        state.logged_in = false;
        state.ssh = false;
        state
    }

    #[cfg(test)]
    pub(crate) fn new_with_acknowledgement_for_test(provider: OAuthProvider) -> Self {
        let mut state = Self::new(provider);
        state.acknowledgement_required = true;
        state
    }

    #[cfg(test)]
    pub(crate) fn new_without_acknowledgement_with_effects_for_test(
        provider: OAuthProvider,
        effects: OAuthEffects,
    ) -> Self {
        let mut state = Self::new_with_effects(provider, effects);
        state.acknowledgement_required = false;
        state.logged_in = false;
        state.ssh = false;
        state
    }

    pub(crate) fn new(provider: OAuthProvider) -> Self {
        Self::new_with_effects(provider, OAuthEffects::production())
    }

    #[cfg(test)]
    pub(crate) fn set_browser_session_for_test(&mut self, authorize_url: &str) {
        self.logged_in = false;
        self.session = OAuthSession::Browser {
            flow_id: self.flow_id.0.to_string(),
            authorize_url: authorize_url.to_string(),
        };
    }

    #[cfg(test)]
    pub(crate) fn browser_state_for_test(&self) -> Option<&str> {
        match &self.session {
            OAuthSession::Browser { authorize_url, .. } => Some(authorize_url),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_device_login_for_test(&mut self, login: codex_oauth::DeviceLogin) {
        self.logged_in = false;
        self.session = OAuthSession::Device {
            flow_id: self.flow_id.0.to_string(),
            verification_uri: login.verification_uri.clone(),
            user_code: login.user_code.clone(),
        };
    }

    pub(super) fn new_with_effects(provider: OAuthProvider, effects: OAuthEffects) -> Self {
        let shape = match provider {
            OAuthProvider::Grok => FlowShape::BrowserCallback,
            OAuthProvider::Codex => FlowShape::DeviceCode,
        };
        Self {
            // This identity survives long-lived async work and is included in
            // retained retry state. A process-reset counter could alias a late
            // completion from a previous TUI instance after reconnect.
            flow_id: OAuthFlowId(uuid::Uuid::new_v4().as_u128()),
            provider,
            shape,
            cursor: 0,
            // Inventory is hydrated by SettingsCx's non-blocking cache refresh.
            // OAuth construction and rendering must never wait on the daemon.
            logged_in: false,
            status: None,
            paste_focused: false,
            manual_input: TextField::default(),
            session: OAuthSession::None,
            pending: false,
            focus_paste_after_begin: false,
            polling: false,
            ssh: (effects.is_ssh)(),
            spinner_tick: 0,
            // Fail closed until the asynchronous inventory answer arrives.
            acknowledgement_required: true,
            acknowledgement_authority_pending: false,
            copy_operation: super::super::shell::PointerOperationGate::default(),
            action_operation: super::super::shell::PointerOperationGate::default(),
        }
    }

    pub(super) fn submit_pointer_copy(
        &mut self,
        flow_id: OAuthFlowId,
        kind: super::super::pointer_actions::OAuthCopyKind,
    ) -> Option<OAuthFlowRequest> {
        if self.flow_id != flow_id {
            return None;
        }
        let (value, open_after_copy) = match kind {
            super::super::pointer_actions::OAuthCopyKind::AuthorizationUrl => {
                (self.authorize_url().map(ToOwned::to_owned), None)
            }
            super::super::pointer_actions::OAuthCopyKind::DeviceCode => {
                let login = self.device_login();
                (
                    login.map(|(_, _, code)| code.to_string()),
                    (!self.ssh)
                        .then(|| login.map(|(_, uri, _)| uri.to_string()))
                        .flatten(),
                )
            }
        };
        let Some(value) = value else {
            return None;
        };
        Some(
            self.request(OAuthFlowOp::Present {
                authorize_url: open_after_copy.clone().unwrap_or_else(|| value.clone()),
                user_code: matches!(
                    kind,
                    super::super::pointer_actions::OAuthCopyKind::DeviceCode
                )
                .then_some(value),
                open_browser: open_after_copy.is_some(),
                advance_flow: false,
            }),
        )
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

    #[cfg(test)]
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

    #[cfg(test)]
    fn submit_device_code(
        &mut self,
        value: Option<&str>,
        open_after_copy: Option<&str>,
        effects: OAuthEffects,
    ) {
        self.submit_copy(value, open_after_copy, effects);
        if let Some(Ok(message)) = &mut self.status {
            *message = message.replacen("copied OAuth URL", "copied device code", 1);
        }
    }

    pub(super) fn cancel_copy_effect(&mut self) {
        self.copy_operation.cancel();
    }

    fn request(&mut self, op: OAuthFlowOp) -> OAuthFlowRequest {
        if matches!(op, OAuthFlowOp::Acknowledge) {
            self.acknowledgement_authority_pending = true;
        }
        OAuthFlowRequest {
            provider: self.provider,
            client_flow_id: self.flow_id,
            operation_id: self.action_operation.begin(),
            op,
        }
    }

    pub(crate) fn accepts_result(
        &mut self,
        client_flow_id: OAuthFlowId,
        operation_id: super::super::shell::PointerOperationId,
    ) -> bool {
        self.flow_id == client_flow_id && self.action_operation.complete(operation_id)
    }

    fn remote_flow_id(&self) -> Option<String> {
        match &self.session {
            OAuthSession::Browser { flow_id, .. } | OAuthSession::Device { flow_id, .. } => {
                Some(flow_id.clone())
            }
            OAuthSession::None => None,
        }
    }

    fn begin_cancel(&mut self) -> OAuthFlowRequest {
        self.action_operation.cancel();
        self.cancel_copy_effect();
        self.status = Some(Ok("Cancelling OAuth login...".to_string()));
        self.request(OAuthFlowOp::Cancel {
            flow_id: self.remote_flow_id(),
        })
    }

    pub(crate) fn apply_cancel(&mut self, result: Result<bool, String>) {
        match result {
            Ok(cancelled) => {
                self.pending = false;
                self.polling = false;
                self.paste_focused = false;
                self.focus_paste_after_begin = false;
                self.manual_input.set("");
                self.session = OAuthSession::None;
                self.status = Some(Ok(if cancelled {
                    "OAuth login cancelled".to_string()
                } else {
                    "OAuth login had already reached a terminal outcome".to_string()
                }));
            }
            Err(error) => {
                // Lost/ambiguous cancellation must retain surface ownership.
                // Escape retries the exact begin target with a fresh cancel
                // idempotency key; navigation stays fenced meanwhile.
                self.pending = true;
                self.polling = false;
                self.status = Some(Err(format!(
                    "OAuth cancellation is not settled; press Esc to retry: {error}"
                )));
            }
        }
    }

    pub(crate) fn apply_cancel_authoritative_failure(&mut self, error: String) {
        // A rejected cancel is proof only that this cancel attempt did not
        // terminate the original flow. Retain the daemon flow/session and the
        // authority fence; Escape can issue another correlated cancellation.
        self.pending = true;
        self.polling = false;
        self.status = Some(Err(format!(
            "OAuth cancellation was authoritatively rejected; the login remains live. Press Esc to retry: {error}"
        )));
    }

    pub(crate) fn apply_settlement_unknown(&mut self, error: String) {
        // Do not clear pending/polling/session state: the daemon operation may
        // already be committed. Navigation remains fenced, and the next user
        // retry derives the same durable operation ID from this flow.
        self.pending = true;
        self.status = Some(Err(format!(
            "OAuth settlement is unknown; retry the exact operation: {error}"
        )));
    }

    pub(crate) fn apply_acknowledgement_settlement_unknown(&mut self, error: String) {
        // The transport attempt is complete, but the durable acknowledgement
        // may already have committed. Keep the explicit authority fence and
        // the acknowledgement option so Enter replays the same flow-derived
        // daemon operation id.
        self.acknowledgement_authority_pending = true;
        self.status = Some(Err(format!(
            "Subscription acknowledgement settlement is unknown; press Enter to retry the exact operation: {error}"
        )));
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

    pub(super) fn device_login(&self) -> Option<(&str, &str, &str)> {
        match &self.session {
            OAuthSession::Device {
                flow_id,
                verification_uri,
                user_code,
            } if !self.confirming() => Some((flow_id, verification_uri, user_code)),
            _ => None,
        }
    }

    pub(crate) fn apply_begin_deferred(
        &mut self,
        result: OAuthBeginResult,
    ) -> Option<OAuthFlowRequest> {
        match result {
            OAuthBeginResult::Public(Ok(begin)) if self.provider == OAuthProvider::Codex => {
                let code = begin.user_code.unwrap_or_default();
                self.polling = true;
                self.status = Some(Ok(
                    "Device code ready; preparing browser and clipboard...".to_string()
                ));
                self.session = OAuthSession::Device {
                    flow_id: begin.flow_id.clone(),
                    verification_uri: begin.authorize_url.clone(),
                    user_code: code.clone(),
                };
                Some(self.request(OAuthFlowOp::Present {
                    authorize_url: begin.authorize_url,
                    user_code: Some(code),
                    open_browser: !self.ssh,
                    advance_flow: true,
                }))
            }
            OAuthBeginResult::Public(Err(e)) if self.provider == OAuthProvider::Codex => {
                self.polling = false;
                self.status = Some(Err(e));
                None
            }
            OAuthBeginResult::Public(Ok(begin)) if self.provider == OAuthProvider::Grok => {
                let focus_paste_after_begin = std::mem::take(&mut self.focus_paste_after_begin);
                self.session = OAuthSession::Browser {
                    flow_id: begin.flow_id,
                    authorize_url: begin.authorize_url.clone(),
                };
                self.status = Some(Ok("Login URL ready; preparing browser...".into()));
                self.focus_paste_after_begin = focus_paste_after_begin;
                Some(self.request(OAuthFlowOp::Present {
                    authorize_url: begin.authorize_url,
                    user_code: None,
                    open_browser: !self.ssh,
                    advance_flow: true,
                }))
            }
            OAuthBeginResult::Public(Err(e)) if self.provider == OAuthProvider::Grok => {
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

    #[cfg(test)]
    pub(crate) fn apply_begin(
        &mut self,
        result: OAuthBeginResult,
        effects: OAuthEffects,
    ) -> Option<OAuthFlowRequest> {
        let next = self.apply_begin_deferred(result);
        let Some(OAuthFlowRequest {
            client_flow_id,
            operation_id,
            op:
                OAuthFlowOp::Present {
                    authorize_url,
                    user_code,
                    open_browser,
                    advance_flow,
                },
            ..
        }) = next
        else {
            return next;
        };
        let value = user_code.as_deref().unwrap_or(&authorize_url);
        let copy = (effects.copy)(value);
        let presentation = OAuthPresentationResult {
            copied: copy.is_ok(),
            copy_unverified: copy
                .as_ref()
                .is_ok_and(|result| crate::clipboard::feedback::classify(result).is_unverified()),
            opened: open_browser && (effects.open)(&authorize_url).is_ok(),
            advance_flow,
        };
        assert!(self.accepts_result(client_flow_id, operation_id));
        self.apply_present(Ok(presentation))
    }

    pub(crate) fn apply_present(
        &mut self,
        result: Result<OAuthPresentationResult, String>,
    ) -> Option<OAuthFlowRequest> {
        if result.as_ref().is_ok_and(|result| !result.advance_flow) {
            self.status = Some(
                result.map(|result| result.status(matches!(self.provider, OAuthProvider::Codex))),
            );
            return None;
        }
        match self.provider {
            OAuthProvider::Codex => {
                let status = match result {
                    Ok(result) => result.status(true),
                    Err(error) => format!(
                        "Open the link and enter the displayed code. Host integration failed: {error}"
                    ),
                };
                self.status = Some(Ok(status));
                let Some(flow_id) = self.remote_flow_id() else {
                    self.polling = false;
                    self.status = Some(Err("OAuth flow lost its daemon identity".into()));
                    return None;
                };
                Some(self.request(OAuthFlowOp::Poll { flow_id }))
            }
            OAuthProvider::Grok => {
                let opened = result.as_ref().is_ok_and(|value| value.opened);
                self.pending = false;
                self.paste_focused = std::mem::take(&mut self.focus_paste_after_begin) || !opened;
                self.status = Some(match result {
                    Ok(_) if opened => {
                        Ok("Opened browser; paste callback/code here when complete.".into())
                    }
                    Ok(_) => Ok("Open the URL manually and paste callback/code here.".into()),
                    Err(error) => Err(format!(
                        "Could not open the browser; open the displayed URL manually: {error}"
                    )),
                });
                None
            }
        }
    }

    pub(crate) fn apply_complete(&mut self, result: Result<bool, String>) {
        let result = result.and_then(|logged_in| {
            logged_in
                .then_some(true)
                .ok_or_else(|| "provider did not confirm OAuth login".to_string())
        });
        match self.provider {
            OAuthProvider::Codex => {
                self.polling = false;
                self.logged_in = result.as_ref().copied().unwrap_or(false);
                self.status = Some(result.map(|_| "Codex OAuth login complete".to_string()));
                if self.logged_in {
                    self.session = OAuthSession::None;
                }
            }
            OAuthProvider::Grok => {
                self.pending = false;
                self.logged_in = result.as_ref().copied().unwrap_or(false);
                self.status = Some(result.map(|_| "xAI OAuth login complete".to_string()));
                if self.logged_in {
                    self.paste_focused = false;
                    self.manual_input.set("");
                    self.session = OAuthSession::None;
                }
            }
        }
    }

    /// Apply metadata-only inventory answers obtained by SettingsCx. `None`
    /// means the async refresh is still in flight and deliberately leaves the
    /// previous state intact.
    pub(crate) fn refresh_inventory_state(
        &mut self,
        logged_in: Option<bool>,
        acknowledged: Option<bool>,
    ) {
        if let Some(logged_in) = logged_in {
            self.logged_in = logged_in;
        }
        if let Some(acknowledged) = acknowledged {
            // Inventory refresh is advisory while this visible pane owns an
            // acknowledgement mutation. Only its exact typed settlement may
            // release that authority fence.
            if !self.acknowledgement_authority_pending {
                self.acknowledgement_required = !acknowledged;
            }
        }
    }

    pub(crate) fn apply_acknowledgement(&mut self, result: Result<(), String>) {
        self.acknowledgement_authority_pending = false;
        match result {
            Ok(()) => {
                self.acknowledgement_required = false;
                self.status = Some(Ok("Subscription OAuth risk acknowledged.".to_string()));
            }
            Err(error) => {
                self.status = Some(Err(format!("Could not record acknowledgement: {error}")));
            }
        }
    }

    pub(crate) fn has_unsettled_authority(&self) -> bool {
        self.pending || self.polling || self.acknowledgement_authority_pending
    }

    pub(crate) fn has_unsettled_acknowledgement(&self) -> bool {
        self.acknowledgement_authority_pending
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
    // A provider flow owns this settings surface until its exact terminal
    // completion (including cancellation) is applied.  In particular, do not
    // let navigation, another login, acknowledgement, paste editing, or a
    // wizard save race a live begin/poll/exchange.
    if s.action_operation.is_pending() {
        return if matches!(key.code, KeyCode::Esc) {
            OAuthKeyOutcome::stay(Some(s.begin_cancel()))
        } else {
            OAuthKeyOutcome::stay(None)
        };
    }
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
                let OAuthSession::Browser { flow_id, .. } = &s.session else {
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
                s.manual_input.set("");
                s.pending = true;
                s.status = Some(Ok("Completing xAI OAuth login...".to_string()));
                return OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Complete {
                    flow_id: flow_id.clone(),
                    input: zeroize::Zeroizing::new(input),
                })));
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
            let action = url.map(|authorize_url| {
                s.request(OAuthFlowOp::Present {
                    authorize_url,
                    user_code: None,
                    open_browser: false,
                    advance_flow: false,
                })
            });
            return OAuthKeyOutcome::stay_present(s, action, effects);
        }
        (OAuthProvider::Codex, KeyCode::Char('c')) => {
            let login = s
                .device_login()
                .map(|(_, url, code)| (url.to_string(), code.to_string()));
            let action = login.map(|(url, code)| {
                s.request(OAuthFlowOp::Present {
                    authorize_url: url,
                    user_code: (!s.ssh).then_some(code),
                    open_browser: !s.ssh,
                    advance_flow: false,
                })
            });
            return OAuthKeyOutcome::stay_present(s, action, effects);
        }
        (OAuthProvider::Codex, KeyCode::Char('y')) => {
            let login = s
                .device_login()
                .map(|(_, url, code)| (url.to_string(), code.to_string()));
            let action = login.map(|(url, code)| {
                s.request(OAuthFlowOp::Present {
                    authorize_url: url,
                    user_code: Some(code),
                    open_browser: false,
                    advance_flow: false,
                })
            });
            return OAuthKeyOutcome::stay_present(s, action, effects);
        }
        _ => {}
    }

    match key.code {
        KeyCode::Esc => {
            if s.acknowledgement_authority_pending {
                s.status = Some(Err(
                    "Subscription acknowledgement is still settling; press Enter to retry the exact operation"
                        .into(),
                ));
                OAuthKeyOutcome::stay(None)
            } else if matches!(s.session, OAuthSession::None) {
                OAuthKeyOutcome::back(None)
            } else {
                // The OAuth surface remains the owner until the exact cancel
                // receipt settles; only apply_cancel may release navigation.
                OAuthKeyOutcome::stay(Some(s.begin_cancel()))
            }
        }
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
            s.status = Some(Ok(
                "Recording subscription OAuth acknowledgement...".to_string()
            ));
            OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Acknowledge)))
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
                OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Begin)))
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
            OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Begin)))
        }
        (OAuthProvider::Grok, OAuthOption::Poll) => {
            s.pending = true;
            s.paste_focused = false;
            s.status = Some(Ok("Checking xAI OAuth callback...".to_string()));
            OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Begin)))
        }
        (OAuthProvider::Codex, OAuthOption::Login) => {
            s.polling = true;
            s.status = Some(Ok("Requesting Codex device code...".to_string()));
            OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Begin)))
        }
        (OAuthProvider::Codex, OAuthOption::Poll) => {
            let Some((flow_id, _, _)) = s.device_login() else {
                s.polling = true;
                s.status = Some(Ok("Requesting Codex device code...".to_string()));
                return OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Begin)));
            };
            let flow_id = flow_id.to_string();
            s.polling = true;
            s.status = Some(Ok("Waiting for Codex approval...".to_string()));
            OAuthKeyOutcome::stay(Some(s.request(OAuthFlowOp::Poll { flow_id })))
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

pub(crate) fn oauth_options(s: &OAuthFlowState, host: OAuthHost) -> Vec<OAuthOption> {
    if s.provider == OAuthProvider::Codex {
        return codex_oauth_options(s, host)
            .into_iter()
            .map(OAuthOption::from)
            .collect();
    }
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
                opts.push(OAuthOption::Poll);
                opts.push(OAuthOption::ManualPaste);
            } else {
                opts.push(OAuthOption::Login);
                opts.push(OAuthOption::ManualPaste);
            }
        }
        OAuthProvider::Codex => unreachable!("Codex options use their sealed inventory"),
    }
    if host == OAuthHost::AddWizard
        || (host == OAuthHost::Standalone && (s.pending || s.device_login().is_some()))
    {
        opts.push(OAuthOption::SkipContinue);
    }
    opts
}

fn codex_oauth_options(s: &OAuthFlowState, host: OAuthHost) -> Vec<CodexOAuthOption> {
    if s.acknowledgement_required {
        return vec![CodexOAuthOption::Acknowledge];
    }
    if s.confirming() {
        return vec![CodexOAuthOption::Continue];
    }

    let mut options = vec![if s.device_login().is_some() {
        CodexOAuthOption::Poll
    } else {
        CodexOAuthOption::Login
    }];
    if host == OAuthHost::AddWizard
        || (host == OAuthHost::Standalone && (s.pending || s.device_login().is_some()))
    {
        options.push(CodexOAuthOption::SkipContinue);
    }
    options
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
    if let Some((_, verification_uri, user_code)) = s.device_login() {
        lines.push(Line::from(Span::styled(
            "Open this URL in any browser, including a different machine from this terminal."
                .to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(
                verification_uri.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Code: ", muted),
            Span::styled(user_code.to_string(), yellow.add_modifier(Modifier::BOLD)),
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
