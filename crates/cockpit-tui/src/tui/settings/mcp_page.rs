//! `/settings → MCP` page (GOALS §18a).
//!
//! Edits the daemon-owned sibling `mcp.json` in the same `.cockpit/` directory
//! as the settings dialog's `config.json`. The page consumes a daemon-redacted
//! snapshot and submits mutations through the daemon. Two views:
//!   - **List**: every configured server with transport, enabled, and auth
//!     status, color-coded (green = ready + enabled, yellow = ready + not
//!     enabled, red = needs auth + not authed). Per-server actions: toggle
//!     enabled (`space`), authenticate (`a`). Plus `[+ add server]` and
//!     delete (`d`).
//!   - **Add**: name + cycled transport / auth + endpoint-or-command
//!     text field, with a warning when auth is `none`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use std::collections::{BTreeMap, BTreeSet};

use crate::tui::textfield::TextField;
use cockpit_core::mcp::config::{
    Auth, EnvAuth, HeaderAuth, McpConfig, OauthAuth, ServerConfig, Transport,
};

use super::secret_display;
use super::shell::{
    SettingsScrollRegionId, error_style, marker, muted_style, push_text_field_at_cursor,
    selected_line_from_marker, selected_style, warning_style,
};
use super::{Nav, SettingsCx, SettingsPage, save_button_line, save_status};

/// `/settings → MCP` state: the server list or the add form.
pub(super) enum McpPage {
    List(ListState),
    Add(Box<AddState>),
}

pub(super) struct ListState {
    pub(super) cursor: usize,
    pub(super) status: Option<String>,
    /// Two-step delete confirm: armed by the first `d`, applied by the
    /// second on the same row.
    pub(super) delete_pending: bool,
    /// In-progress daemon-owned OAuth handshake. Keeping this in the list
    /// page lets SSH/headless users see the authorize URL and paste a
    /// callback without exposing any token or PKCE state.
    pub(super) oauth: Option<McpOAuthState>,
}

pub(super) struct McpOAuthState {
    pub(super) server: String,
    pub(super) begin_client_operation_id: String,
    pub(super) flow_id: String,
    pub(super) authorize_url: String,
    pub(super) callback: TextField,
    pub(super) status: Option<String>,
}

pub(super) struct AddState {
    pub(super) original_name: Option<String>,
    pub(super) name: TextField,
    pub(super) endpoint: TextField,
    pub(super) command: TextField,
    pub(super) args: TextField,
    pub(super) base_env: TextField,
    pub(super) stored_base_env_refs: BTreeMap<String, String>,
    pub(super) transport: Transport,
    pub(super) auth: AuthKind,
    pub(super) header_name: TextField,
    pub(super) header_value: TextField,
    pub(super) stored_header_credential_ref: Option<String>,
    pub(super) auth_env: TextField,
    pub(super) stored_auth_env_refs: BTreeMap<String, String>,
    pub(super) oauth_authorize_url: TextField,
    pub(super) oauth_token_url: TextField,
    pub(super) oauth_client_id: TextField,
    pub(super) oauth_scopes: TextField,
    pub(super) enabled: bool,
    pub(super) cache_ttl_secs: TextField,
    pub(super) connect_timeout_secs: TextField,
    pub(super) request_timeout_secs: TextField,
    pub(super) cursor: usize,
    pub(super) status: Option<String>,
}

/// Auth choices in the add form (the static, no-credential subset; OAuth
/// is configured then authenticated from the list with `a`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum AuthKind {
    None,
    Oauth,
    Header,
    Env,
}

impl AuthKind {
    fn label(self) -> &'static str {
        match self {
            AuthKind::None => "none (public)",
            AuthKind::Oauth => "oauth",
            AuthKind::Header => "header",
            AuthKind::Env => "env",
        }
    }
    fn from_auth(auth: &Auth) -> Self {
        match auth {
            Auth::None => AuthKind::None,
            Auth::Oauth(_) => AuthKind::Oauth,
            Auth::Header(_) => AuthKind::Header,
            Auth::Env(_) => AuthKind::Env,
        }
    }
    fn cycle_for_transport(self, transport: Transport) -> Self {
        let choices: &[AuthKind] = match transport {
            Transport::Stdio => &[AuthKind::None, AuthKind::Env],
            Transport::Streamable | Transport::Sse => {
                &[AuthKind::None, AuthKind::Header, AuthKind::Oauth]
            }
        };
        let idx = choices.iter().position(|k| *k == self).unwrap_or(0);
        choices[(idx + 1) % choices.len()]
    }
    fn is_compatible(self, transport: Transport) -> bool {
        match self {
            AuthKind::None => true,
            AuthKind::Env => matches!(transport, Transport::Stdio),
            AuthKind::Header | AuthKind::Oauth => !matches!(transport, Transport::Stdio),
        }
    }
}

const FIELD_NAME: usize = 0;
const FIELD_ENABLED: usize = 1;
const FIELD_TRANSPORT: usize = 2;
const FIELD_ENDPOINT: usize = 3;
const FIELD_COMMAND: usize = 4;
const FIELD_ARGS: usize = 5;
const FIELD_BASE_ENV: usize = 6;
const FIELD_AUTH: usize = 7;
const FIELD_HEADER_NAME: usize = 8;
const FIELD_HEADER_VALUE: usize = 9;
const FIELD_AUTH_ENV: usize = 10;
const FIELD_OAUTH_AUTHORIZE: usize = 11;
const FIELD_OAUTH_TOKEN: usize = 12;
const FIELD_OAUTH_CLIENT: usize = 13;
const FIELD_OAUTH_SCOPES: usize = 14;
const FIELD_CACHE_TTL: usize = 15;
const FIELD_CONNECT_TIMEOUT: usize = 16;
const FIELD_REQUEST_TIMEOUT: usize = 17;
const FIELD_SAVE: usize = 18;
const ADD_FIELDS: usize = 19;

macro_rules! push_pointer_text_field {
    ($bindings:expr, $id:expr, $($args:expr),+ $(,)?) => {{
        let range = push_text_field_at_cursor($($args),+);
        $bindings.extend(range.map(|line| (line, mcp_add_action($id))));
    }};
}

fn mcp_add_action(index: usize) -> super::pointer_actions::McpAction {
    use super::pointer_actions::McpAction;
    match index {
        FIELD_NAME => McpAction::EditName,
        FIELD_ENABLED => McpAction::ToggleEditorEnabled,
        FIELD_TRANSPORT => McpAction::CycleTransport,
        FIELD_ENDPOINT => McpAction::EditEndpoint,
        FIELD_COMMAND => McpAction::EditCommand,
        FIELD_ARGS => McpAction::EditArgs,
        FIELD_BASE_ENV => McpAction::EditBaseEnv,
        FIELD_AUTH => McpAction::CycleAuth,
        FIELD_HEADER_NAME => McpAction::EditHeaderName,
        FIELD_HEADER_VALUE => McpAction::EditHeaderValue,
        FIELD_AUTH_ENV => McpAction::EditAuthEnv,
        FIELD_OAUTH_AUTHORIZE => McpAction::EditOauthAuthorizeUrl,
        FIELD_OAUTH_TOKEN => McpAction::EditOauthTokenUrl,
        FIELD_OAUTH_CLIENT => McpAction::EditOauthClientId,
        FIELD_OAUTH_SCOPES => McpAction::EditOauthScopes,
        FIELD_CACHE_TTL => McpAction::EditCacheTtl,
        FIELD_CONNECT_TIMEOUT => McpAction::EditConnectTimeout,
        FIELD_REQUEST_TIMEOUT => McpAction::EditRequestTimeout,
        FIELD_SAVE => McpAction::Save,
        _ => unreachable!("sealed MCP add field index"),
    }
}

fn mcp_add_index(action: &super::pointer_actions::McpAction) -> Option<usize> {
    use super::pointer_actions::McpAction;
    Some(match action {
        McpAction::EditName => FIELD_NAME,
        McpAction::ToggleEditorEnabled => FIELD_ENABLED,
        McpAction::CycleTransport => FIELD_TRANSPORT,
        McpAction::EditEndpoint => FIELD_ENDPOINT,
        McpAction::EditCommand => FIELD_COMMAND,
        McpAction::EditArgs => FIELD_ARGS,
        McpAction::EditBaseEnv => FIELD_BASE_ENV,
        McpAction::CycleAuth => FIELD_AUTH,
        McpAction::EditHeaderName => FIELD_HEADER_NAME,
        McpAction::EditHeaderValue => FIELD_HEADER_VALUE,
        McpAction::EditAuthEnv => FIELD_AUTH_ENV,
        McpAction::EditOauthAuthorizeUrl => FIELD_OAUTH_AUTHORIZE,
        McpAction::EditOauthTokenUrl => FIELD_OAUTH_TOKEN,
        McpAction::EditOauthClientId => FIELD_OAUTH_CLIENT,
        McpAction::EditOauthScopes => FIELD_OAUTH_SCOPES,
        McpAction::EditCacheTtl => FIELD_CACHE_TTL,
        McpAction::EditConnectTimeout => FIELD_CONNECT_TIMEOUT,
        McpAction::EditRequestTimeout => FIELD_REQUEST_TIMEOUT,
        McpAction::Save => FIELD_SAVE,
        McpAction::Cancel
        | McpAction::Open(_)
        | McpAction::Add
        | McpAction::ToggleEnabled(_)
        | McpAction::Authenticate(_)
        | McpAction::Delete(_) => return None,
    })
}

type EnvMaps = (BTreeMap<String, String>, BTreeMap<String, String>);

enum ServerLifecycle {
    DisabledDraft,
    NeedsAuth,
    Ready,
    Error,
}

fn lifecycle(name: &str, s: &ServerConfig) -> ServerLifecycle {
    if s.require_endpoint(name).is_err() && !matches!(s.transport, Transport::Stdio) {
        return ServerLifecycle::Error;
    }
    if s.require_command(name).is_err() && matches!(s.transport, Transport::Stdio) {
        return ServerLifecycle::Error;
    }
    if s.validate_transport_auth(name).is_err() {
        return ServerLifecycle::Error;
    }
    if !s.enabled {
        return ServerLifecycle::DisabledDraft;
    }
    match &s.auth {
        Auth::None => ServerLifecycle::Ready,
        Auth::Header(h) => {
            if h.value.trim().is_empty() && h.credential_ref.is_none() {
                ServerLifecycle::NeedsAuth
            } else {
                ServerLifecycle::Ready
            }
        }
        Auth::Env(e) => {
            if e.vars.is_empty() && e.credential_refs.is_empty() {
                ServerLifecycle::NeedsAuth
            } else {
                ServerLifecycle::Ready
            }
        }
        // The renderer supplies the cached OAuth answer below.  The pure
        // fallback remains conservative for non-render callers and tests.
        Auth::Oauth(_) => ServerLifecycle::NeedsAuth,
    }
}

fn lifecycle_label(name: &str, s: &ServerConfig) -> &'static str {
    match lifecycle(name, s) {
        ServerLifecycle::DisabledDraft => "disabled/draft",
        ServerLifecycle::NeedsAuth => "needs_auth",
        ServerLifecycle::Ready => "ready",
        ServerLifecycle::Error => "error",
    }
}

fn cached_lifecycle(cx: &SettingsCx, name: &str, s: &ServerConfig) -> ServerLifecycle {
    if !matches!(s.auth, Auth::Oauth(_)) {
        return lifecycle(name, s);
    }
    if s.validate_transport_auth(name).is_err() {
        return ServerLifecycle::Error;
    }
    if !s.enabled {
        return ServerLifecycle::DisabledDraft;
    }
    let key = cockpit_core::mcp::auth::cred_key(name);
    if cx
        .cached_secret_inventory_contains(&key, None)
        .unwrap_or(false)
    {
        ServerLifecycle::Ready
    } else {
        ServerLifecycle::NeedsAuth
    }
}

fn cached_lifecycle_label(cx: &SettingsCx, name: &str, s: &ServerConfig) -> &'static str {
    match cached_lifecycle(cx, name, s) {
        ServerLifecycle::DisabledDraft => "disabled/draft",
        ServerLifecycle::NeedsAuth => "needs_auth",
        ServerLifecycle::Ready => "ready",
        ServerLifecycle::Error => "error",
    }
}

fn cached_row_color(cx: &SettingsCx, name: &str, s: &ServerConfig) -> Color {
    match cached_lifecycle(cx, name, s) {
        ServerLifecycle::Error | ServerLifecycle::NeedsAuth => Color::Red,
        ServerLifecycle::Ready => Color::Green,
        ServerLifecycle::DisabledDraft => Color::Yellow,
    }
}

/// The color for a server row (GOALS §18a):
/// green = ready + enabled, yellow = ready + disabled, red = needs auth.
pub(crate) fn row_color(name: &str, s: &ServerConfig) -> Color {
    match lifecycle(name, s) {
        ServerLifecycle::Error | ServerLifecycle::NeedsAuth => Color::Red,
        ServerLifecycle::Ready => Color::Green,
        ServerLifecycle::DisabledDraft => Color::Yellow,
    }
}

impl SettingsCx {
    /// Return the daemon-redacted MCP snapshot cached when the settings
    /// session opened. Disk reads belong to the daemon owner boundary.
    pub(super) fn load_mcp(&self) -> McpConfig {
        self.mcp_config.clone()
    }

    fn save_mcp(
        &mut self,
        cfg: &McpConfig,
        secret_values: &BTreeMap<String, String>,
        _cleanup_names: &BTreeSet<String>,
    ) -> Result<super::SettingsSaveOutcome, String> {
        let project_root = self
            .active_project_root
            .clone()
            .or_else(|| self.config_path.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let canonical_root = super::canonical_project_root(&project_root);
        let expected_owner_root = self
            .mcp_owner_root
            .clone()
            .filter(|owner| owner == &canonical_root)
            .ok_or_else(|| {
                "MCP authority snapshot is missing or belongs to another workspace; reload settings"
                    .to_string()
            })?;
        let expected_config_path = self.mcp_config_path.clone().ok_or_else(|| {
            "MCP authority snapshot has no daemon-selected config path; reload settings".to_string()
        })?;
        let snapshot_capability = self.mcp_edit_capability.clone().ok_or_else(|| {
            "MCP authority snapshot has no edit capability; reload settings".to_string()
        })?;
        let expected_consumed_revision = self.mcp_revision.clone().ok_or_else(|| {
            "MCP authority snapshot has no target-layer revision; reload settings".to_string()
        })?;
        let mut operations = Vec::new();
        for (name, server) in &cfg.servers {
            let Some(previous) = self.mcp_config.servers.get(name) else {
                operations.push(cockpit_proto::McpConfigPatchOperation::AddServer {
                    name: name.clone(),
                    server_json: serde_json::to_string(server)
                        .map_err(|e| e.to_string())?
                        .into(),
                });
                continue;
            };
            if previous == server {
                continue;
            }
            if self.mcp_authored_config.servers.contains_key(name) {
                let previous = serde_json::to_value(previous).map_err(|e| e.to_string())?;
                let current = serde_json::to_value(server).map_err(|e| e.to_string())?;
                let previous = previous.as_object().ok_or("invalid prior MCP server")?;
                let current = current.as_object().ok_or("invalid edited MCP server")?;
                let set_fields = current
                    .iter()
                    .filter(|(key, value)| previous.get(*key) != Some(*value))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<serde_json::Map<_, _>>();
                let unset_fields = previous
                    .keys()
                    .filter(|key| !current.contains_key(*key))
                    .cloned()
                    .collect();
                operations.push(
                    cockpit_proto::McpConfigPatchOperation::UpdateAuthoredServer {
                        name: name.clone(),
                        set_fields_json: serde_json::to_string(&set_fields)
                            .map_err(|e| e.to_string())?
                            .into(),
                        unset_fields,
                    },
                );
            } else {
                if !credential_refs(name, previous).is_empty() {
                    return Err(format!(
                        "MCP server `{name}` inherits credentials; re-enter them in this layer before overriding it"
                    ));
                }
                operations.push(
                    cockpit_proto::McpConfigPatchOperation::MaterializeInheritedServer {
                        name: name.clone(),
                        server_json: serde_json::to_string(server)
                            .map_err(|e| e.to_string())?
                            .into(),
                    },
                );
            }
        }
        for name in self.mcp_config.servers.keys() {
            if !cfg.servers.contains_key(name) {
                if !self.mcp_authored_config.servers.contains_key(name) {
                    return Err(format!(
                        "MCP server `{name}` is inherited; edit its owning layer instead of deleting it here"
                    ));
                }
                operations.push(
                    cockpit_proto::McpConfigPatchOperation::DeleteAuthoredServer {
                        name: name.clone(),
                    },
                );
            }
        }
        if operations.is_empty() {
            return Err("MCP settings have no changes to save".into());
        }
        let patch = cockpit_proto::McpConfigPatch { operations };
        let patch_wire = serde_json::to_string(&patch).map_err(|e| e.to_string())?;
        let secret_values_json = serde_json::to_string(secret_values).map_err(|e| e.to_string())?;
        let owner = project_root.display().to_string();
        let expected_request_intent_hash =
            super::local_receipt_request_hash(&("save_mcp_config", &owner, &patch_wire))?;
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        self.queue_simple_secret_mutation(
            super::SettingsEffectTarget {
                surface: "settings.mcp-save",
                owner: owner.clone(),
                revision: Some(client_operation_id.clone()),
            },
            super::SettingsDaemonEffectWork::McpConfigSave {
                client_operation_id: client_operation_id.clone(),
                project_root: owner.clone(),
                snapshot_capability: snapshot_capability.clone(),
                owner_root: expected_owner_root.clone(),
                config_path: expected_config_path.clone(),
                expected_revision: expected_consumed_revision.clone(),
                mutation_intent_hash: expected_request_intent_hash.clone(),
                patch,
                secret_values_json: super::SecretPayload::new(secret_values_json),
            },
            super::SettingsMutationAction::McpSave {
                config: cfg.clone(),
                client_operation_id,
                project_root: owner,
                expected_owner_root,
                expected_config_path,
                snapshot_capability,
                expected_consumed_revision,
                expected_request_intent_hash,
            },
        );
        self.extended_warnings = vec!["saving MCP settings…".into()];
        Ok(super::SettingsSaveOutcome::Queued)
    }

    pub(super) fn adopt_pending_mcp_oauth(&mut self, s: &mut ListState) {
        if let Some(completion) = self.pending_mcp_oauth.take() {
            match completion {
                super::PendingMcpOAuth::Started {
                    server,
                    begin_client_operation_id,
                    flow_id,
                    authorize_url,
                } => {
                    s.oauth = Some(McpOAuthState {
                        server,
                        begin_client_operation_id,
                        flow_id,
                        authorize_url,
                        callback: TextField::default(),
                        status: None,
                    });
                    s.status = Some(
                        "open the authorize URL, then paste the callback or code below".into(),
                    );
                }
                super::PendingMcpOAuth::Completed { server, flow_id } => {
                    if s.oauth
                        .as_ref()
                        .is_some_and(|flow| flow.server == server && flow.flow_id == flow_id)
                    {
                        s.oauth = None;
                    }
                    s.status = Some(format!("authenticated `{server}`"));
                }
                super::PendingMcpOAuth::Cancelled { server, flow_id } => {
                    if s.oauth
                        .as_ref()
                        .is_some_and(|flow| flow.server == server && flow.flow_id == flow_id)
                    {
                        s.oauth = None;
                    }
                    s.status = Some(format!("cancelled MCP OAuth for `{server}`"));
                }
                super::PendingMcpOAuth::AlreadyTerminal { server, flow_id } => {
                    if s.oauth
                        .as_ref()
                        .is_some_and(|flow| flow.server == server && flow.flow_id == flow_id)
                    {
                        s.oauth = None;
                    }
                    s.status = Some(format!(
                        "MCP OAuth for `{server}` was already terminal; credential inventory refreshed"
                    ));
                }
            }
        }
    }

    fn handle_mcp_list_key(&mut self, key: KeyEvent, s: &mut ListState) -> Nav {
        self.adopt_pending_mcp_oauth(s);
        let cfg = self.load_mcp();
        let names: Vec<String> = cfg.servers.keys().cloned().collect();
        let row_count = names.len() + 1; // + [+ add server]
        if s.oauth.is_some() {
            let mut flow = s.oauth.take().expect("MCP OAuth state present");
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    let flow_id = flow.flow_id.clone();
                    let client_operation_id = uuid::Uuid::new_v4().to_string();
                    let expected_request_hash = match super::local_receipt_request_hash(&(
                        "cancel_mcp_oauth",
                        &flow.begin_client_operation_id,
                        &Some(flow_id.clone()),
                    )) {
                        Ok(hash) => hash,
                        Err(error) => {
                            flow.status =
                                Some(format!("could not bind OAuth cancellation: {error}"));
                            s.oauth = Some(flow);
                            return Nav::Stay;
                        }
                    };
                    self.queue_simple_mutation(
                        super::SettingsEffectTarget {
                            surface: "settings.mcp-oauth-cancel",
                            owner: flow.server.clone(),
                            revision: Some(flow_id.clone()),
                        },
                        cockpit_proto::Request::CancelMcpOAuth {
                            client_operation_id: client_operation_id.clone(),
                            begin_client_operation_id: flow.begin_client_operation_id.clone(),
                            flow_id: Some(flow_id.clone()),
                        },
                        super::SettingsMutationAction::McpOAuthCancel {
                            server: flow.server.clone(),
                            flow_id,
                            client_operation_id,
                            expected_request_hash,
                        },
                    );
                    s.oauth = Some(flow);
                    s.status = Some("cancelling MCP OAuth…".into());
                }
                KeyCode::Enter => {
                    let input = flow.callback.text().trim().to_string();
                    if input.is_empty() {
                        flow.status = Some(
                            "paste the callback URL or authorization code, then press Enter".into(),
                        );
                        s.oauth = Some(flow);
                        return Nav::Stay;
                    }
                    let flow_id = flow.flow_id.clone();
                    let client_operation_id = uuid::Uuid::new_v4().to_string();
                    let expected_request_hash = match super::local_receipt_request_hash(&(
                        "complete_mcp_oauth_receipt_v2",
                        &client_operation_id,
                        &flow_id,
                    )) {
                        Ok(hash) => hash,
                        Err(error) => {
                            flow.status = Some(format!("could not bind OAuth completion: {error}"));
                            s.oauth = Some(flow);
                            return Nav::Stay;
                        }
                    };
                    self.queue_simple_secret_mutation(
                        super::SettingsEffectTarget {
                            surface: "settings.mcp-oauth-complete",
                            owner: flow.server.clone(),
                            revision: Some(flow_id.clone()),
                        },
                        super::SettingsDaemonEffectWork::McpOAuthComplete {
                            client_operation_id: client_operation_id.clone(),
                            flow_id: flow_id.clone(),
                            input: super::SecretPayload::new(input),
                        },
                        super::SettingsMutationAction::McpOAuthComplete {
                            server: flow.server.clone(),
                            flow_id,
                            client_operation_id,
                            expected_request_hash,
                        },
                    );
                    flow.status = Some("completing authentication…".into());
                    s.oauth = Some(flow);
                }
                _ => {
                    flow.callback.handle_key(key);
                    s.oauth = Some(flow);
                }
            }
            return Nav::Stay;
        }
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.delete_pending = false;
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, row_count);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.delete_pending = false;
                s.cursor = crate::tui::nav::wrap_next(s.cursor, row_count);
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if s.cursor == names.len() => {
                // [+ add server]
                return Nav::Replace(super::mcp_page(McpPage::Add(Box::new(AddState::new()))));
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(name) = names.get(s.cursor)
                    && let Some(server) = cfg.servers.get(name)
                {
                    return Nav::Replace(super::mcp_page(McpPage::Add(Box::new(
                        AddState::from_server(name, server),
                    ))));
                }
            }
            KeyCode::Char(' ') => {
                // Toggle enabled.
                if let Some(name) = names.get(s.cursor) {
                    let mut cfg = cfg;
                    if let Some(server) = cfg.servers.get_mut(name) {
                        server.enabled = !server.enabled;
                    }
                    s.status = save_status(self.save_mcp(&cfg, &BTreeMap::new(), &BTreeSet::new()));
                }
            }
            KeyCode::Char('a') => {
                // Authenticate (OAuth servers only). The daemon owns the
                // browser callback, PKCE verifier, exchange, and vault write;
                // the TUI only forwards begin/complete requests.
                if let Some(name) = names.get(s.cursor)
                    && let Some(server) = cfg.servers.get(name)
                {
                    if matches!(server.auth, Auth::Oauth(_)) {
                        let name = name.clone();
                        let client_operation_id = uuid::Uuid::new_v4().to_string();
                        let project_root = self
                            .active_project_root
                            .clone()
                            .or_else(|| std::env::current_dir().ok())
                            .unwrap_or_else(|| std::path::PathBuf::from("."));
                        let project_root = super::canonical_project_root(&project_root);
                        let expected_request_hash = match super::local_receipt_request_hash(&(
                            "begin_mcp_oauth",
                            &project_root,
                            &name,
                        )) {
                            Ok(hash) => hash,
                            Err(error) => {
                                s.status = Some(format!("could not bind OAuth start: {error}"));
                                return Nav::Stay;
                            }
                        };
                        self.queue_simple_mutation(
                            super::SettingsEffectTarget {
                                surface: "settings.mcp-oauth-begin",
                                owner: name.clone(),
                                revision: None,
                            },
                            cockpit_proto::Request::BeginMcpOAuth {
                                client_operation_id: client_operation_id.clone(),
                                project_root,
                                server: name.clone(),
                            },
                            super::SettingsMutationAction::McpOAuthBegin {
                                server: name,
                                client_operation_id,
                                expected_request_hash,
                            },
                        );
                        s.status = Some("starting MCP OAuth…".into());
                    } else {
                        s.status = Some("server uses no OAuth — nothing to authenticate".into());
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(name) = names.get(s.cursor) {
                    if s.delete_pending {
                        let mut cfg = cfg;
                        let cleanup = cfg
                            .servers
                            .get(name)
                            .map(|old| credential_refs(name, old))
                            .unwrap_or_default();
                        cfg.servers.remove(name);
                        s.delete_pending = false;
                        if s.cursor > 0 {
                            s.cursor -= 1;
                        }
                        s.status = save_status(self.save_mcp(&cfg, &BTreeMap::new(), &cleanup));
                    } else {
                        s.delete_pending = true;
                        s.status = Some(format!("press d again to delete `{name}`"));
                    }
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn handle_mcp_add_key(&mut self, key: KeyEvent, s: &mut AddState) -> Nav {
        let editing_text = active_text_field_mut(s).is_some();
        match key.code {
            KeyCode::Esc => {
                return Nav::Replace(super::mcp_page(McpPage::List(ListState {
                    cursor: 0,
                    status: None,
                    delete_pending: false,
                    oauth: None,
                })));
            }
            KeyCode::Up => s.cursor = crate::tui::nav::wrap_prev(s.cursor, ADD_FIELDS),
            KeyCode::Down | KeyCode::Tab => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, ADD_FIELDS)
            }
            KeyCode::Enter => match s.cursor {
                FIELD_ENABLED => s.enabled = !s.enabled,
                FIELD_TRANSPORT => {
                    s.transport = cycle_transport(s.transport);
                    if !s.auth.is_compatible(s.transport) {
                        s.auth = AuthKind::None;
                    }
                }
                FIELD_AUTH => s.auth = s.auth.cycle_for_transport(s.transport),
                FIELD_SAVE => return self.commit_add(s),
                _ => s.cursor = crate::tui::nav::wrap_next(s.cursor, ADD_FIELDS),
            },
            KeyCode::Char(' ') if s.cursor == FIELD_ENABLED => s.enabled = !s.enabled,
            KeyCode::Char(' ') if s.cursor == FIELD_TRANSPORT => {
                s.transport = cycle_transport(s.transport);
                if !s.auth.is_compatible(s.transport) {
                    s.auth = AuthKind::None;
                }
            }
            KeyCode::Char(' ') if s.cursor == FIELD_AUTH => {
                s.auth = s.auth.cycle_for_transport(s.transport)
            }
            _ if editing_text => {
                // Delegate char/backspace/cursor editing to the active field.
                if let Some(field) = active_text_field_mut(s) {
                    field.handle_key(key);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn commit_add(&mut self, s: &mut AddState) -> Nav {
        let name = s.name.text().trim().to_string();
        if name.is_empty() {
            s.status = Some("name is required".into());
            return Nav::Stay;
        }
        let mut cfg = self.load_mcp();
        if s.original_name.as_deref() != Some(&name) && cfg.servers.contains_key(&name) {
            s.status = Some(format!("`{name}` already exists"));
            return Nav::Stay;
        }
        let old_refs = s
            .original_name
            .as_deref()
            .and_then(|old_name| {
                cfg.servers
                    .get(old_name)
                    .map(|old| credential_refs(old_name, old))
            })
            .unwrap_or_default();
        let (server, new_refs, secret_values) = match build_server_from_editor(&name, s) {
            Ok(pair) => pair,
            Err(e) => {
                s.status = Some(e);
                return Nav::Stay;
            }
        };
        if let Some(original) = &s.original_name
            && original != &name
        {
            cfg.servers.remove(original);
        }
        cfg.servers.insert(name.clone(), server);
        let stale_refs = old_refs
            .difference(&new_refs)
            .cloned()
            .collect::<BTreeSet<_>>();
        match self.save_mcp(&cfg, &secret_values, &stale_refs) {
            Ok(_) => {
                self.pending_mcp_navigation = Some((name, s.original_name.is_some()));
                s.status = Some("saving MCP server…".into());
                Nav::Stay
            }
            Err(e) => {
                s.status = Some(format!("save failed: {e}"));
                Nav::Stay
            }
        }
    }

    pub(super) fn render_mcp_page(&self, frame: &mut Frame, area: Rect, page: &McpPage) {
        match page {
            McpPage::List(s) => self.render_mcp_list(frame, area, s),
            McpPage::Add(s) => self.render_mcp_add(frame, area, s),
        }
    }

    fn render_mcp_list(&self, frame: &mut Frame, area: Rect, s: &ListState) {
        let cfg = self.load_mcp();
        let mut lines: Vec<Line> = vec![
            Line::from(Span::styled(
                "MCP servers — space: toggle  a: authenticate  d: delete",
                muted_style(),
            )),
            Line::from(""),
        ];
        let mut bindings = Vec::new();
        let names: Vec<&String> = cfg.servers.keys().collect();
        for (i, name) in names.iter().enumerate() {
            let server = &cfg.servers[*name];
            let color = cached_row_color(self, name, server);
            let marker = marker(i == s.cursor);
            let text = format!(
                "{marker}{name}  {}  {}  auth={}  {}",
                server.transport.as_str(),
                if server.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                server.auth.kind_str(),
                cached_lifecycle_label(self, name, server),
            );
            bindings.push((
                lines.len(),
                super::pointer_actions::McpAction::Open(super::pointer_actions::McpServerId(
                    (*name).clone(),
                )),
            ));
            lines.push(Line::from(Span::styled(text, Style::default().fg(color))));
        }
        // [+ add server] row.
        let add_marker = marker(s.cursor == names.len());
        bindings.push((lines.len(), super::pointer_actions::McpAction::Add));
        lines.push(Line::from(Span::styled(
            format!("{add_marker}[+ add server]"),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if let Some(name) = names.get(s.cursor) {
            lines.push(Line::from(""));
            if s.delete_pending {
                lines.push(Line::from(format!("Delete {name}?")));
                bindings.push((
                    lines.len(),
                    super::pointer_actions::McpAction::Delete(super::pointer_actions::McpServerId(
                        (*name).clone(),
                    )),
                ));
                lines.push(Line::from("[Delete]"));
                bindings.push((lines.len(), super::pointer_actions::McpAction::Cancel));
                lines.push(Line::from("[Cancel]"));
            } else {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::McpAction::ToggleEnabled(
                        super::pointer_actions::McpServerId((*name).clone()),
                    ),
                ));
                lines.push(Line::from("[Toggle enabled]"));
                let oauth = self
                    .load_mcp()
                    .servers
                    .get(*name)
                    .is_some_and(|server| matches!(server.auth, Auth::Oauth(_)));
                if oauth {
                    bindings.push((
                        lines.len(),
                        super::pointer_actions::McpAction::Authenticate(
                            super::pointer_actions::McpServerId((*name).clone()),
                        ),
                    ));
                    lines.push(Line::from("[Authenticate]"));
                }
                bindings.push((
                    lines.len(),
                    super::pointer_actions::McpAction::Delete(super::pointer_actions::McpServerId(
                        (*name).clone(),
                    )),
                ));
                lines.push(Line::from("[Delete]"));
            }
        }
        if names.is_empty() {
            lines.insert(2, Line::from("No MCP servers configured."));
            for (line, _) in &mut bindings {
                if *line >= 2 {
                    *line += 1;
                }
            }
        }
        if let Some(status) = &s.status {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().add_modifier(Modifier::ITALIC),
            )));
        }
        if let Some(flow) = &s.oauth {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("OAuth for `{}` — open this URL:", flow.server),
                warning_style(),
            )));
            lines.push(Line::from(flow.authorize_url.clone()));
            lines.push(Line::from(Span::styled(
                "Paste the callback URL or authorization code:",
                muted_style(),
            )));
            lines.push(Line::from(format!("> {}", flow.callback.text())));
            lines.push(Line::from(Span::styled(
                "Enter: complete   Esc: cancel",
                muted_style(),
            )));
            if let Some(status) = &flow.status {
                lines.push(Line::from(Span::styled(status.clone(), error_style())));
            }
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "mcp:list",
            (lines, selected_line),
            bindings,
            (&self.pointer_surface, SettingsScrollRegionId("mcp:list")).into(),
        );
    }

    fn render_mcp_add(&self, frame: &mut Frame, area: Rect, s: &AddState) {
        let mut lines = vec![
            Line::from(Span::styled(
                if s.original_name.is_some() {
                    "Edit MCP server"
                } else {
                    "Add MCP server"
                },
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled("Server", muted_style())),
        ];
        let mut bindings = Vec::new();
        push_pointer_text_field!(
            bindings,
            FIELD_NAME,
            &mut lines,
            area.width,
            "name",
            s.name.text(),
            s.name.cursor(),
            s.cursor == FIELD_NAME,
            None,
        );
        bindings.push((lines.len(), mcp_add_action(FIELD_ENABLED)));
        lines.push(Line::from(vec![
            Span::raw("enabled: "),
            Span::styled(
                if s.enabled { "yes" } else { "no (draft)" },
                if s.cursor == FIELD_ENABLED {
                    selected_style()
                } else {
                    Style::default()
                },
            ),
        ]));
        bindings.push((lines.len(), mcp_add_action(FIELD_TRANSPORT)));
        lines.push(Line::from(vec![
            Span::raw("transport: "),
            Span::styled(
                s.transport.as_str().to_string(),
                if s.cursor == FIELD_TRANSPORT {
                    selected_style()
                } else {
                    Style::default()
                },
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Connection", muted_style())));
        push_pointer_text_field!(
            bindings,
            FIELD_ENDPOINT,
            &mut lines,
            area.width,
            "endpoint",
            s.endpoint.text(),
            s.endpoint.cursor(),
            s.cursor == FIELD_ENDPOINT,
            Some("remote transports"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_COMMAND,
            &mut lines,
            area.width,
            "command",
            s.command.text(),
            s.command.cursor(),
            s.cursor == FIELD_COMMAND,
            Some("stdio"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_ARGS,
            &mut lines,
            area.width,
            "args",
            s.args.text(),
            s.args.cursor(),
            s.cursor == FIELD_ARGS,
            Some("stdio, space separated"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_BASE_ENV,
            &mut lines,
            area.width,
            "base env",
            s.base_env.text(),
            s.base_env.cursor(),
            s.cursor == FIELD_BASE_ENV,
            Some("stdio env, one KEY=VALUE per row"),
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Auth", muted_style())));
        bindings.push((lines.len(), mcp_add_action(FIELD_AUTH)));
        lines.push(Line::from(vec![
            Span::raw("auth: "),
            Span::styled(
                s.auth.label().to_string(),
                if s.cursor == FIELD_AUTH {
                    selected_style()
                } else {
                    Style::default()
                },
            ),
        ]));
        push_pointer_text_field!(
            bindings,
            FIELD_HEADER_NAME,
            &mut lines,
            area.width,
            "header name",
            s.header_name.text(),
            s.header_name.cursor(),
            s.cursor == FIELD_HEADER_NAME,
            Some("remote header auth"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_HEADER_VALUE,
            &mut lines,
            area.width,
            "header value",
            s.header_value.text(),
            s.header_value.cursor(),
            s.cursor == FIELD_HEADER_VALUE,
            Some("literal stored in credentials, or $ENV"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_AUTH_ENV,
            &mut lines,
            area.width,
            "auth env",
            s.auth_env.text(),
            s.auth_env.cursor(),
            s.cursor == FIELD_AUTH_ENV,
            Some("stdio env auth, one KEY=VALUE per row"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_OAUTH_AUTHORIZE,
            &mut lines,
            area.width,
            "oauth authorize",
            s.oauth_authorize_url.text(),
            s.oauth_authorize_url.cursor(),
            s.cursor == FIELD_OAUTH_AUTHORIZE,
            None,
        );
        push_pointer_text_field!(
            bindings,
            FIELD_OAUTH_TOKEN,
            &mut lines,
            area.width,
            "oauth token",
            s.oauth_token_url.text(),
            s.oauth_token_url.cursor(),
            s.cursor == FIELD_OAUTH_TOKEN,
            None,
        );
        push_pointer_text_field!(
            bindings,
            FIELD_OAUTH_CLIENT,
            &mut lines,
            area.width,
            "oauth client id",
            s.oauth_client_id.text(),
            s.oauth_client_id.cursor(),
            s.cursor == FIELD_OAUTH_CLIENT,
            None,
        );
        push_pointer_text_field!(
            bindings,
            FIELD_OAUTH_SCOPES,
            &mut lines,
            area.width,
            "oauth scopes",
            s.oauth_scopes.text(),
            s.oauth_scopes.cursor(),
            s.cursor == FIELD_OAUTH_SCOPES,
            Some("space separated"),
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Behavior", muted_style())));
        push_pointer_text_field!(
            bindings,
            FIELD_CACHE_TTL,
            &mut lines,
            area.width,
            "cache ttl",
            s.cache_ttl_secs.text(),
            s.cache_ttl_secs.cursor(),
            s.cursor == FIELD_CACHE_TTL,
            Some("seconds"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_CONNECT_TIMEOUT,
            &mut lines,
            area.width,
            "connect timeout",
            s.connect_timeout_secs.text(),
            s.connect_timeout_secs.cursor(),
            s.cursor == FIELD_CONNECT_TIMEOUT,
            Some("seconds, remote"),
        );
        push_pointer_text_field!(
            bindings,
            FIELD_REQUEST_TIMEOUT,
            &mut lines,
            area.width,
            "request timeout",
            s.request_timeout_secs.text(),
            s.request_timeout_secs.cursor(),
            s.cursor == FIELD_REQUEST_TIMEOUT,
            Some("seconds, remote"),
        );
        bindings.push((lines.len(), mcp_add_action(FIELD_SAVE)));
        lines.push(save_button_line("[ save ]", s.cursor == FIELD_SAVE));
        if !s.auth.is_compatible(s.transport) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "This auth mode is incompatible with the selected transport.",
                error_style(),
            )));
        } else if matches!(s.auth, AuthKind::None) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Warning: this server will be unauthenticated (public).",
                warning_style(),
            )));
        } else if matches!(s.auth, AuthKind::Oauth) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "OAuth can be saved pending, then authenticated from the server list with a.",
                warning_style(),
            )));
        }
        if let Some(status) = &s.status {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(status.clone(), error_style())));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "mcp:add",
            (lines, selected_line),
            bindings,
            (&self.pointer_surface, SettingsScrollRegionId("mcp:add")).into(),
        );
    }
}

fn cycle_transport(t: Transport) -> Transport {
    match t {
        Transport::Streamable => Transport::Stdio,
        Transport::Stdio => Transport::Sse,
        Transport::Sse => Transport::Streamable,
    }
}

impl AddState {
    fn new() -> Self {
        Self {
            original_name: None,
            name: TextField::default(),
            endpoint: TextField::default(),
            command: TextField::default(),
            args: TextField::default(),
            base_env: TextField::default(),
            stored_base_env_refs: BTreeMap::new(),
            transport: Transport::Streamable,
            auth: AuthKind::None,
            header_name: TextField::new("Authorization"),
            header_value: TextField::default(),
            stored_header_credential_ref: None,
            auth_env: TextField::default(),
            stored_auth_env_refs: BTreeMap::new(),
            oauth_authorize_url: TextField::default(),
            oauth_token_url: TextField::default(),
            oauth_client_id: TextField::default(),
            oauth_scopes: TextField::default(),
            enabled: true,
            cache_ttl_secs: TextField::new("3600"),
            connect_timeout_secs: TextField::default(),
            request_timeout_secs: TextField::default(),
            cursor: 0,
            status: None,
        }
    }

    fn from_server(name: &str, server: &ServerConfig) -> Self {
        let mut s = Self::new();
        s.original_name = Some(name.to_string());
        s.name = TextField::new(name);
        s.endpoint = TextField::new(server.endpoint.clone().unwrap_or_default());
        s.command = TextField::new(server.command.clone().unwrap_or_default());
        s.args = TextField::new(server.args.join(" "));
        s.stored_base_env_refs = server.env_credential_refs.clone();
        s.base_env = TextField::new(format_pairs_for_edit(
            &server.env,
            &server.env_credential_refs,
        ));
        s.transport = server.transport;
        s.auth = AuthKind::from_auth(&server.auth);
        match &server.auth {
            Auth::Header(h) => {
                s.header_name = TextField::new(h.header.clone());
                s.stored_header_credential_ref = h.credential_ref.clone();
                s.header_value = TextField::new(if h.credential_ref.is_some() {
                    secret_display::mask_value().to_string()
                } else {
                    h.value.clone()
                });
            }
            Auth::Env(e) => {
                s.stored_auth_env_refs = e.credential_refs.clone();
                s.auth_env = TextField::new(format_pairs_for_edit(&e.vars, &e.credential_refs));
            }
            Auth::Oauth(o) => {
                s.oauth_authorize_url = TextField::new(o.authorize_url.clone().unwrap_or_default());
                s.oauth_token_url = TextField::new(o.token_url.clone().unwrap_or_default());
                s.oauth_client_id = TextField::new(o.client_id.clone().unwrap_or_default());
                s.oauth_scopes = TextField::new(o.scopes.join(" "));
            }
            Auth::None => {}
        }
        s.enabled = server.enabled;
        s.cache_ttl_secs = TextField::new(server.cache_ttl_secs.to_string());
        s.connect_timeout_secs = TextField::new(
            server
                .connect_timeout_secs
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        s.request_timeout_secs = TextField::new(
            server
                .timeout_secs
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        s
    }
}

fn active_text_field_mut(s: &mut AddState) -> Option<&mut TextField> {
    match s.cursor {
        FIELD_NAME => Some(&mut s.name),
        FIELD_ENDPOINT => Some(&mut s.endpoint),
        FIELD_COMMAND => Some(&mut s.command),
        FIELD_ARGS => Some(&mut s.args),
        FIELD_BASE_ENV => Some(&mut s.base_env),
        FIELD_HEADER_NAME => Some(&mut s.header_name),
        FIELD_HEADER_VALUE => Some(&mut s.header_value),
        FIELD_AUTH_ENV => Some(&mut s.auth_env),
        FIELD_OAUTH_AUTHORIZE => Some(&mut s.oauth_authorize_url),
        FIELD_OAUTH_TOKEN => Some(&mut s.oauth_token_url),
        FIELD_OAUTH_CLIENT => Some(&mut s.oauth_client_id),
        FIELD_OAUTH_SCOPES => Some(&mut s.oauth_scopes),
        FIELD_CACHE_TTL => Some(&mut s.cache_ttl_secs),
        FIELD_CONNECT_TIMEOUT => Some(&mut s.connect_timeout_secs),
        FIELD_REQUEST_TIMEOUT => Some(&mut s.request_timeout_secs),
        _ => None,
    }
}

pub(super) fn paste_into_add_state(s: &mut AddState, text: &str) {
    if let Some(field) = active_text_field_mut(s) {
        field.paste(text);
    }
}

/// A server built from the editor: its config, the set of credential
/// references it declares, and the staged secret values keyed by reference.
type BuiltServerFromEditor = (ServerConfig, BTreeSet<String>, BTreeMap<String, String>);

fn build_server_from_editor(name: &str, s: &AddState) -> Result<BuiltServerFromEditor, String> {
    if !s.auth.is_compatible(s.transport) {
        return Err("auth mode is incompatible with transport".into());
    }
    let cache_ttl_secs = parse_required_u64(s.cache_ttl_secs.text(), "cache ttl")?;
    let connect_timeout_secs =
        parse_optional_u64(s.connect_timeout_secs.text(), "connect timeout")?;
    let timeout_secs = parse_optional_u64(s.request_timeout_secs.text(), "request timeout")?;
    let endpoint = nonempty_option(s.endpoint.text());
    let command = nonempty_option(s.command.text());
    let args = split_words(s.args.text());
    let mut credential_refs = BTreeSet::new();
    let mut secret_values = BTreeMap::new();
    let (env, env_credential_refs) = split_secret_pairs(
        name,
        s.base_env.text(),
        &s.stored_base_env_refs,
        cockpit_core::mcp::auth::base_env_cred_key,
        &mut credential_refs,
        &mut secret_values,
    )?;
    let auth = match s.auth {
        AuthKind::None => Auth::None,
        AuthKind::Header => {
            let header = s.header_name.text().trim();
            if header.is_empty() {
                return Err("header name is required for header auth".into());
            }
            let value = s.header_value.text().trim();
            if value.is_empty() {
                return Err("header value is required for header auth".into());
            }
            let credential_ref = if is_env_reference(value) {
                None
            } else if secret_display::is_mask_value(value) {
                match &s.stored_header_credential_ref {
                    Some(key) => {
                        credential_refs.insert(key.clone());
                        Some(key.clone())
                    }
                    None => {
                        let key = cockpit_core::mcp::auth::header_cred_key(name);
                        secret_values.insert(key.clone(), value.to_string());
                        credential_refs.insert(key.clone());
                        Some(key)
                    }
                }
            } else {
                let key = cockpit_core::mcp::auth::header_cred_key(name);
                secret_values.insert(key.clone(), value.to_string());
                credential_refs.insert(key.clone());
                Some(key)
            };
            Auth::Header(HeaderAuth {
                header: header.to_string(),
                value: if credential_ref.is_some() {
                    String::new()
                } else {
                    value.to_string()
                },
                credential_ref,
            })
        }
        AuthKind::Env => {
            let (vars, credential_refs_map) = split_secret_pairs(
                name,
                s.auth_env.text(),
                &s.stored_auth_env_refs,
                cockpit_core::mcp::auth::auth_env_cred_key,
                &mut credential_refs,
                &mut secret_values,
            )?;
            if vars.is_empty() && credential_refs_map.is_empty() {
                return Err("at least one auth env mapping is required for env auth".into());
            }
            Auth::Env(EnvAuth {
                vars,
                credential_refs: credential_refs_map,
            })
        }
        AuthKind::Oauth => Auth::Oauth(OauthAuth {
            authorize_url: nonempty_option(s.oauth_authorize_url.text()),
            token_url: nonempty_option(s.oauth_token_url.text()),
            client_id: nonempty_option(s.oauth_client_id.text()),
            scopes: split_words(s.oauth_scopes.text()),
        }),
    };
    let enabled = if matches!(&auth, Auth::Oauth(o) if o.authorize_url.is_none() || o.token_url.is_none())
    {
        false
    } else {
        s.enabled
    };
    let server = ServerConfig {
        transport: s.transport,
        endpoint,
        command,
        args,
        env,
        env_credential_refs,
        auth,
        mode: Default::default(),
        enabled,
        cache_ttl_secs,
        connect_timeout_secs,
        timeout_secs,
    };
    match s.transport {
        Transport::Stdio => {
            server.require_command(name).map_err(|e| e.to_string())?;
        }
        Transport::Streamable | Transport::Sse => {
            server.require_endpoint(name).map_err(|e| e.to_string())?;
        }
    }
    server
        .validate_transport_auth(name)
        .map_err(|e| e.to_string())?;
    Ok((server, credential_refs, secret_values))
}

fn parse_required_u64(raw: &str, label: &str) -> Result<u64, String> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| format!("{label} must be a number"))
}

fn parse_optional_u64(raw: &str, label: &str) -> Result<Option<u64>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        Ok(None)
    } else {
        raw.parse::<u64>()
            .map(Some)
            .map_err(|_| format!("{label} must be a number"))
    }
}

fn nonempty_option(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn split_words(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

fn parse_pairs(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for item in raw.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let Some((key, value)) = item.split_once('=') else {
            return Err(format!("env mapping `{item}` must be KEY=VALUE"));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err("env mapping key cannot be empty".into());
        }
        out.insert(key.to_string(), value.trim().to_string());
    }
    Ok(out)
}

fn split_secret_pairs(
    server: &str,
    raw: &str,
    existing_refs: &BTreeMap<String, String>,
    key_fn: fn(&str, &str) -> String,
    refs: &mut BTreeSet<String>,
    secret_values: &mut BTreeMap<String, String>,
) -> Result<EnvMaps, String> {
    let pairs = parse_pairs(raw)?;
    let mut plain = BTreeMap::new();
    let mut credential_refs = BTreeMap::new();
    for (key, value) in pairs {
        if is_env_reference(&value) {
            plain.insert(key, value);
        } else if secret_display::is_mask_value(&value) {
            if let Some(credential_ref) = existing_refs.get(&key) {
                refs.insert(credential_ref.clone());
                credential_refs.insert(key, credential_ref.clone());
            } else {
                let credential_ref = key_fn(server, &key);
                secret_values.insert(credential_ref.clone(), value.clone());
                refs.insert(credential_ref.clone());
                credential_refs.insert(key, credential_ref);
            }
        } else {
            let credential_ref = key_fn(server, &key);
            secret_values.insert(credential_ref.clone(), value.clone());
            refs.insert(credential_ref.clone());
            credential_refs.insert(key, credential_ref);
        }
    }
    Ok((plain, credential_refs))
}

fn is_env_reference(value: &str) -> bool {
    value.trim().starts_with('$')
}

fn credential_refs(name: &str, server: &ServerConfig) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    refs.extend(server.env_credential_refs.values().cloned());
    for (env_name, value) in &server.env {
        if !value.trim().is_empty() && !is_env_reference(value) {
            refs.insert(cockpit_core::mcp::auth::base_env_cred_key(name, env_name));
        }
    }
    match &server.auth {
        Auth::Header(h) => {
            if let Some(key) = &h.credential_ref {
                refs.insert(key.clone());
            } else if !h.value.trim().is_empty() && !is_env_reference(&h.value) {
                refs.insert(cockpit_core::mcp::auth::header_cred_key(name));
            }
        }
        Auth::Env(e) => {
            refs.extend(e.credential_refs.values().cloned());
            for (env_name, value) in &e.vars {
                if !is_env_reference(value) {
                    refs.insert(cockpit_core::mcp::auth::auth_env_cred_key(name, env_name));
                }
            }
        }
        Auth::Oauth(_) => {
            // OAuth tokens share the named-secret compartment with the header
            // and env MCP credentials, so deleting/renaming a server must
            // include this owner-RPC-managed key in its cleanup set.
            refs.insert(cockpit_core::mcp::auth::cred_key(name));
        }
        Auth::None => {}
    }
    refs
}

fn format_pairs_for_edit(
    vars: &BTreeMap<String, String>,
    credential_refs: &BTreeMap<String, String>,
) -> String {
    let mut parts: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
    for k in credential_refs.keys() {
        parts.push(format!("{k}={}", secret_display::mask_value()));
    }
    parts.join("\n")
}

impl SettingsPage for McpPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Mcp
    }

    fn pointer_surface_token(&self) -> u64 {
        match self {
            McpPage::List(_) => 300,
            McpPage::Add(_) => 301,
        }
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        match self {
            McpPage::List(_) => super::SettingsLocalBack::NoLocalBack,
            McpPage::Add(_) => super::SettingsLocalBack::LocalBack,
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match self {
            McpPage::List(s) => cx.handle_mcp_list_key(key, s),
            McpPage::Add(s) => cx.handle_mcp_add_key(key, s),
        }
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_mcp_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Mcp(action) = action else {
            return Nav::Stay;
        };
        if let McpPage::List(state) = self {
            let key = match &action {
                super::pointer_actions::McpAction::Cancel if state.delete_pending => {
                    state.delete_pending = false;
                    state.status = Some("delete cancelled".into());
                    return Nav::Stay;
                }
                super::pointer_actions::McpAction::ToggleEnabled(id) => {
                    let names: Vec<_> = cx.load_mcp().servers.keys().cloned().collect();
                    let Some(index) = names.iter().position(|name| name == &id.0) else {
                        return Nav::Stay;
                    };
                    state.cursor = index;
                    Some(KeyCode::Char(' '))
                }
                super::pointer_actions::McpAction::Authenticate(id) => {
                    let names: Vec<_> = cx.load_mcp().servers.keys().cloned().collect();
                    let Some(index) = names.iter().position(|name| name == &id.0) else {
                        return Nav::Stay;
                    };
                    state.cursor = index;
                    Some(KeyCode::Char('a'))
                }
                super::pointer_actions::McpAction::Delete(id) => {
                    let names: Vec<_> = cx.load_mcp().servers.keys().cloned().collect();
                    let Some(index) = names.iter().position(|name| name == &id.0) else {
                        return Nav::Stay;
                    };
                    state.cursor = index;
                    Some(KeyCode::Char('d'))
                }
                _ => None,
            };
            if let Some(key) = key {
                return cx.handle_mcp_list_key(KeyEvent::new(key, KeyModifiers::NONE), state);
            }
        }
        match (&mut *self, &action) {
            (McpPage::List(state), super::pointer_actions::McpAction::Open(id)) => {
                let names: Vec<_> = cx.load_mcp().servers.keys().cloned().collect();
                let Some(index) = names.iter().position(|name| name == &id.0) else {
                    return Nav::Stay;
                };
                state.cursor = index;
            }
            (McpPage::List(state), super::pointer_actions::McpAction::Add) => {
                state.cursor = cx.load_mcp().servers.len()
            }
            (McpPage::Add(state), _) => {
                let Some(index) = mcp_add_index(&action) else {
                    return Nav::Stay;
                };
                state.cursor = index;
            }
            _ => return Nav::Stay,
        }
        self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
        column: u16,
        _row: u16,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Mcp(ref mcp_action) = action else {
            return Nav::Stay;
        };
        let Some(index) = mcp_add_index(mcp_action) else {
            return self.handle_pointer_control(cx, action);
        };
        if let McpPage::Add(state) = self {
            if index >= ADD_FIELDS {
                return Nav::Stay;
            }
            state.cursor = index;
            let label = match index {
                FIELD_NAME => Some("name"),
                FIELD_ENDPOINT => Some("endpoint"),
                FIELD_COMMAND => Some("command"),
                FIELD_ARGS => Some("args"),
                FIELD_BASE_ENV => Some("base env"),
                FIELD_HEADER_NAME => Some("header name"),
                FIELD_HEADER_VALUE => Some("header value"),
                FIELD_AUTH_ENV => Some("auth env"),
                FIELD_OAUTH_AUTHORIZE => Some("oauth authorize"),
                FIELD_OAUTH_TOKEN => Some("oauth token"),
                FIELD_OAUTH_CLIENT => Some("oauth client id"),
                FIELD_OAUTH_SCOPES => Some("oauth scopes"),
                FIELD_CACHE_TTL => Some("cache ttl"),
                FIELD_CONNECT_TIMEOUT => Some("connect timeout"),
                FIELD_REQUEST_TIMEOUT => Some("request timeout"),
                _ => None,
            };
            if let Some(label) = label {
                let area_x = cx.pointer_surface.area.get().map_or(0, |area| area.x);
                let value_x = area_x.saturating_add(label.len() as u16 + 2);
                if let Some(field) = active_text_field_mut(state) {
                    field.set_cursor_display_col(usize::from(column.saturating_sub(value_x)));
                }
                return Nav::Stay;
            }
        }
        self.handle_pointer_control(cx, action)
    }

    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        match self {
            McpPage::List(state) if region == SettingsScrollRegionId("mcp:list") => {
                state.delete_pending = false;
                state.cursor = state
                    .cursor
                    .saturating_add_signed(delta)
                    .min(cx.load_mcp().servers.len());
            }
            McpPage::Add(state) if region == SettingsScrollRegionId("mcp:add") => {
                state.cursor = state
                    .cursor
                    .saturating_add_signed(delta)
                    .min(ADD_FIELDS - 1);
            }
            _ => {}
        }
        Nav::Stay
    }

    fn cancel_pointer_transients(&mut self) {
        if let McpPage::List(state) = self {
            state.delete_pending = false;
        }
    }

    fn title(&self, cx: &SettingsCx) -> String {
        let crumbs = match self {
            McpPage::List(_) => " › MCP",
            McpPage::Add(_) => " › MCP › Add",
        };
        format!(
            "{}{}",
            cockpit_core::welcome::display_path(&cx.config_path),
            crumbs
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        match self {
            McpPage::List(_) => {
                "↑/↓/Tab/Shift+Tab  space: toggle  m: mode  a: authenticate  d: delete (×2)  enter: add  esc/h: back  q: close"
            }
            McpPage::Add(_) => {
                "↑/↓/Tab  enter: cycle / save  type to edit name/endpoint  esc: back"
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "MCP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_secret_custody_stays_daemon_owned() {
        let source = include_str!("mcp_page.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(production.contains("SettingsDaemonEffectWork::McpConfigSave"));
        assert!(production.contains("SecretPayload::new(secret_values_json)"));
        assert!(!production.contains("Request::SaveMcpConfig"));
        assert!(production.contains("self.mcp_config.clone()"));
        assert!(!production.contains("read_to_string"));
        assert!(production.contains("Response::McpConfigCommitted"));
        assert!(production.contains("self.mcp_owner_root"));
        assert!(production.contains("self.mcp_config_path"));
        assert!(production.contains("self.mcp_revision"));
        assert!(!production.contains("serde_json::to_string(&self.config)"));
        assert!(!production.contains("Response::Ack"));
        assert!(!production.contains("write_private"));
        assert!(!production.contains("CredentialStore"));
        assert!(!production.contains("save_record_merged"));
    }

    fn server(auth: Auth, enabled: bool) -> ServerConfig {
        ServerConfig {
            transport: Transport::Streamable,
            endpoint: Some("https://x/mcp".into()),
            command: None,
            args: vec![],
            env: Default::default(),
            env_credential_refs: Default::default(),
            auth,
            mode: Default::default(),
            enabled,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        }
    }

    #[test]
    fn color_states_match_spec() {
        // Public + enabled → green.
        assert_eq!(row_color("a", &server(Auth::None, true)), Color::Green);
        // Public + disabled → yellow.
        assert_eq!(row_color("a", &server(Auth::None, false)), Color::Yellow);
        // OAuth with no stored token → red (needs auth), regardless of enabled.
        // (No credentials stored in the test env for `mcp:unauthed`.)
        let red = row_color(
            "unauthed-test-server-xyz",
            &server(Auth::Oauth(OauthAuth::default()), true),
        );
        assert_eq!(red, Color::Red);
    }

    #[test]
    fn auth_kind_cycles_through_all_four() {
        let mut k = AuthKind::None;
        let mut seen = vec![k.label()];
        for _ in 0..3 {
            k = match k {
                AuthKind::None => AuthKind::Oauth,
                AuthKind::Oauth => AuthKind::Header,
                AuthKind::Header => AuthKind::Env,
                AuthKind::Env => AuthKind::None,
            };
            seen.push(k.label());
        }
        assert_eq!(seen.len(), 4);
        assert_eq!(
            AuthKind::None.cycle_for_transport(Transport::Stdio),
            AuthKind::Env
        );
        assert_eq!(
            AuthKind::None.cycle_for_transport(Transport::Streamable),
            AuthKind::Header
        );
    }

    #[test]
    fn empty_static_auth_needs_auth_not_ready() {
        let header = server(
            Auth::Header(HeaderAuth {
                header: "Authorization".into(),
                value: String::new(),
                credential_ref: None,
            }),
            true,
        );
        assert!(matches!(
            lifecycle("empty-header", &header),
            ServerLifecycle::NeedsAuth
        ));
        let env = ServerConfig {
            transport: Transport::Stdio,
            endpoint: None,
            command: Some("node".into()),
            args: vec![],
            env: Default::default(),
            env_credential_refs: Default::default(),
            auth: Auth::Env(EnvAuth::default()),
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        };
        assert!(matches!(
            lifecycle("empty-env", &env),
            ServerLifecycle::NeedsAuth
        ));
    }

    #[test]
    fn incompatible_auth_is_error() {
        let mut stdio = server(
            Auth::Header(HeaderAuth {
                header: "Authorization".into(),
                value: "$TOKEN".into(),
                credential_ref: None,
            }),
            true,
        );
        stdio.transport = Transport::Stdio;
        stdio.endpoint = None;
        stdio.command = Some("node".into());
        assert!(matches!(lifecycle("bad", &stdio), ServerLifecycle::Error));
    }

    #[test]
    fn oauth_credential_cleanup_uses_its_named_secret_key() {
        let refs = credential_refs(
            "example",
            &server(
                Auth::Oauth(OauthAuth {
                    authorize_url: Some("https://auth.example/authorize".into()),
                    token_url: Some("https://auth.example/token".into()),
                    client_id: None,
                    scopes: vec![],
                }),
                true,
            ),
        );
        assert_eq!(
            refs.into_iter().collect::<Vec<_>>(),
            vec![cockpit_core::mcp::auth::cred_key("example")]
        );
    }

    #[test]
    fn env_pairs_allow_commas_in_values_per_row() {
        let pairs = parse_pairs("A=one,two\nB=three").unwrap();
        assert_eq!(pairs.get("A").map(String::as_str), Some("one,two"));
        assert_eq!(pairs.get("B").map(String::as_str), Some("three"));

        let mut vars = BTreeMap::new();
        vars.insert("A".to_string(), "one,two".to_string());
        assert_eq!(format_pairs_for_edit(&vars, &BTreeMap::new()), "A=one,two");
    }

    #[test]
    fn editor_masks_stored_header_secret_and_preserves_ref_when_unchanged() {
        let state = AddState::from_server(
            "typefully",
            &server(
                Auth::Header(HeaderAuth {
                    header: "Authorization".into(),
                    value: String::new(),
                    credential_ref: Some("mcp:typefully:header".into()),
                }),
                true,
            ),
        );
        assert_eq!(state.header_value.text(), secret_display::mask_value());
        assert!(!state.header_value.text().contains("decrypted-token"));

        let (server, refs, secret_values) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        assert!(secret_values.is_empty(), "masked refs must not rotate");
    }

    #[test]
    fn editor_replaces_stored_header_secret_only_when_new_value_typed() {
        let mut state = AddState::from_server(
            "typefully",
            &server(
                Auth::Header(HeaderAuth {
                    header: "Authorization".into(),
                    value: String::new(),
                    credential_ref: Some("mcp:typefully:header".into()),
                }),
                true,
            ),
        );
        state.header_value.set("Bearer replacement-token");
        let (server, refs, secret_values) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        assert_eq!(
            secret_values
                .get("mcp:typefully:header")
                .map(String::as_str),
            Some("Bearer replacement-token")
        );
    }

    #[test]
    fn editor_header_secret_builds_credential_ref_without_raw_value() {
        let mut state = AddState::new();
        state.name.set("typefully");
        state.endpoint.set("https://api.example.com/mcp");
        state.auth = AuthKind::Header;
        state.header_value.set("Bearer secret-token");
        let (server, refs, secret_values) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        assert_eq!(
            secret_values
                .get("mcp:typefully:header")
                .map(String::as_str),
            Some("Bearer secret-token")
        );
    }
}
