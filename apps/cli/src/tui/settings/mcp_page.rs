//! `/settings → MCP` page (GOALS §18a).
//!
//! Edits the sibling `mcp.json` in the same `.cockpit/` directory as the
//! settings dialog's `config.json`. Two views:
//!   - **List**: every configured server with transport, enabled, and auth
//!     status, color-coded (green = ready + enabled, yellow = ready + not
//!     enabled, red = needs auth + not authed). Per-server actions: toggle
//!     enabled (`space`), authenticate (`a`). Plus `[+ add server]` and
//!     delete (`d`).
//!   - **Add**: name + cycled transport / auth + endpoint-or-command
//!     text field, with a warning when auth is `none`.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use std::collections::{BTreeMap, BTreeSet};

use crate::mcp::config::{
    Auth, EnvAuth, HeaderAuth, McpConfig, OauthAuth, ServerConfig, Transport,
};
use crate::tui::textfield::TextField;

use super::secret_display;
use super::shell::{
    error_style, marker, muted_style, push_text_field, selected_line_from_marker, selected_style,
    warning_style,
};
use super::{Nav, Page, SettingsDialog, save_button_line, save_status};

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
        Auth::Oauth(_) => {
            // OAuth is ready iff a token is stored for `mcp:<name>`.
            let stored = crate::credentials::CredentialStore::open_default()
                .ok()
                .and_then(|store| store.get(&crate::mcp::auth::cred_key(name)).cloned())
                .is_some();
            if stored {
                ServerLifecycle::Ready
            } else {
                ServerLifecycle::NeedsAuth
            }
        }
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

/// The color for a server row (GOALS §18a):
/// green = ready + enabled, yellow = ready + disabled, red = needs auth.
pub(crate) fn row_color(name: &str, s: &ServerConfig) -> Color {
    match lifecycle(name, s) {
        ServerLifecycle::Error | ServerLifecycle::NeedsAuth => Color::Red,
        ServerLifecycle::Ready => Color::Green,
        ServerLifecycle::DisabledDraft => Color::Yellow,
    }
}

impl SettingsDialog {
    /// The path to the sibling `mcp.json` (same dir as `config.json`).
    pub(super) fn mcp_path(&self) -> std::path::PathBuf {
        self.config_path
            .parent()
            .map(|p| p.join("mcp.json"))
            .unwrap_or_else(|| std::path::PathBuf::from("mcp.json"))
    }

    pub(super) fn load_mcp(&self) -> McpConfig {
        std::fs::read_to_string(self.mcp_path())
            .ok()
            .and_then(|raw| McpConfig::parse(&raw).ok())
            .unwrap_or_default()
    }

    fn save_mcp(&self, cfg: &McpConfig) -> Result<(), String> {
        let path = self.mcp_path();
        cfg.write_private(&path).map_err(|e| e.to_string())
    }

    pub(super) fn enter_mcp(&mut self) {
        self.page = Page::Mcp(McpPage::List(ListState {
            cursor: 0,
            status: None,
            delete_pending: false,
        }));
    }

    pub(super) fn handle_mcp_key(&mut self, key: KeyEvent) -> bool {
        // Swap the page out so we can mutate it without borrowing `self`.
        let mut page = std::mem::replace(
            &mut self.page,
            Page::Mcp(McpPage::List(ListState {
                cursor: 0,
                status: None,
                delete_pending: false,
            })),
        );
        let nav = match &mut page {
            Page::Mcp(McpPage::List(s)) => self.handle_mcp_list_key(key, s),
            Page::Mcp(McpPage::Add(s)) => self.handle_mcp_add_key(key, s),
            _ => Nav::Close,
        };
        match nav {
            Nav::Stay => {
                self.page = page;
                false
            }
            Nav::Replace(p) => {
                self.page = p;
                false
            }
            Nav::Close => true,
        }
    }

    fn handle_mcp_list_key(&mut self, key: KeyEvent, s: &mut ListState) -> Nav {
        let cfg = self.load_mcp();
        let names: Vec<String> = cfg.servers.keys().cloned().collect();
        let row_count = names.len() + 1; // + [+ add server]
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                return Nav::Replace(Page::Root {
                    cursor: self.last_root_cursor,
                });
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
                return Nav::Replace(Page::Mcp(McpPage::Add(Box::new(AddState::new()))));
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(name) = names.get(s.cursor)
                    && let Some(server) = cfg.servers.get(name)
                {
                    return Nav::Replace(Page::Mcp(McpPage::Add(Box::new(AddState::from_server(
                        name, server,
                    )))));
                }
            }
            KeyCode::Char(' ') => {
                // Toggle enabled.
                if let Some(name) = names.get(s.cursor) {
                    let mut cfg = cfg;
                    if let Some(server) = cfg.servers.get_mut(name) {
                        server.enabled = !server.enabled;
                    }
                    s.status = save_status(self.save_mcp(&cfg));
                }
            }
            KeyCode::Char('a') => {
                // Authenticate (OAuth servers only). Runs the flow inline.
                if let Some(name) = names.get(s.cursor)
                    && let Some(server) = cfg.servers.get(name)
                {
                    if matches!(server.auth, Auth::Oauth(_)) {
                        let name = name.clone();
                        let server = server.clone();
                        let res = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current()
                                .block_on(crate::mcp::auth::run_oauth_flow(&name, &server))
                        });
                        s.status = Some(match res {
                            Ok(_) => format!("authenticated `{name}`"),
                            Err(e) => format!("auth failed: {e}"),
                        });
                    } else {
                        s.status = Some("server uses no OAuth — nothing to authenticate".into());
                    }
                }
            }
            KeyCode::Char('d') => {
                if let Some(name) = names.get(s.cursor) {
                    if s.delete_pending {
                        let mut cfg = cfg;
                        if let Some(old) = cfg.servers.remove(name) {
                            let _ = remove_credential_refs(&credential_refs(name, &old));
                        }
                        s.delete_pending = false;
                        if s.cursor > 0 {
                            s.cursor -= 1;
                        }
                        s.status = save_status(self.save_mcp(&cfg));
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
                return Nav::Replace(Page::Mcp(McpPage::List(ListState {
                    cursor: 0,
                    status: None,
                    delete_pending: false,
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
        let (server, new_refs) = match build_server_from_editor(&name, s) {
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
        if let Err(e) = reconcile_credential_refs(&old_refs, &new_refs) {
            s.status = Some(format!("credential cleanup failed: {e}"));
            return Nav::Stay;
        }
        match self.save_mcp(&cfg) {
            Ok(()) => Nav::Replace(Page::Mcp(McpPage::List(ListState {
                cursor: 0,
                status: Some(if s.original_name.is_some() {
                    format!("saved `{name}`")
                } else {
                    format!("added `{name}`")
                }),
                delete_pending: false,
            }))),
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
        let names: Vec<&String> = cfg.servers.keys().collect();
        for (i, name) in names.iter().enumerate() {
            let server = &cfg.servers[*name];
            let color = row_color(name, server);
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
                lifecycle_label(name, server),
            );
            lines.push(Line::from(Span::styled(text, Style::default().fg(color))));
        }
        // [+ add server] row.
        let add_marker = marker(s.cursor == names.len());
        lines.push(Line::from(Span::styled(
            format!("{add_marker}[+ add server]"),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        if names.is_empty() {
            lines.insert(2, Line::from("No MCP servers configured."));
        }
        if let Some(status) = &s.status {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().add_modifier(Modifier::ITALIC),
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "mcp:list", lines, selected_line);
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
        push_text_field(
            &mut lines,
            area.width,
            "name",
            s.name.text(),
            s.cursor == FIELD_NAME,
            None,
        );
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
        push_text_field(
            &mut lines,
            area.width,
            "endpoint",
            s.endpoint.text(),
            s.cursor == FIELD_ENDPOINT,
            Some("remote transports"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "command",
            s.command.text(),
            s.cursor == FIELD_COMMAND,
            Some("stdio"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "args",
            s.args.text(),
            s.cursor == FIELD_ARGS,
            Some("stdio, space separated"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "base env",
            s.base_env.text(),
            s.cursor == FIELD_BASE_ENV,
            Some("stdio env, one KEY=VALUE per row"),
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Auth", muted_style())));
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
        push_text_field(
            &mut lines,
            area.width,
            "header name",
            s.header_name.text(),
            s.cursor == FIELD_HEADER_NAME,
            Some("remote header auth"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "header value",
            s.header_value.text(),
            s.cursor == FIELD_HEADER_VALUE,
            Some("literal stored in credentials, or $ENV"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "auth env",
            s.auth_env.text(),
            s.cursor == FIELD_AUTH_ENV,
            Some("stdio env auth, one KEY=VALUE per row"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "oauth authorize",
            s.oauth_authorize_url.text(),
            s.cursor == FIELD_OAUTH_AUTHORIZE,
            None,
        );
        push_text_field(
            &mut lines,
            area.width,
            "oauth token",
            s.oauth_token_url.text(),
            s.cursor == FIELD_OAUTH_TOKEN,
            None,
        );
        push_text_field(
            &mut lines,
            area.width,
            "oauth client id",
            s.oauth_client_id.text(),
            s.cursor == FIELD_OAUTH_CLIENT,
            None,
        );
        push_text_field(
            &mut lines,
            area.width,
            "oauth scopes",
            s.oauth_scopes.text(),
            s.cursor == FIELD_OAUTH_SCOPES,
            Some("space separated"),
        );
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Behavior", muted_style())));
        push_text_field(
            &mut lines,
            area.width,
            "cache ttl",
            s.cache_ttl_secs.text(),
            s.cursor == FIELD_CACHE_TTL,
            Some("seconds"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "connect timeout",
            s.connect_timeout_secs.text(),
            s.cursor == FIELD_CONNECT_TIMEOUT,
            Some("seconds, remote"),
        );
        push_text_field(
            &mut lines,
            area.width,
            "request timeout",
            s.request_timeout_secs.text(),
            s.cursor == FIELD_REQUEST_TIMEOUT,
            Some("seconds, remote"),
        );
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
        self.scroll_states
            .render_lines(frame, area, "mcp:add", lines, selected_line);
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

fn build_server_from_editor(
    name: &str,
    s: &AddState,
) -> Result<(ServerConfig, BTreeSet<String>), String> {
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
    let (env, env_credential_refs) = split_secret_pairs(
        name,
        s.base_env.text(),
        &s.stored_base_env_refs,
        crate::mcp::auth::base_env_cred_key,
        &mut credential_refs,
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
                        let key = crate::mcp::auth::header_cred_key(name);
                        store_secret(&key, value).map_err(|e| e.to_string())?;
                        credential_refs.insert(key.clone());
                        Some(key)
                    }
                }
            } else {
                let key = crate::mcp::auth::header_cred_key(name);
                store_secret(&key, value).map_err(|e| e.to_string())?;
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
                crate::mcp::auth::auth_env_cred_key,
                &mut credential_refs,
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
    Ok((server, credential_refs))
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
                store_secret(&credential_ref, &value).map_err(|e| e.to_string())?;
                refs.insert(credential_ref.clone());
                credential_refs.insert(key, credential_ref);
            }
        } else {
            let credential_ref = key_fn(server, &key);
            store_secret(&credential_ref, &value).map_err(|e| e.to_string())?;
            refs.insert(credential_ref.clone());
            credential_refs.insert(key, credential_ref);
        }
    }
    Ok((plain, credential_refs))
}

fn is_env_reference(value: &str) -> bool {
    value.trim().starts_with('$')
}

fn store_secret(key: &str, value: &str) -> anyhow::Result<()> {
    let store = crate::credentials::CredentialStore::open_default()?;
    store.save_record_merged(key, serde_json::json!({ "secret": value }))
}

fn remove_credential_refs(refs: &BTreeSet<String>) -> anyhow::Result<()> {
    let store = crate::credentials::CredentialStore::open_default()?;
    for key in refs {
        store.remove_record_merged(key)?;
    }
    Ok(())
}

fn reconcile_credential_refs(
    old_refs: &BTreeSet<String>,
    new_refs: &BTreeSet<String>,
) -> anyhow::Result<()> {
    let stale: BTreeSet<String> = old_refs.difference(new_refs).cloned().collect();
    if stale.is_empty() {
        Ok(())
    } else {
        remove_credential_refs(&stale)
    }
}

fn credential_refs(name: &str, server: &ServerConfig) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    refs.extend(server.env_credential_refs.values().cloned());
    match &server.auth {
        Auth::Header(h) => {
            if let Some(key) = &h.credential_ref {
                refs.insert(key.clone());
            } else if !h.value.trim().is_empty() && !is_env_reference(&h.value) {
                refs.insert(crate::mcp::auth::header_cred_key(name));
            }
        }
        Auth::Env(e) => {
            refs.extend(e.credential_refs.values().cloned());
            for (env_name, value) in &e.vars {
                if !is_env_reference(value) {
                    refs.insert(crate::mcp::auth::auth_env_cred_key(name, env_name));
                }
            }
        }
        Auth::Oauth(_) | Auth::None => {}
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::daemon::test_harness::lock_env();
        let old_xdg = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };
        let store = crate::credentials::CredentialStore::open_default().unwrap();
        store
            .save_record_merged(
                "mcp:typefully:header",
                serde_json::json!({ "secret": "Bearer decrypted-token" }),
            )
            .unwrap();

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

        let (server, refs) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        let reloaded =
            crate::credentials::CredentialStore::open(store.path().to_path_buf()).unwrap();
        assert_eq!(
            reloaded
                .get("mcp:typefully:header")
                .and_then(|v| v.get("secret"))
                .and_then(|v| v.as_str()),
            Some("Bearer decrypted-token")
        );
        match old_xdg {
            Some(value) => unsafe { std::env::set_var("XDG_STATE_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }

    #[test]
    fn editor_replaces_stored_header_secret_only_when_new_value_typed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::daemon::test_harness::lock_env();
        let old_xdg = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };
        let store = crate::credentials::CredentialStore::open_default().unwrap();
        store
            .save_record_merged(
                "mcp:typefully:header",
                serde_json::json!({ "secret": "Bearer old-token" }),
            )
            .unwrap();

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
        let (server, refs) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        let reloaded =
            crate::credentials::CredentialStore::open(store.path().to_path_buf()).unwrap();
        assert_eq!(
            reloaded
                .get("mcp:typefully:header")
                .and_then(|v| v.get("secret"))
                .and_then(|v| v.as_str()),
            Some("Bearer replacement-token")
        );
        match old_xdg {
            Some(value) => unsafe { std::env::set_var("XDG_STATE_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }

    #[test]
    fn editor_header_secret_builds_credential_ref_without_raw_value() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::daemon::test_harness::lock_env();
        let old_xdg = std::env::var_os("XDG_STATE_HOME");
        // SAFETY: settings tests in this module run synchronously here and only
        // need XDG_STATE_HOME isolated for this store write/read.
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };
        let mut state = AddState::new();
        state.name.set("typefully");
        state.endpoint.set("https://api.example.com/mcp");
        state.auth = AuthKind::Header;
        state.header_value.set("Bearer secret-token");
        let (server, refs) = build_server_from_editor("typefully", &state).unwrap();
        match server.auth {
            Auth::Header(h) => {
                assert!(h.value.is_empty());
                assert_eq!(h.credential_ref.as_deref(), Some("mcp:typefully:header"));
            }
            other => panic!("expected header auth, got {other:?}"),
        }
        assert!(refs.contains("mcp:typefully:header"));
        let store = crate::credentials::CredentialStore::open_default().unwrap();
        assert_eq!(
            store
                .get("mcp:typefully:header")
                .and_then(|v| v.get("secret"))
                .and_then(|v| v.as_str()),
            Some("Bearer secret-token")
        );
        match old_xdg {
            Some(value) => unsafe { std::env::set_var("XDG_STATE_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
    }
}
