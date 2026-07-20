//! `/settings -> Tools` page: effective web tools, builtin inventory,
//! user-defined command tools, and MCP catalog visibility.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::settings::secret_display::{MASKED_VALUE, mask_value};
use crate::tui::textfield::TextField;
use cockpit_config::extended::{ToolCommandTemplate, WebConfig, WebProvider as ConfigWebProvider};
use cockpit_core::credentials::CredentialStore;
use cockpit_core::engine::builtin::{builtin_tool_inventory, is_reserved_custom_tool_name};
use cockpit_core::mcp::cache;
use cockpit_core::mcp::protocol::{ToolDescriptor, sanitize_tool_descriptor};

use super::mcp_page::{ListState as McpListState, McpPage};
use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    WrappedValueLayout, focused_field_style, muted_style, push_text_field_at_cursor,
    push_wrapped_prefixed_value, selected_line_from_marker, selected_style, warning_style,
};
use super::{Nav, SettingsCx, SettingsPage, save_status};

const TOOL_ROW_MARKER_WIDTH: usize = 2;
const TOOL_ROW_LABEL_WIDTH: usize = 18;
const TOOL_ROW_GAP_WIDTH: usize = 2;
const TOOL_ROW_VALUE_INDENT: usize =
    TOOL_ROW_MARKER_WIDTH + TOOL_ROW_LABEL_WIDTH + TOOL_ROW_GAP_WIDTH;

/// `/settings -> Tools` state.
pub(super) struct ToolsPage {
    pub(super) cursor: usize,
    pub(super) editing: Option<ToolField>,
    pub(super) buf: TextField,
    pub(super) status: Option<String>,
    pub(super) reset: ResetButton,
    pub(super) delete_pending: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ToolField {
    WebFetchCommand,
    WebSearchCommand,
    WebKey(WebKeyProvider),
    FirecrawlBaseUrl,
    NewToolName,
    UserToolCommand(String),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum WebKeyProvider {
    Firecrawl,
    TinyFish,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ToolRow {
    WebProvider,
    FirecrawlBaseUrl,
    FirecrawlKey,
    TinyFishKey,
    WebFetchCommand,
    WebSearchCommand,
    Builtin(&'static str),
    UserTool(String),
    AddUserTool,
    McpTool { server: String, tool: String },
    McpJump,
    Reset,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum WebKeyStatus {
    Env,
    Stored,
}

fn web_key_provider_id(provider: WebKeyProvider) -> &'static str {
    match provider {
        WebKeyProvider::Firecrawl => "firecrawl",
        WebKeyProvider::TinyFish => "tinyfish",
    }
}

fn web_key_env(provider: WebKeyProvider) -> &'static str {
    match provider {
        WebKeyProvider::Firecrawl => "FIRECRAWL_API_KEY",
        WebKeyProvider::TinyFish => "TINYFISH_API_KEY",
    }
}

fn web_key_provider_label(provider: WebKeyProvider) -> &'static str {
    match provider {
        WebKeyProvider::Firecrawl => "Firecrawl",
        WebKeyProvider::TinyFish => "TinyFish",
    }
}

fn web_key_status_label(status: Option<WebKeyStatus>) -> String {
    match status {
        Some(WebKeyStatus::Env) => format!("detected via env ({MASKED_VALUE})"),
        Some(WebKeyStatus::Stored) => format!("stored credential ({MASKED_VALUE})"),
        None => "none".to_string(),
    }
}

fn masked_edit_value(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        mask_value().to_string()
    }
}

fn valid_http_url(raw: &str) -> bool {
    reqwest::Url::parse(raw)
        .ok()
        .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn provider_label(provider: ConfigWebProvider) -> &'static str {
    match provider {
        ConfigWebProvider::Firecrawl => "Firecrawl",
        ConfigWebProvider::Tinyfish => "TinyFish",
        ConfigWebProvider::Custom => "Custom",
    }
}

impl SettingsCx {
    fn handle_tools_page_key(&mut self, key: KeyEvent, p: &mut ToolsPage) -> Nav {
        if let Some(field) = p.editing.clone() {
            match key.code {
                KeyCode::Enter => {
                    self.apply_tools_edit(p, field);
                }
                KeyCode::Esc => {
                    p.editing = None;
                    p.status = None;
                }
                _ => {
                    p.buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        let rows = self.tools_page_rows();
        if rows.is_empty() {
            p.cursor = 0;
        } else if p.cursor >= rows.len() {
            p.cursor = rows.len() - 1;
        }
        let total_rows = rows.len().max(1);

        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.reset.disarm();
                p.delete_pending = None;
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, total_rows);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.reset.disarm();
                p.delete_pending = None;
                p.cursor = crate::tui::nav::wrap_next(p.cursor, total_rows);
            }
            KeyCode::Char('d') => {
                if let Some(ToolRow::UserTool(name)) = rows.get(p.cursor) {
                    self.delete_user_tool(p, name);
                }
            }
            KeyCode::Char('t') => {
                if let Some(row) = rows.get(p.cursor) {
                    self.toggle_tools_row(p, row);
                }
            }
            KeyCode::Char('r') => {
                if let Some(row) = rows.get(p.cursor) {
                    self.reset_tools_row(p, row);
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(row) = rows.get(p.cursor) {
                    return self.activate_tools_row(p, row);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn apply_tools_edit(&mut self, p: &mut ToolsPage, field: ToolField) {
        match field {
            ToolField::WebFetchCommand => {
                let new = p.buf.text().trim().to_string();
                self.extended.web.custom.fetch_command =
                    if new.is_empty() { None } else { Some(new) };
                p.status = save_status(self.save_extended());
                p.editing = None;
            }
            ToolField::WebSearchCommand => {
                let new = p.buf.text().trim().to_string();
                self.extended.web.custom.search_command =
                    if new.is_empty() { None } else { Some(new) };
                p.status = save_status(self.save_extended());
                p.editing = None;
            }
            ToolField::WebKey(provider) => {
                let key = p.buf.text().trim().to_string();
                if key.is_empty() {
                    p.status = Some("Paste a non-empty API key.".to_string());
                } else {
                    p.status = Some(match self.save_web_api_key(provider, &key) {
                        Ok(()) => format!(
                            "{} key saved to credentials.",
                            web_key_provider_label(provider)
                        ),
                        Err(e) => format!("Save failed: {e}"),
                    });
                    p.buf = TextField::default();
                    p.editing = None;
                }
            }
            ToolField::FirecrawlBaseUrl => {
                let raw = p.buf.text().trim().to_string();
                if raw.is_empty() {
                    self.extended.web.firecrawl_base_url = None;
                    p.status = save_status(self.save_extended());
                    p.editing = None;
                } else if valid_http_url(&raw) {
                    self.extended.web.firecrawl_base_url = Some(raw);
                    p.status = save_status(self.save_extended());
                    p.editing = None;
                } else {
                    p.status = Some("Base URL must be a valid http(s) URL.".to_string());
                }
            }
            ToolField::NewToolName => {
                let name = p.buf.text().trim().to_string();
                if name.is_empty() {
                    p.status = Some("Tool name cannot be empty.".to_string());
                } else if is_reserved_custom_tool_name(&name) {
                    p.status = Some(format!(
                        "`{name}` is reserved; choose a different tool name."
                    ));
                } else if self.extended.tools.contains_key(&name) {
                    p.status = Some(format!("`{name}` already exists."));
                } else {
                    self.extended.tools.insert(
                        name.clone(),
                        ToolCommandTemplate {
                            enabled: true,
                            command: String::new(),
                            description: Some("User-defined command tool.".to_string()),
                        },
                    );
                    p.status = save_status(self.save_extended())
                        .or_else(|| Some(format!("added `{name}`")));
                    p.editing = None;
                    p.buf = TextField::default();
                    if let Some(idx) = self.tools_page_rows().iter().position(
                        |row| matches!(row, ToolRow::UserTool(row_name) if row_name == &name),
                    ) {
                        p.cursor = idx;
                    }
                }
            }
            ToolField::UserToolCommand(name) => {
                let command = p.buf.text().trim().to_string();
                if let Some(tool) = self.extended.tools.get_mut(&name) {
                    tool.command = command;
                    p.status = save_status(self.save_extended());
                    p.editing = None;
                } else {
                    p.status = Some(format!("`{name}` no longer exists."));
                    p.editing = None;
                }
            }
        }
    }

    fn activate_tools_row(&mut self, p: &mut ToolsPage, row: &ToolRow) -> Nav {
        p.delete_pending = None;
        match row {
            ToolRow::WebProvider => {
                self.cycle_web_provider(p);
            }
            ToolRow::FirecrawlBaseUrl => {
                p.buf = TextField::new(
                    self.extended
                        .web
                        .firecrawl_base_url
                        .clone()
                        .unwrap_or_default(),
                );
                p.editing = Some(ToolField::FirecrawlBaseUrl);
            }
            ToolRow::FirecrawlKey => {
                p.buf = TextField::default();
                p.editing = Some(ToolField::WebKey(WebKeyProvider::Firecrawl));
            }
            ToolRow::TinyFishKey => {
                p.buf = TextField::default();
                p.editing = Some(ToolField::WebKey(WebKeyProvider::TinyFish));
            }
            ToolRow::WebFetchCommand => {
                p.buf = TextField::new(
                    self.extended
                        .web
                        .custom
                        .fetch_command
                        .clone()
                        .unwrap_or_default(),
                );
                p.editing = Some(ToolField::WebFetchCommand);
            }
            ToolRow::WebSearchCommand => {
                p.buf = TextField::new(
                    self.extended
                        .web
                        .custom
                        .search_command
                        .clone()
                        .unwrap_or_default(),
                );
                p.editing = Some(ToolField::WebSearchCommand);
            }
            ToolRow::UserTool(name) => {
                let command = self
                    .extended
                    .tools
                    .get(name)
                    .map(|tool| tool.command.clone())
                    .unwrap_or_default();
                p.buf = TextField::new(command);
                p.editing = Some(ToolField::UserToolCommand(name.clone()));
            }
            ToolRow::AddUserTool => {
                p.buf = TextField::default();
                p.editing = Some(ToolField::NewToolName);
                p.status = None;
            }
            ToolRow::McpJump => {
                return Nav::Replace(super::mcp_page(McpPage::List(McpListState {
                    cursor: 0,
                    status: None,
                    delete_pending: false,
                })));
            }
            ToolRow::Reset => {
                if p.reset.activate() == ResetOutcome::Apply {
                    self.reset_tools_to_defaults();
                    p.status = save_status(self.save_extended());
                } else {
                    p.status = None;
                }
            }
            ToolRow::Builtin(_) | ToolRow::McpTool { .. } => {
                p.status = Some("read-only inventory row".to_string());
            }
        }
        Nav::Stay
    }

    fn toggle_tools_row(&mut self, p: &mut ToolsPage, row: &ToolRow) {
        match row {
            ToolRow::WebProvider => self.cycle_web_provider(p),
            ToolRow::UserTool(name) => {
                if let Some(tool) = self.extended.tools.get_mut(name) {
                    tool.enabled = !tool.enabled;
                    p.status = save_status(self.save_extended());
                }
            }
            _ => {}
        }
    }

    fn reset_tools_row(&mut self, p: &mut ToolsPage, row: &ToolRow) {
        match row {
            ToolRow::WebFetchCommand => {
                self.extended.web.custom.fetch_command = None;
                p.status = save_status(self.save_extended());
            }
            ToolRow::WebSearchCommand => {
                self.extended.web.custom.search_command = None;
                p.status = save_status(self.save_extended());
            }
            ToolRow::FirecrawlBaseUrl => {
                self.extended.web.firecrawl_base_url = None;
                p.status = save_status(self.save_extended());
            }
            _ => {}
        }
    }

    fn cycle_web_provider(&mut self, p: &mut ToolsPage) {
        self.extended.web.provider = match self.extended.web.provider {
            ConfigWebProvider::Firecrawl => ConfigWebProvider::Tinyfish,
            ConfigWebProvider::Tinyfish => ConfigWebProvider::Custom,
            ConfigWebProvider::Custom => ConfigWebProvider::Firecrawl,
        };
        p.status = save_status(self.save_extended());
    }

    fn delete_user_tool(&mut self, p: &mut ToolsPage, name: &str) {
        if p.delete_pending.as_deref() == Some(name) {
            self.extended.tools.remove(name);
            p.delete_pending = None;
            p.status = save_status(self.save_extended());
            let rows_len = self.tools_page_rows().len();
            if rows_len > 0 && p.cursor >= rows_len {
                p.cursor = rows_len - 1;
            }
        } else {
            p.delete_pending = Some(name.to_string());
            p.status = Some(format!("press d again to remove `{name}`"));
        }
    }

    /// Reset configurable tool state. Builtin and MCP inventory sections are
    /// read-only and therefore unaffected.
    fn reset_tools_to_defaults(&mut self) {
        self.extended.tools.clear();
        self.extended.web = WebConfig::default();
    }

    fn credential_store(&self) -> Result<CredentialStore, String> {
        match &self.credential_store_path {
            Some(path) => CredentialStore::open(path.clone()).map_err(|e| e.to_string()),
            None => CredentialStore::open_default().map_err(|e| e.to_string()),
        }
    }

    fn stored_web_key(&self, provider: WebKeyProvider) -> Option<String> {
        self.credential_store()
            .ok()
            .and_then(|store| store.api_key(web_key_provider_id(provider)))
            .filter(|value| !value.trim().is_empty())
    }

    fn web_key_status(&self, provider: WebKeyProvider) -> Option<WebKeyStatus> {
        let env_name = web_key_env(provider);
        (self.env_lookup)(env_name)
            .filter(|value| !value.trim().is_empty())
            .map(|_| WebKeyStatus::Env)
            .or_else(|| self.stored_web_key(provider).map(|_| WebKeyStatus::Stored))
    }

    fn save_web_api_key(&self, provider: WebKeyProvider, key: &str) -> Result<(), String> {
        let store = self.credential_store()?;
        store
            .save_record_merged(
                web_key_provider_id(provider),
                serde_json::json!({ "api_key": key }),
            )
            .map_err(|e| e.to_string())
    }

    fn tools_page_rows(&self) -> Vec<ToolRow> {
        let mut rows = vec![ToolRow::WebProvider];
        match self.extended.web.provider {
            ConfigWebProvider::Firecrawl => {
                rows.push(ToolRow::FirecrawlKey);
                rows.push(ToolRow::FirecrawlBaseUrl);
            }
            ConfigWebProvider::Tinyfish => {
                rows.push(ToolRow::TinyFishKey);
            }
            ConfigWebProvider::Custom => {
                rows.push(ToolRow::WebFetchCommand);
                rows.push(ToolRow::WebSearchCommand);
            }
        }

        rows.extend(
            builtin_tool_inventory()
                .iter()
                .map(|tool| ToolRow::Builtin(tool.name)),
        );

        let mut user_tools = self.extended.tools.keys().cloned().collect::<Vec<_>>();
        user_tools.sort();
        rows.extend(user_tools.into_iter().map(ToolRow::UserTool));
        rows.push(ToolRow::AddUserTool);

        for (server, tool) in self.cached_mcp_tool_rows() {
            rows.push(ToolRow::McpTool { server, tool });
        }
        rows.push(ToolRow::McpJump);
        rows.push(ToolRow::Reset);
        rows
    }

    fn cached_mcp_tool_rows(&self) -> Vec<(String, String)> {
        let cfg = self.load_mcp();
        let mut out = Vec::new();
        for (name, server) in cfg.enabled_servers() {
            for tool in self.cached_mcp_tools(name, server) {
                out.push((name.to_string(), tool.name));
            }
        }
        out
    }

    fn cached_mcp_tools(
        &self,
        name: &str,
        server: &cockpit_core::mcp::config::ServerConfig,
    ) -> Vec<ToolDescriptor> {
        let key = cache::cache_key(name, server);
        let cached = match &self.mcp_cache_dir {
            Some(dir) => cache::load_in(dir, &key, server.cache_ttl_secs),
            None => cache::load(&key, server.cache_ttl_secs),
        };
        cached
            .map(|catalog| {
                catalog
                    .tools
                    .into_iter()
                    .map(sanitize_tool_descriptor)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) fn build_tools_page_lines(&self, width: u16, p: &ToolsPage) -> Vec<Line<'static>> {
        let muted = muted_style();
        let mut lines = Vec::new();
        let mut row_idx = 0usize;

        push_section(&mut lines, "Web tools");
        self.push_web_tools_lines(width, p, &mut lines, &mut row_idx);

        push_section(&mut lines, "Built-in tools");
        self.push_builtin_tools_lines(width, p, &mut lines, &mut row_idx);

        push_section(&mut lines, "User-defined tools");
        self.push_user_defined_tools_lines(width, p, &mut lines, &mut row_idx);

        push_section(&mut lines, "MCP tools");
        self.push_mcp_tools_lines(width, p, &mut lines, &mut row_idx);

        lines.push(Line::default());
        let reset_row = row_idx;
        lines.push(
            p.reset
                .render_line(p.cursor == reset_row, "reset to defaults"),
        );

        if let Some(field) = &p.editing {
            let label = match field {
                ToolField::WebFetchCommand => "fetch command",
                ToolField::WebSearchCommand => "search command",
                ToolField::WebKey(_) => "api key",
                ToolField::FirecrawlBaseUrl => "base url",
                ToolField::NewToolName => "tool name",
                ToolField::UserToolCommand(_) => "command",
            };
            let visible = match field {
                ToolField::WebKey(_) => masked_edit_value(p.buf.text()),
                _ => p.buf.text().to_string(),
            };
            let cursor = match field {
                ToolField::WebKey(_) if !p.buf.text().is_empty() => visible.chars().count(),
                _ => p.buf.cursor(),
            };
            lines.push(Line::default());
            push_text_field_at_cursor(&mut lines, width, label, &visible, cursor, true, None);
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), warning_style())));
        }

        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Custom web commands must include {url} for webfetch and {query} for websearch."
                .to_string(),
            muted,
        )));

        lines
    }

    fn push_web_tools_lines(
        &self,
        width: u16,
        p: &ToolsPage,
        lines: &mut Vec<Line<'static>>,
        row_idx: &mut usize,
    ) {
        push_selectable_row(
            lines,
            width,
            p,
            row_idx,
            "provider",
            &format!(
                "{} (enter cycles Firecrawl, TinyFish, Custom)",
                provider_label(self.extended.web.provider)
            ),
            muted_style(),
        );
        match self.extended.web.provider {
            ConfigWebProvider::Firecrawl => {
                push_selectable_row(
                    lines,
                    width,
                    p,
                    row_idx,
                    "api key",
                    &format!(
                        "{}; env wins over stored credentials",
                        web_key_status_label(self.web_key_status(WebKeyProvider::Firecrawl))
                    ),
                    muted_style(),
                );
                let env_override = (self.env_lookup)("FIRECRAWL_API_URL")
                    .filter(|v| !v.trim().is_empty())
                    .map(|_| "env FIRECRAWL_API_URL overrides config".to_string())
                    .unwrap_or_else(|| "empty uses https://api.firecrawl.dev".to_string());
                push_selectable_row(
                    lines,
                    width,
                    p,
                    row_idx,
                    "base url",
                    &format!(
                        "{} ({env_override})",
                        self.extended
                            .web
                            .firecrawl_base_url
                            .as_deref()
                            .unwrap_or("default")
                    ),
                    muted_style(),
                );
            }
            ConfigWebProvider::Tinyfish => {
                push_selectable_row(
                    lines,
                    width,
                    p,
                    row_idx,
                    "api key",
                    &format!(
                        "{}; env wins over stored credentials",
                        web_key_status_label(self.web_key_status(WebKeyProvider::TinyFish))
                    ),
                    if self.web_key_status(WebKeyProvider::TinyFish).is_some() {
                        muted_style()
                    } else {
                        warning_style()
                    },
                );
            }
            ConfigWebProvider::Custom => {
                let fetch_command = self.extended.web.custom.fetch_command.as_deref();
                push_selectable_row(
                    lines,
                    width,
                    p,
                    row_idx,
                    "webfetch",
                    &web_command_status(fetch_command, "{url}"),
                    if fetch_command.is_some_and(|command| !command.trim().is_empty()) {
                        muted_style()
                    } else {
                        warning_style()
                    },
                );
                let search_command = self.extended.web.custom.search_command.as_deref();
                push_selectable_row(
                    lines,
                    width,
                    p,
                    row_idx,
                    "websearch",
                    &web_command_status(search_command, "{query}"),
                    if search_command.is_some_and(|command| !command.trim().is_empty()) {
                        muted_style()
                    } else {
                        warning_style()
                    },
                );
            }
        }
    }

    fn push_builtin_tools_lines(
        &self,
        width: u16,
        p: &ToolsPage,
        lines: &mut Vec<Line<'static>>,
        row_idx: &mut usize,
    ) {
        let mut last_family = "";
        for tool in builtin_tool_inventory() {
            if tool.family != last_family {
                lines.push(Line::from(Span::styled(
                    format!("  {}", tool.family),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                last_family = tool.family;
            }
            let value = match tool.condition {
                Some(condition) => format!("{} ({condition})", tool.summary),
                None => tool.summary.to_string(),
            };
            push_selectable_row(lines, width, p, row_idx, tool.name, &value, muted_style());
        }
    }

    fn push_user_defined_tools_lines(
        &self,
        width: u16,
        p: &ToolsPage,
        lines: &mut Vec<Line<'static>>,
        row_idx: &mut usize,
    ) {
        let mut names = self.extended.tools.keys().cloned().collect::<Vec<_>>();
        names.sort();
        if names.is_empty() {
            lines.push(Line::from(Span::styled(
                "No user-defined tools configured.".to_string(),
                muted_style(),
            )));
        }
        for name in names {
            let Some(tool) = self.extended.tools.get(&name) else {
                continue;
            };
            let enabled = if tool.enabled { "enabled" } else { "disabled" };
            let command = if tool.command.trim().is_empty() {
                "not registered - no command set".to_string()
            } else {
                tool.command.clone()
            };
            let desc = tool
                .description
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!("; {value}"))
                .unwrap_or_default();
            let pending = p.delete_pending.as_deref() == Some(name.as_str());
            let value = if pending {
                format!("press d again to remove; {enabled}; {command}{desc}")
            } else {
                format!("{enabled}; {command}{desc}")
            };
            push_selectable_row(
                lines,
                width,
                p,
                row_idx,
                &name,
                &value,
                if tool.command.trim().is_empty() {
                    warning_style()
                } else {
                    muted_style()
                },
            );
        }
        push_selectable_row(
            lines,
            width,
            p,
            row_idx,
            "[+ add tool]",
            "create a user-defined bash-command tool",
            Style::default().add_modifier(Modifier::BOLD),
        );
    }

    fn push_mcp_tools_lines(
        &self,
        width: u16,
        p: &ToolsPage,
        lines: &mut Vec<Line<'static>>,
        row_idx: &mut usize,
    ) {
        let cfg = self.load_mcp();
        let enabled_servers = cfg.enabled_servers();
        if enabled_servers.is_empty() {
            lines.push(Line::from(Span::styled(
                "No MCP servers configured.".to_string(),
                muted_style(),
            )));
        } else {
            let mut any_cached = false;
            for (server_name, server) in enabled_servers {
                let tools = self.cached_mcp_tools(server_name, server);
                if tools.is_empty() {
                    lines.push(Line::from(Span::styled(
                        format!("{server_name}: no cached tools yet"),
                        muted_style(),
                    )));
                    continue;
                }
                any_cached = true;
                for tool in tools {
                    push_selectable_row(
                        lines,
                        width,
                        p,
                        row_idx,
                        &format!("{server_name}/{}", tool.name),
                        first_line_or_default(&tool.description),
                        muted_style(),
                    );
                }
            }
            if !any_cached {
                lines.push(Line::from(Span::styled(
                    "Open or use MCP once to populate cached tool catalogs.".to_string(),
                    muted_style(),
                )));
            }
        }
        push_selectable_row(
            lines,
            width,
            p,
            row_idx,
            "configure in MCP ->",
            "jump to MCP server settings",
            Style::default().add_modifier(Modifier::BOLD),
        );
    }

    pub(super) fn render_tools_page(&self, frame: &mut Frame, area: Rect, p: &ToolsPage) {
        let lines = self.build_tools_page_lines(area.width, p);
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "tools", lines, selected_line);
    }
}

fn web_command_status(command: Option<&str>, placeholder: &str) -> String {
    match command.map(str::trim).filter(|value| !value.is_empty()) {
        Some(command) if command.contains(placeholder) => command.to_string(),
        Some(_) => "not registered - required placeholder is missing".to_string(),
        None => "not registered - no command set".to_string(),
    }
}

fn first_line_or_default(value: &str) -> &str {
    value
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .unwrap_or("no description")
}

fn push_section(lines: &mut Vec<Line<'static>>, title: &str) {
    if !lines.is_empty() {
        lines.push(Line::default());
    }
    lines.push(Line::from(Span::styled(
        title.to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());
}

fn push_selectable_row(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    p: &ToolsPage,
    row_idx: &mut usize,
    label: &str,
    value: &str,
    value_style: Style,
) {
    let selected = p.cursor == *row_idx;
    let marker = if selected { "▸ " } else { "  " };
    let label_style = if selected {
        selected_style()
    } else {
        focused_field_style()
    };
    push_tool_value_row(lines, width, marker, label, label_style, value, value_style);
    *row_idx += 1;
}

fn push_tool_value_row(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    marker: &str,
    label: &str,
    label_style: Style,
    value: &str,
    value_style: Style,
) {
    push_wrapped_prefixed_value(
        lines,
        width,
        WrappedValueLayout {
            first_prefix: vec![
                Span::raw(marker.to_string()),
                Span::styled(format!("{:<TOOL_ROW_LABEL_WIDTH$}", label), label_style),
                Span::raw(" ".repeat(TOOL_ROW_GAP_WIDTH)),
            ],
            prefix_width: TOOL_ROW_VALUE_INDENT,
            continuation_prefix: vec![Span::raw(" ".repeat(TOOL_ROW_VALUE_INDENT))],
            suffix: None,
        },
        value,
        value_style,
    );
}

impl SettingsPage for ToolsPage {
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_tools_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_tools_page(frame, area, self);
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › Tools",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.editing.is_some() {
            "type to edit  enter: apply  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: edit/cycle  t: toggle  d: remove  r: reset row  esc/h: back  q: close"
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
        "Tools"
    }
}
