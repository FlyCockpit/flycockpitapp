//! `/settings → Tools` page: built-in custom-tool templates
//! (`webfetch`, `websearch`) and their per-tool command + description
//! + enabled fields under `config.json`'s `tools` key.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::config::extended::{ToolCommandTemplate, WebProvider as ConfigWebProvider};
use crate::credentials::CredentialStore;
use crate::tools::custom_templates::{builtin_tool_names, default_template_for};
use crate::tui::settings::secret_display::{MASKED_VALUE, mask_value};
use crate::tui::textfield::TextField;

use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    WrappedValueLayout, focused_field_style, muted_style, push_text_field_at_cursor,
    push_wrapped_prefixed_value, selected_line_from_marker, selected_style, warning_style,
};
use super::{Nav, SettingsCx, SettingsPage, save_status};

const TOOL_ROW_MARKER_WIDTH: usize = 2;
const TOOL_ROW_LABEL_WIDTH: usize = 14;
const TOOL_ROW_GAP_WIDTH: usize = 2;
const TOOL_ROW_VALUE_INDENT: usize =
    TOOL_ROW_MARKER_WIDTH + TOOL_ROW_LABEL_WIDTH + TOOL_ROW_GAP_WIDTH;

/// `/settings → Tools` state. Edits the user-defined bash-command
/// templates under `config.json`'s `tools` key.
pub(super) struct ToolsPage {
    pub(super) cursor: usize,
    pub(super) setup: Option<WebSetupState>,
    pub(super) editing: Option<ToolField>,
    pub(super) buf: TextField,
    /// Which tool's row is being edited, when `editing` is `Some`.
    pub(super) edit_target: Option<String>,
    pub(super) status: Option<String>,
    /// Page-level "reset to defaults" confirm state (the last navigable
    /// row).
    pub(super) reset: ResetButton,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum WebSetupState {
    Provider,
    FirecrawlDetails,
    TinyFishDetails,
    CustomPresets,
    AgentBrowserSearchEngine,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum ToolField {
    Command,
    Description,
    WebKey(WebKeyProvider),
    FirecrawlBaseUrl,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum WebKeyProvider {
    Firecrawl,
    TinyFish,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum WebChoice {
    Firecrawl,
    TinyFish,
    Custom,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum AgentBrowserSearchEngine {
    Google,
    Bing,
    Brave,
}

struct WebProviderChoice {
    provider: WebChoice,
    label: &'static str,
    docs_url: &'static str,
    hint: &'static str,
}

fn agent_browser_fetch_template() -> ToolCommandTemplate {
    ToolCommandTemplate {
        enabled: true,
        command: "agent-browser --session cockpit-webfetch open {url} && agent-browser --session cockpit-webfetch get text body".to_string(),
        description: Some(
            "Fetch a URL using agent-browser. Pass `url`; returns readable page text from the browser session. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
        ),
    }
}

fn agent_browser_search_template(engine: AgentBrowserSearchEngine) -> ToolCommandTemplate {
    let url = match engine {
        AgentBrowserSearchEngine::Google => "https://www.google.com/search?q={query}",
        AgentBrowserSearchEngine::Bing => "https://www.bing.com/search?q={query}",
        AgentBrowserSearchEngine::Brave => "https://search.brave.com/search?q={query}",
    };
    ToolCommandTemplate {
        enabled: true,
        command: format!(
            "agent-browser --session cockpit-websearch open \"{url}\" && agent-browser --session cockpit-websearch get text body"
        ),
        description: Some(
            "Search the web using agent-browser. Pass `query`; search results may require a configured browser profile/session when the engine challenges automation. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
        ),
    }
}

fn agent_browser_engine_label(engine: AgentBrowserSearchEngine) -> &'static str {
    match engine {
        AgentBrowserSearchEngine::Google => "Google",
        AgentBrowserSearchEngine::Bing => "Bing",
        AgentBrowserSearchEngine::Brave => "Brave",
    }
}

fn web_provider_choices() -> [WebProviderChoice; 3] {
    [
        WebProviderChoice {
            provider: WebChoice::Firecrawl,
            label: "Firecrawl",
            docs_url: "https://www.firecrawl.dev",
            hint: "default native backend; no API key required, FIRECRAWL_API_KEY raises limits",
        },
        WebProviderChoice {
            provider: WebChoice::TinyFish,
            label: "TinyFish",
            docs_url: "https://agent.tinyfish.ai",
            hint: "requires TINYFISH_API_KEY or a stored TinyFish key",
        },
        WebProviderChoice {
            provider: WebChoice::Custom,
            label: "Custom CLI command",
            docs_url: "",
            hint: "use configured webfetch/websearch commands and shipped presets",
        },
    ]
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

impl SettingsCx {
    fn handle_tools_page_key(&mut self, key: KeyEvent, p: &mut ToolsPage) -> Nav {
        if let Some(field) = p.editing {
            match key.code {
                KeyCode::Enter => match field {
                    ToolField::Command | ToolField::Description => {
                        let new = p.buf.text().to_string();
                        if let Some(name) = p.edit_target.clone() {
                            let entry = self.extended.tools.entry(name).or_insert_with(|| {
                                ToolCommandTemplate {
                                    enabled: true,
                                    command: String::new(),
                                    description: None,
                                }
                            });
                            match field {
                                ToolField::Command => entry.command = new,
                                ToolField::Description => {
                                    entry.description =
                                        if new.is_empty() { None } else { Some(new) };
                                }
                                _ => unreachable!(),
                            }
                        }
                        p.status = save_status(self.save_extended());
                        p.editing = None;
                        p.edit_target = None;
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
                            p.edit_target = None;
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
                },
                KeyCode::Esc => {
                    p.editing = None;
                    p.edit_target = None;
                }
                _ => {
                    p.buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        if let Some(setup) = p.setup {
            let total_rows = match setup {
                WebSetupState::Provider => web_provider_choices().len(),
                WebSetupState::FirecrawlDetails => 3,
                WebSetupState::TinyFishDetails => 2,
                WebSetupState::CustomPresets => 3,
                WebSetupState::AgentBrowserSearchEngine => 3,
            };
            match key.code {
                KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                    p.setup = if matches!(setup, WebSetupState::Provider) {
                        None
                    } else {
                        Some(WebSetupState::Provider)
                    };
                    p.cursor = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    p.cursor = crate::tui::nav::wrap_prev(p.cursor, total_rows);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    p.cursor = crate::tui::nav::wrap_next(p.cursor, total_rows);
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => match setup {
                    WebSetupState::Provider => {
                        let choices = web_provider_choices();
                        if let Some(choice) = choices.get(p.cursor) {
                            match choice.provider {
                                WebChoice::Firecrawl => {
                                    self.extended.web.provider = ConfigWebProvider::Firecrawl;
                                    p.status = save_status(self.save_extended());
                                    p.setup = Some(WebSetupState::FirecrawlDetails);
                                    p.cursor = 0;
                                }
                                WebChoice::TinyFish => {
                                    p.setup = Some(WebSetupState::TinyFishDetails);
                                    p.cursor = 0;
                                    if self.web_key_status(WebKeyProvider::TinyFish).is_some() {
                                        self.extended.web.provider = ConfigWebProvider::Tinyfish;
                                        p.status = save_status(self.save_extended());
                                    } else {
                                        p.status = Some("TinyFish needs TINYFISH_API_KEY or a stored key before it can be selected.".to_string());
                                    }
                                }
                                WebChoice::Custom => {
                                    self.extended.web.provider = ConfigWebProvider::Custom;
                                    p.status = save_status(self.save_extended());
                                    p.setup = Some(WebSetupState::CustomPresets);
                                    p.cursor = 0;
                                }
                            }
                        }
                    }
                    WebSetupState::FirecrawlDetails => match p.cursor {
                        0 => {
                            self.extended.web.provider = ConfigWebProvider::Firecrawl;
                            p.status = save_status(self.save_extended());
                        }
                        1 => {
                            p.buf = TextField::default();
                            p.editing = Some(ToolField::WebKey(WebKeyProvider::Firecrawl));
                        }
                        2 => {
                            p.buf = TextField::new(
                                self.extended
                                    .web
                                    .firecrawl_base_url
                                    .clone()
                                    .unwrap_or_default(),
                            );
                            p.editing = Some(ToolField::FirecrawlBaseUrl);
                        }
                        _ => {}
                    },
                    WebSetupState::TinyFishDetails => match p.cursor {
                        0 => {
                            if self.web_key_status(WebKeyProvider::TinyFish).is_some() {
                                self.extended.web.provider = ConfigWebProvider::Tinyfish;
                                p.status = save_status(self.save_extended());
                            } else {
                                p.status = Some("TinyFish is disabled until TINYFISH_API_KEY or a stored key is available.".to_string());
                            }
                        }
                        1 => {
                            p.buf = TextField::default();
                            p.editing = Some(ToolField::WebKey(WebKeyProvider::TinyFish));
                        }
                        _ => {}
                    },
                    WebSetupState::CustomPresets => match p.cursor {
                        0 => {
                            self.extended.web.provider = ConfigWebProvider::Custom;
                            p.status = save_status(self.save_extended());
                        }
                        1 => {
                            self.extended.web.provider = ConfigWebProvider::Custom;
                            self.apply_curl_ddgr_preset();
                            p.status = save_status(self.save_extended());
                        }
                        2 => {
                            self.extended.web.provider = ConfigWebProvider::Custom;
                            self.apply_agent_browser_fetch();
                            p.setup = Some(WebSetupState::AgentBrowserSearchEngine);
                            p.cursor = 0;
                            p.status = Some(
                                "agent-browser webfetch applied; choose a search engine"
                                    .to_string(),
                            );
                        }
                        _ => {}
                    },
                    WebSetupState::AgentBrowserSearchEngine => {
                        let engine = match p.cursor {
                            0 => AgentBrowserSearchEngine::Google,
                            1 => AgentBrowserSearchEngine::Bing,
                            _ => AgentBrowserSearchEngine::Brave,
                        };
                        self.extended.web.provider = ConfigWebProvider::Custom;
                        self.apply_agent_browser_search(engine);
                        p.setup = Some(WebSetupState::CustomPresets);
                        p.cursor = 2;
                        p.status = save_status(self.save_extended());
                    }
                },
                _ => {}
            }
            return Nav::Stay;
        }

        // The tools page lays out a flat list:
        //   for each known tool: [command, description, enabled] (3 rows)
        // built-ins (webfetch, websearch) are always present; users can
        // also add their own under arbitrary names but we don't surface
        // an "add tool" affordance in v1 to keep the UI tight.
        let builtins = builtin_tool_names();
        let rows_per_tool = 3usize;
        let tool_rows = builtins.len() * rows_per_tool;
        let setup_row = tool_rows;
        // The `[reset to defaults]` button is the last navigable row.
        let reset_row = setup_row + 1;
        let total_rows = reset_row + 1;
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, total_rows);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, total_rows);
            }
            KeyCode::Char('t') if p.cursor < tool_rows => {
                let tool_idx = p.cursor / rows_per_tool;
                if let Some(name) = builtins.get(tool_idx).copied() {
                    let entry = self
                        .extended
                        .tools
                        .entry(name.to_string())
                        .or_insert_with(|| default_template_for(name));
                    entry.enabled = !entry.enabled;
                    p.status = save_status(self.save_extended());
                }
            }
            KeyCode::Char('r') if p.cursor < tool_rows => {
                let tool_idx = p.cursor / rows_per_tool;
                if let Some(name) = builtins.get(tool_idx).copied() {
                    self.extended
                        .tools
                        .insert(name.to_string(), default_template_for(name));
                    p.status = save_status(self.save_extended());
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if p.cursor == setup_row {
                    p.setup = Some(WebSetupState::Provider);
                    p.cursor = 0;
                    p.reset.disarm();
                    p.status = None;
                    return Nav::Stay;
                }
                if p.cursor == reset_row {
                    // Page-level reset: arm on first activation, apply on
                    // the second.
                    if p.reset.activate() == ResetOutcome::Apply {
                        self.reset_tools_to_defaults();
                        p.status = save_status(self.save_extended());
                    } else {
                        p.status = None;
                    }
                    return Nav::Stay;
                }
                let tool_idx = p.cursor / rows_per_tool;
                let row_in_tool = p.cursor % rows_per_tool;
                if let Some(name) = builtins.get(tool_idx).copied() {
                    let entry = self
                        .extended
                        .tools
                        .entry(name.to_string())
                        .or_insert_with(|| default_template_for(name));
                    match row_in_tool {
                        0 => {
                            p.buf = TextField::new(entry.command.clone());
                            p.edit_target = Some(name.to_string());
                            p.editing = Some(ToolField::Command);
                        }
                        1 => {
                            p.buf = TextField::new(entry.description.clone().unwrap_or_default());
                            p.edit_target = Some(name.to_string());
                            p.editing = Some(ToolField::Description);
                        }
                        2 => {
                            entry.enabled = !entry.enabled;
                            p.status = save_status(self.save_extended());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Reset the tools map to its default state: every built-in template
    /// restored to its [`default_template_for`] default, and every
    /// user-added/custom tool entry removed.
    fn reset_tools_to_defaults(&mut self) {
        self.extended.tools.clear();
        for name in builtin_tool_names() {
            self.extended
                .tools
                .insert(name.to_string(), default_template_for(name));
        }
    }

    fn apply_curl_ddgr_preset(&mut self) {
        for name in builtin_tool_names() {
            self.extended
                .tools
                .insert(name.to_string(), default_template_for(name));
        }
    }

    fn apply_agent_browser_fetch(&mut self) {
        self.extended
            .tools
            .insert("webfetch".to_string(), agent_browser_fetch_template());
    }

    fn apply_agent_browser_search(&mut self, engine: AgentBrowserSearchEngine) {
        self.extended.tools.insert(
            "websearch".to_string(),
            agent_browser_search_template(engine),
        );
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

    pub(super) fn build_tools_page_lines(&self, width: u16, p: &ToolsPage) -> Vec<Line<'static>> {
        let muted = muted_style();
        let yellow = warning_style();
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(Line::from(Span::styled(
            "Custom bash-command tools".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());

        if let Some(setup) = p.setup {
            match setup {
                WebSetupState::Provider => {
                    lines.push(Line::from(Span::styled(
                        "Choose web provider".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    for (idx, choice) in web_provider_choices().iter().enumerate() {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        let current = match (choice.provider, self.extended.web.provider) {
                            (WebChoice::Firecrawl, ConfigWebProvider::Firecrawl)
                            | (WebChoice::TinyFish, ConfigWebProvider::Tinyfish)
                            | (WebChoice::Custom, ConfigWebProvider::Custom) => "current; ",
                            _ => "",
                        };
                        let disabled = choice.provider == WebChoice::TinyFish
                            && self.web_key_status(WebKeyProvider::TinyFish).is_none();
                        let disabled_hint = if disabled { "disabled; " } else { "" };
                        let docs = if choice.docs_url.is_empty() {
                            String::new()
                        } else {
                            format!(" - {}", choice.docs_url)
                        };
                        let value = format!(
                            "{}{disabled_hint}{}{} - {}",
                            current, choice.label, docs, choice.hint
                        );
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            "  provider",
                            label_style,
                            &value,
                            if disabled { yellow } else { muted },
                        );
                    }
                }
                WebSetupState::FirecrawlDetails => {
                    lines.push(Line::from(Span::styled(
                        "Firecrawl".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    let key_status =
                        web_key_status_label(self.web_key_status(WebKeyProvider::Firecrawl));
                    let env_override = (self.env_lookup)("FIRECRAWL_API_URL")
                        .filter(|v| !v.trim().is_empty())
                        .map(|_| "env FIRECRAWL_API_URL overrides config".to_string())
                        .unwrap_or_else(|| "empty uses https://api.firecrawl.dev".to_string());
                    let rows = [
                        (
                            "  provider",
                            "native Firecrawl (keyless allowed)".to_string(),
                        ),
                        (
                            "  api key",
                            format!("{key_status}; env wins over stored credentials"),
                        ),
                        (
                            "  base url",
                            format!(
                                "{} ({env_override})",
                                self.extended
                                    .web
                                    .firecrawl_base_url
                                    .as_deref()
                                    .unwrap_or("default")
                            ),
                        ),
                    ];
                    for (idx, (label, value)) in rows.iter().enumerate() {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            label,
                            label_style,
                            value,
                            muted,
                        );
                    }
                }
                WebSetupState::TinyFishDetails => {
                    lines.push(Line::from(Span::styled(
                        "TinyFish".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    let available = self.web_key_status(WebKeyProvider::TinyFish).is_some();
                    let key_status =
                        web_key_status_label(self.web_key_status(WebKeyProvider::TinyFish));
                    let rows = [
                        (
                            "  provider",
                            if available {
                                "native TinyFish".to_string()
                            } else {
                                "disabled until TINYFISH_API_KEY or a stored key is available; https://agent.tinyfish.ai".to_string()
                            },
                        ),
                        (
                            "  api key",
                            format!("{key_status}; env wins over stored credentials"),
                        ),
                    ];
                    for (idx, (label, value)) in rows.iter().enumerate() {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            label,
                            label_style,
                            value,
                            if idx == 0 && !available {
                                yellow
                            } else {
                                muted
                            },
                        );
                    }
                }
                WebSetupState::CustomPresets => {
                    lines.push(Line::from(Span::styled(
                        "Custom CLI command".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    let rows = [
                        ("  provider", "use configured webfetch/websearch commands"),
                        ("  preset", "curl + ddgr shipped defaults"),
                        ("  preset", "agent-browser (choose search engine next)"),
                    ];
                    for (idx, (label, value)) in rows.iter().enumerate() {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            label,
                            label_style,
                            value,
                            muted,
                        );
                    }
                }
                WebSetupState::AgentBrowserSearchEngine => {
                    lines.push(Line::from(Span::styled(
                        "Choose agent-browser search engine".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    for (idx, engine) in [
                        AgentBrowserSearchEngine::Google,
                        AgentBrowserSearchEngine::Bing,
                        AgentBrowserSearchEngine::Brave,
                    ]
                    .iter()
                    .copied()
                    .enumerate()
                    {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            "  engine",
                            label_style,
                            agent_browser_engine_label(engine),
                            muted,
                        );
                    }
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(
                        "Search engines may challenge automation; configure the browser profile/session if needed.".to_string(),
                        muted,
                    )));
                }
            }
            if let Some(field) = p.editing {
                let label = match field {
                    ToolField::Command => "command",
                    ToolField::Description => "description",
                    ToolField::WebKey(_) => "api key",
                    ToolField::FirecrawlBaseUrl => "base url",
                };
                let visible = match field {
                    ToolField::WebKey(_) => masked_edit_value(p.buf.text()),
                    _ => p.buf.text().to_string(),
                };
                let cursor = match field {
                    ToolField::WebKey(_) if !p.buf.text().is_empty() => visible.chars().count(),
                    _ => p.buf.cursor(),
                };
                push_text_field_at_cursor(&mut lines, width, label, &visible, cursor, true, None);
            }
            if let Some(status) = &p.status {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(status.clone(), yellow)));
            }
            return lines;
        }

        let builtins = builtin_tool_names();
        let mut row_idx = 0usize;
        for name in builtins.iter() {
            let entry = self.extended.tools.get(*name);
            let default = default_template_for(name);
            let cmd = entry
                .map(|e| e.command.as_str())
                .unwrap_or(&default.command);
            let desc = entry
                .and_then(|e| e.description.as_deref())
                .or(default.description.as_deref())
                .unwrap_or("");
            let enabled = entry.map(|e| e.enabled).unwrap_or(default.enabled);

            lines.push(Line::from(Span::styled(
                format!("[{name}]"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));

            let sub_rows: [(&str, String); 3] = [
                ("  command", cmd.to_string()),
                ("  description", desc.to_string()),
                (
                    "  enabled",
                    if enabled { "yes".into() } else { "no".into() },
                ),
            ];
            for (label, value) in &sub_rows {
                let selected = row_idx == p.cursor;
                let marker = if selected { "▸ " } else { "  " };
                let label_style = if selected {
                    selected_style()
                } else {
                    focused_field_style()
                };
                push_tool_value_row(&mut lines, width, marker, label, label_style, value, muted);
                row_idx += 1;
            }
            lines.push(Line::default());
        }

        let selected = row_idx == p.cursor;
        let marker = if selected { "▸ " } else { "  " };
        let label_style = if selected {
            selected_style()
        } else {
            focused_field_style()
        };
        push_tool_value_row(
            &mut lines,
            width,
            marker,
            "Web setup",
            label_style,
            "choose native Firecrawl/TinyFish or custom CLI presets",
            muted,
        );
        row_idx += 1;

        // `[reset to defaults]` button — the last navigable row, at
        // cursor `builtins.len() * 3 + 1`.
        let reset_row = row_idx;
        lines.push(
            p.reset
                .render_line(p.cursor == reset_row, "reset to defaults"),
        );
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Clearing a built-in tool description inherits the default.".to_string(),
            muted,
        )));

        if let Some(field) = p.editing {
            let label = match field {
                ToolField::Command => "command",
                ToolField::Description => "description",
                ToolField::WebKey(_) => "api key",
                ToolField::FirecrawlBaseUrl => "base url",
            };
            let visible = match field {
                ToolField::WebKey(_) => masked_edit_value(p.buf.text()),
                _ => p.buf.text().to_string(),
            };
            let cursor = match field {
                ToolField::WebKey(_) if !p.buf.text().is_empty() => visible.chars().count(),
                _ => p.buf.cursor(),
            };
            push_text_field_at_cursor(&mut lines, width, label, &visible, cursor, true, None);
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        lines
    }

    pub(super) fn render_tools_page(&self, frame: &mut Frame, area: Rect, p: &ToolsPage) {
        let lines = self.build_tools_page_lines(area.width, p);
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "tools", lines, selected_line);
    }
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
        format!("{} › Tools", crate::welcome::display_path(&cx.config_path))
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.editing.is_some() {
            "type to edit  enter: apply  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: edit  t: toggle  r: reset  esc/h: back  q: close"
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
