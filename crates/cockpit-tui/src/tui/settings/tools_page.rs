//! `/settings → Tools` page: web provider selection and custom web-command
//! fields under `config.json`'s typed `web.custom` key.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::settings::secret_display::{MASKED_VALUE, mask_value};
use crate::tui::textfield::TextField;
use cockpit_config::extended::WebProvider as ConfigWebProvider;
use cockpit_core::credentials::CredentialStore;

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
    CustomCommands,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum ToolField {
    WebFetchCommand,
    WebSearchCommand,
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

struct WebProviderChoice {
    provider: WebChoice,
    label: &'static str,
    docs_url: &'static str,
    hint: &'static str,
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
            hint: "use typed web.custom commands",
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
                    ToolField::WebFetchCommand => {
                        let new = p.buf.text().trim().to_string();
                        self.extended.web.custom.fetch_command =
                            if new.is_empty() { None } else { Some(new) };
                        p.status = save_status(self.save_extended());
                        p.editing = None;
                        p.edit_target = None;
                    }
                    ToolField::WebSearchCommand => {
                        let new = p.buf.text().trim().to_string();
                        self.extended.web.custom.search_command =
                            if new.is_empty() { None } else { Some(new) };
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
                WebSetupState::CustomCommands => 2,
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
                                    p.setup = Some(WebSetupState::CustomCommands);
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
                    WebSetupState::CustomCommands => match p.cursor {
                        0 => {
                            self.extended.web.provider = ConfigWebProvider::Custom;
                            p.buf = TextField::new(
                                self.extended
                                    .web
                                    .custom
                                    .fetch_command
                                    .clone()
                                    .unwrap_or_default(),
                            );
                            p.editing = Some(ToolField::WebFetchCommand);
                            p.status = save_status(self.save_extended());
                        }
                        1 => {
                            self.extended.web.provider = ConfigWebProvider::Custom;
                            p.buf = TextField::new(
                                self.extended
                                    .web
                                    .custom
                                    .search_command
                                    .clone()
                                    .unwrap_or_default(),
                            );
                            p.editing = Some(ToolField::WebSearchCommand);
                            p.status = save_status(self.save_extended());
                        }
                        _ => {}
                    },
                },
                _ => {}
            }
            return Nav::Stay;
        }

        let tool_rows = 2usize;
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
            KeyCode::Char('r') if p.cursor < tool_rows => {
                match p.cursor {
                    0 => self.extended.web.custom.fetch_command = None,
                    1 => self.extended.web.custom.search_command = None,
                    _ => {}
                }
                p.status = save_status(self.save_extended());
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
                match p.cursor {
                    0 => {
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
                    1 => {
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
                    _ => {}
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Reset custom tool state: user-added tools are removed and typed custom
    /// web commands return to the empty default.
    fn reset_tools_to_defaults(&mut self) {
        self.extended.tools.clear();
        self.extended.web.custom = cockpit_config::extended::WebCustomConfig::default();
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
                WebSetupState::CustomCommands => {
                    lines.push(Line::from(Span::styled(
                        "Custom CLI command".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    let rows = [
                        (
                            "  fetch",
                            self.extended
                                .web
                                .custom
                                .fetch_command
                                .as_deref()
                                .unwrap_or("not configured"),
                        ),
                        (
                            "  search",
                            self.extended
                                .web
                                .custom
                                .search_command
                                .as_deref()
                                .unwrap_or("not configured"),
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
            }
            if let Some(field) = p.editing {
                let label = match field {
                    ToolField::WebFetchCommand => "fetch command",
                    ToolField::WebSearchCommand => "search command",
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

        let mut row_idx = 0usize;
        let custom_rows = [
            (
                "webfetch",
                self.extended
                    .web
                    .custom
                    .fetch_command
                    .as_deref()
                    .unwrap_or("not configured"),
            ),
            (
                "websearch",
                self.extended
                    .web
                    .custom
                    .search_command
                    .as_deref()
                    .unwrap_or("not configured"),
            ),
        ];
        for (name, value) in custom_rows {
            let selected = row_idx == p.cursor;
            let marker = if selected { "▸ " } else { "  " };
            let label_style = if selected {
                selected_style()
            } else {
                focused_field_style()
            };
            push_tool_value_row(&mut lines, width, marker, name, label_style, value, muted);
            row_idx += 1;
        }
        lines.push(Line::default());

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
            "choose native Firecrawl/TinyFish or typed custom commands",
            muted,
        );
        row_idx += 1;

        // `[reset to defaults]` button — the last navigable row.
        let reset_row = row_idx;
        lines.push(
            p.reset
                .render_line(p.cursor == reset_row, "reset to defaults"),
        );
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Custom web commands must include {url} for webfetch and {query} for websearch."
                .to_string(),
            muted,
        )));

        if let Some(field) = p.editing {
            let label = match field {
                ToolField::WebFetchCommand => "fetch command",
                ToolField::WebSearchCommand => "search command",
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
        format!(
            "{} › Tools",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
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
