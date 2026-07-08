//! `/settings → Tools` page: built-in custom-tool templates
//! (`webfetch`, `websearch`) and their per-tool command + description
//! + enabled fields under `config.json`'s `tools` key.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::config::extended::ToolCommandTemplate;
use crate::tui::textfield::TextField;

use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    WrappedValueLayout, focused_field_style, muted_style, push_text_field_at_cursor,
    push_wrapped_prefixed_value, selected_style, warning_style, window_lines,
};
use super::{Nav, Page, SettingsDialog, save_status};

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

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum WebSetupState {
    Provider,
    AgentBrowserSearchEngine,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum ToolField {
    Command,
    Description,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum WebProvider {
    Firecrawl,
    TinyFish,
    AgentBrowser,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum AgentBrowserSearchEngine {
    Google,
    Bing,
    Brave,
}

struct WebProviderChoice {
    provider: WebProvider,
    label: &'static str,
    command: &'static str,
    docs_url: &'static str,
    installed: bool,
    hint: &'static str,
}

/// Built-in custom-tool names surfaced on the Tools page. These are
/// also registered as live tools by the agent runtime (see
/// `src/tools/custom.rs`).
pub fn builtin_tool_names() -> &'static [&'static str] {
    &["webfetch", "websearch"]
}

/// Default bash command + description for a built-in tool. The defaults
/// rely only on widely-available CLI utilities (curl, ddgr) so a user
/// can land a working tool without configuring anything.
pub fn default_template_for(name: &str) -> ToolCommandTemplate {
    match name {
        "webfetch" => ToolCommandTemplate {
            enabled: true,
            command:
                "curl -sSL --max-time 20 --max-filesize 2000000 --user-agent 'cockpit-cli' {url}"
                    .to_string(),
            description: Some(
                "Fetch a URL. Pass `url` (the target). Returns the response body. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer (news, non-package info).".to_string(),
            ),
        },
        "websearch" => ToolCommandTemplate {
            enabled: true,
            command: "ddgr --json --num 8 -- {query}".to_string(),
            description: Some(
                "Search the web. Pass `query`. Returns JSON results from DuckDuckGo. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer (news, non-package info).".to_string(),
            ),
        },
        _ => ToolCommandTemplate {
            enabled: true,
            command: String::new(),
            description: None,
        },
    }
}

fn firecrawl_template_for(name: &str) -> Option<ToolCommandTemplate> {
    match name {
        "webfetch" => Some(ToolCommandTemplate {
            enabled: true,
            command: "firecrawl scrape --format markdown {url}".to_string(),
            description: Some(
                "Fetch a URL using Firecrawl. Pass `url`; returns markdown page content. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
            ),
        }),
        "websearch" => Some(ToolCommandTemplate {
            enabled: true,
            command: "firecrawl search --json --limit 8 {query}".to_string(),
            description: Some(
                "Search the web using Firecrawl. Pass `query`; returns compact JSON web results. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
            ),
        }),
        _ => None,
    }
}

fn tinyfish_template_for(name: &str) -> Option<ToolCommandTemplate> {
    match name {
        "webfetch" => Some(ToolCommandTemplate {
            enabled: true,
            command: "tinyfish fetch content get --format markdown {url}".to_string(),
            description: Some(
                "Fetch a URL using TinyFish. Pass `url`; returns markdown content from the fetched page. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
            ),
        }),
        "websearch" => Some(ToolCommandTemplate {
            enabled: true,
            command: "tinyfish search query --pretty {query}".to_string(),
            description: Some(
                "Search the web using TinyFish. Pass `query`; returns readable search results. For dependency API usage, use docs when uncertain; web is for what `docs` can't answer.".to_string(),
            ),
        }),
        _ => None,
    }
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

fn web_provider_choices(command_installed: fn(&str) -> bool) -> [WebProviderChoice; 3] {
    [
        WebProviderChoice {
            provider: WebProvider::Firecrawl,
            label: "Firecrawl",
            command: "firecrawl",
            docs_url: "https://github.com/firecrawl/cli",
            installed: command_installed("firecrawl"),
            hint: "commonly requires FIRECRAWL_API_KEY",
        },
        WebProviderChoice {
            provider: WebProvider::TinyFish,
            label: "TinyFish",
            command: "tinyfish",
            docs_url: "https://docs.tinyfish.ai/cli",
            installed: command_installed("tinyfish"),
            hint: "may require TinyFish auth setup",
        },
        WebProviderChoice {
            provider: WebProvider::AgentBrowser,
            label: "agent-browser",
            command: "agent-browser",
            docs_url: "https://github.com/vercel-labs/agent-browser",
            installed: command_installed("agent-browser"),
            hint: "search may require a configured browser profile/session",
        },
    ]
}

impl SettingsDialog {
    pub(super) fn handle_tools_key(&mut self, key: KeyEvent) -> bool {
        let placeholder = Page::Tools(ToolsPage {
            cursor: 0,
            setup: None,
            editing: None,
            buf: TextField::default(),
            edit_target: None,
            status: None,
            reset: ResetButton::default(),
        });
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::Tools(p) = &mut page {
            self.handle_tools_page_key(key, p)
        } else {
            Nav::Stay
        };
        match nav {
            Nav::Stay => {
                self.page = page;
                false
            }
            Nav::Replace(new) => {
                self.page = new;
                false
            }
            Nav::Close => true,
        }
    }

    fn handle_tools_page_key(&mut self, key: KeyEvent, p: &mut ToolsPage) -> Nav {
        if let Some(field) = p.editing {
            match key.code {
                KeyCode::Enter => {
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
                                entry.description = if new.is_empty() { None } else { Some(new) };
                            }
                        }
                    }
                    p.editing = None;
                    p.edit_target = None;
                    p.status = save_status(self.save_extended());
                }
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
                WebSetupState::Provider => web_provider_choices(self.command_installed).len(),
                WebSetupState::AgentBrowserSearchEngine => 3,
            };
            match key.code {
                KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                    p.setup = None;
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
                        let choices = web_provider_choices(self.command_installed);
                        if let Some(choice) = choices.get(p.cursor) {
                            if !choice.installed {
                                p.status = Some(format!(
                                    "{} is not on PATH. Install: {}",
                                    choice.command, choice.docs_url
                                ));
                            } else if choice.provider == WebProvider::AgentBrowser {
                                self.apply_agent_browser_fetch();
                                p.setup = Some(WebSetupState::AgentBrowserSearchEngine);
                                p.cursor = 0;
                                p.status = Some(
                                    "agent-browser webfetch applied; choose a search engine"
                                        .to_string(),
                                );
                            } else {
                                self.apply_web_provider(choice.provider, None);
                                p.setup = None;
                                p.cursor = 0;
                                p.status = save_status(self.save_extended());
                            }
                        }
                    }
                    WebSetupState::AgentBrowserSearchEngine => {
                        let engine = match p.cursor {
                            0 => AgentBrowserSearchEngine::Google,
                            1 => AgentBrowserSearchEngine::Bing,
                            _ => AgentBrowserSearchEngine::Brave,
                        };
                        self.apply_web_provider(WebProvider::AgentBrowser, Some(engine));
                        p.setup = None;
                        p.cursor = 0;
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
                return Nav::Replace(Page::Root {
                    cursor: self.last_root_cursor,
                });
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

    fn apply_web_provider(
        &mut self,
        provider: WebProvider,
        engine: Option<AgentBrowserSearchEngine>,
    ) {
        match provider {
            WebProvider::Firecrawl => {
                for name in builtin_tool_names() {
                    if let Some(tpl) = firecrawl_template_for(name) {
                        self.extended.tools.insert(name.to_string(), tpl);
                    }
                }
            }
            WebProvider::TinyFish => {
                for name in builtin_tool_names() {
                    if let Some(tpl) = tinyfish_template_for(name) {
                        self.extended.tools.insert(name.to_string(), tpl);
                    }
                }
            }
            WebProvider::AgentBrowser => {
                self.apply_agent_browser_fetch();
                if let Some(engine) = engine {
                    self.extended.tools.insert(
                        "websearch".to_string(),
                        agent_browser_search_template(engine),
                    );
                }
            }
        }
    }

    fn apply_agent_browser_fetch(&mut self) {
        self.extended
            .tools
            .insert("webfetch".to_string(), agent_browser_fetch_template());
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
                        "Choose web CLI provider".to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::default());
                    for (idx, choice) in web_provider_choices(self.command_installed)
                        .iter()
                        .enumerate()
                    {
                        let selected = idx == p.cursor;
                        let marker = if selected { "▸ " } else { "  " };
                        let state = if choice.installed {
                            "installed"
                        } else {
                            "missing"
                        };
                        let value = format!(
                            "{} ({state}) - {} - {}",
                            choice.label, choice.docs_url, choice.hint
                        );
                        let label_style = if selected {
                            selected_style()
                        } else {
                            focused_field_style()
                        };
                        push_tool_value_row(
                            &mut lines,
                            width,
                            marker,
                            "  provider",
                            label_style,
                            &value,
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
            "choose Firecrawl, TinyFish, or agent-browser presets",
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

        if let Some(field) = p.editing {
            let label = match field {
                ToolField::Command => "command",
                ToolField::Description => "description",
            };
            push_text_field_at_cursor(
                &mut lines,
                width,
                label,
                p.buf.text(),
                p.buf.cursor(),
                true,
                None,
            );
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        lines
    }

    pub(super) fn render_tools_page(&self, frame: &mut Frame, area: Rect, p: &ToolsPage) {
        let lines = self.build_tools_page_lines(area.width, p);
        let lines = window_lines(&lines, Some(p.cursor), area.height);
        frame.render_widget(Paragraph::new(lines), area);
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
