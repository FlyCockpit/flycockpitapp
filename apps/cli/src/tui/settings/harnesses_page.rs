//! `/settings → Harnesses` page (GOALS §6,
//! implementation note).
//!
//! Edits the `extended.harnesses` map: external coding harnesses cockpit
//! can delegate to via `harness_invoke`. Two views:
//!   - **List**: every configured harness, plus `[+ add harness]`, a
//!     `[seed installed presets]` action (seeds, from claude/codex/
//!     opencode/copilot/goose/grok, only those whose `command` is installed
//!     on `PATH`), and the page-level reset (clear, then re-seed installed
//!     presets). Add / delete here.
//!   - **Edit**: per-harness field editor — text fields (command, args,
//!     model flag, default model, models, model-list args, JSON-output
//!     args, agent-file args/env, auth env vars, auth probe, timeout) and
//!     cycled enums (prompt input mode, argv overflow, JSON-output +
//!     agent-file toggles).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::config::extended::{
    ArgvOverflowBehavior, DEFAULT_HARNESS_TIMEOUT_SECS, HarnessConfig, PromptInputMode,
    builtin_harness_presets,
};
use crate::tui::textfield::TextField;

use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    focused_field_style, marker, muted_style, push_text_field_at_cursor, selected_style,
    warning_style, window_lines,
};
use super::{Nav, Page, SettingsDialog, save_status};

/// `/settings → Harnesses` state: either the harness list or a per-harness
/// field editor.
pub(super) enum HarnessesPage {
    List(ListState),
    Edit(EditState),
}

pub(super) struct ListState {
    pub(super) cursor: usize,
    pub(super) status: Option<String>,
    /// Two-step delete confirm: armed by the first `d`, applied by the
    /// second on the same row.
    pub(super) delete_pending: bool,
    /// Page-level "reset to verified presets" confirm.
    pub(super) reset: ResetButton,
    /// `Some` while typing a new harness's name (the `[+ add]` flow).
    pub(super) adding: Option<TextField>,
}

pub(super) struct EditState {
    /// The harness being edited (its map key).
    pub(super) name: String,
    pub(super) cursor: usize,
    pub(super) status: Option<String>,
    /// `Some` while editing a text field; carries the edit buffer.
    pub(super) editing: Option<TextField>,
}

/// The editable fields of a harness, in display order. Enum rows cycle on
/// Enter; text rows open the edit buffer.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Field {
    Command,
    Args,
    PromptInput,
    ArgvOverflow,
    ModelArgs,
    DefaultModel,
    Models,
    ModelListArgs,
    SupportsJson,
    JsonOutputArgs,
    SupportsAgentFile,
    AgentFileArgs,
    AgentFileEnv,
    AuthEnvVars,
    AuthProbeArgs,
    Timeout,
}

const FIELDS: [Field; 16] = [
    Field::Command,
    Field::Args,
    Field::PromptInput,
    Field::ArgvOverflow,
    Field::ModelArgs,
    Field::DefaultModel,
    Field::Models,
    Field::ModelListArgs,
    Field::SupportsJson,
    Field::JsonOutputArgs,
    Field::SupportsAgentFile,
    Field::AgentFileArgs,
    Field::AgentFileEnv,
    Field::AuthEnvVars,
    Field::Timeout,
    // AuthProbeArgs sits before Timeout in the struct but we keep the
    // common fields first; place it last so the high-traffic ones lead.
    Field::AuthProbeArgs,
];

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::Command => "command",
            Field::Args => "args",
            Field::PromptInput => "prompt input",
            Field::ArgvOverflow => "argv overflow",
            Field::ModelArgs => "model args",
            Field::DefaultModel => "default model",
            Field::Models => "models",
            Field::ModelListArgs => "model-list args",
            Field::SupportsJson => "JSON output",
            Field::JsonOutputArgs => "JSON output args",
            Field::SupportsAgentFile => "agent file (flag)",
            Field::AgentFileArgs => "agent-file args",
            Field::AgentFileEnv => "agent-file env",
            Field::AuthEnvVars => "auth env vars",
            Field::AuthProbeArgs => "auth probe args",
            Field::Timeout => "timeout (secs)",
        }
    }

    /// Whether the row is a text field (vs a cycled enum/toggle).
    fn is_text(self) -> bool {
        !matches!(
            self,
            Field::PromptInput
                | Field::ArgvOverflow
                | Field::SupportsJson
                | Field::SupportsAgentFile
        )
    }

    /// The field's current display value for `hc`.
    fn value(self, hc: &HarnessConfig) -> String {
        match self {
            Field::Command => hc.command.clone(),
            Field::Args => join_args(&hc.args),
            Field::PromptInput => hc.prompt_input.as_str().to_string(),
            Field::ArgvOverflow => hc.argv_overflow.as_str().to_string(),
            Field::ModelArgs => join_args(&hc.model_args),
            Field::DefaultModel => hc.default_model.clone().unwrap_or_default(),
            Field::Models => join_args(&hc.models),
            Field::ModelListArgs => join_args(&hc.model_list_args),
            Field::SupportsJson => yesno(hc.supports_json_output),
            Field::JsonOutputArgs => join_args(&hc.json_output_args),
            Field::SupportsAgentFile => yesno(hc.supports_agent_file),
            Field::AgentFileArgs => join_args(&hc.agent_file_args),
            Field::AgentFileEnv => hc.agent_file_env.clone().unwrap_or_default(),
            Field::AuthEnvVars => join_args(&hc.auth_env_vars),
            Field::AuthProbeArgs => join_args(&hc.auth_probe_args),
            Field::Timeout => hc.timeout_secs.to_string(),
        }
    }

    /// Apply a committed text-field edit to `hc`. Whitespace-split for the
    /// list fields; trimmed scalar for the others.
    fn apply_text(self, hc: &mut HarnessConfig, raw: &str) {
        match self {
            Field::Command => hc.command = raw.trim().to_string(),
            Field::Args => hc.args = split_args(raw),
            Field::ModelArgs => hc.model_args = split_args(raw),
            Field::DefaultModel => {
                let t = raw.trim();
                hc.default_model = if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                };
            }
            Field::Models => hc.models = split_args(raw),
            Field::ModelListArgs => hc.model_list_args = split_args(raw),
            Field::JsonOutputArgs => hc.json_output_args = split_args(raw),
            Field::AgentFileArgs => hc.agent_file_args = split_args(raw),
            Field::AgentFileEnv => {
                let t = raw.trim();
                hc.agent_file_env = if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                };
            }
            Field::AuthEnvVars => hc.auth_env_vars = split_args(raw),
            Field::AuthProbeArgs => hc.auth_probe_args = split_args(raw),
            Field::Timeout => {
                if let Ok(n) = raw.trim().parse::<u64>()
                    && n > 0
                {
                    hc.timeout_secs = n;
                }
            }
            // Enum/toggle fields don't reach here.
            Field::PromptInput
            | Field::ArgvOverflow
            | Field::SupportsJson
            | Field::SupportsAgentFile => {}
        }
    }

    /// Cycle an enum/toggle field on `hc`.
    fn cycle(self, hc: &mut HarnessConfig) {
        match self {
            Field::PromptInput => hc.prompt_input = hc.prompt_input.cycled(),
            Field::ArgvOverflow => hc.argv_overflow = hc.argv_overflow.cycled(),
            Field::SupportsJson => hc.supports_json_output = !hc.supports_json_output,
            Field::SupportsAgentFile => hc.supports_agent_file = !hc.supports_agent_file,
            _ => {}
        }
    }
}

fn yesno(b: bool) -> String {
    if b { "yes".into() } else { "no".into() }
}

/// Join an argv list into a single editable space-separated string. Args
/// containing spaces are wrapped in double quotes so the round-trip is
/// lossless for the common case.
fn join_args(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') || a.is_empty() {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Split an edited argv string back into tokens, honoring double-quoted
/// runs (the inverse of [`join_args`] for the common case).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut had_token = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                had_token = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if had_token {
                    out.push(std::mem::take(&mut cur));
                    had_token = false;
                }
            }
            c => {
                cur.push(c);
                had_token = true;
            }
        }
    }
    if had_token {
        out.push(cur);
    }
    out
}

impl SettingsDialog {
    pub(super) fn handle_harnesses_key(&mut self, key: KeyEvent) -> bool {
        let placeholder = Page::Harnesses(HarnessesPage::List(ListState {
            cursor: 0,
            status: None,
            delete_pending: false,
            reset: ResetButton::default(),
            adding: None,
        }));
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::Harnesses(p) = &mut page {
            self.handle_harnesses_page_key(key, p)
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

    fn handle_harnesses_page_key(&mut self, key: KeyEvent, p: &mut HarnessesPage) -> Nav {
        match p {
            HarnessesPage::List(s) => self.handle_harness_list_key(key, s),
            HarnessesPage::Edit(s) => self.handle_harness_edit_key(key, s),
        }
    }

    // ── List view ────────────────────────────────────────────────────

    fn handle_harness_list_key(&mut self, key: KeyEvent, s: &mut ListState) -> Nav {
        // Add-name entry mode.
        if let Some(buf) = s.adding.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    let name = buf.text().trim().to_string();
                    s.adding = None;
                    if name.is_empty() {
                        return Nav::Stay;
                    }
                    if self.extended.harnesses.contains_key(&name) {
                        s.status = Some(format!("harness `{name}` already exists"));
                        return Nav::Stay;
                    }
                    // New blank harness; drop straight into its editor.
                    self.extended
                        .harnesses
                        .insert(name.clone(), blank_harness());
                    s.status = save_status(self.save_extended());
                    return Nav::Replace(Page::Harnesses(HarnessesPage::Edit(EditState {
                        name,
                        cursor: 0,
                        status: None,
                        editing: None,
                    })));
                }
                KeyCode::Esc => s.adding = None,
                _ => {
                    buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        let mut names = self.harness_names();
        let n = names.len();
        // Rows: 0..n harnesses, then [+ add], [seed presets], [reset].
        let add_row = n;
        let seed_row = n + 1;
        let reset_row = n + 2;
        let total = n + 3;

        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Replace(Page::Root {
                    cursor: self.last_root_cursor,
                });
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.delete_pending = false;
                s.reset.disarm();
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, total);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.delete_pending = false;
                s.reset.disarm();
                s.cursor = crate::tui::nav::wrap_next(s.cursor, total);
            }
            KeyCode::Char('a') => {
                s.adding = Some(TextField::default());
            }
            KeyCode::Char('d') if s.cursor < n => {
                if s.delete_pending {
                    let name = names.remove(s.cursor);
                    self.extended.harnesses.remove(&name);
                    s.delete_pending = false;
                    if s.cursor >= names.len() && s.cursor > 0 {
                        s.cursor -= 1;
                    }
                    s.status = save_status(self.save_extended());
                } else {
                    s.delete_pending = true;
                    s.status = Some("press d again to delete".into());
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if s.cursor < n {
                    let name = names[s.cursor].clone();
                    return Nav::Replace(Page::Harnesses(HarnessesPage::Edit(EditState {
                        name,
                        cursor: 0,
                        status: None,
                        editing: None,
                    })));
                } else if s.cursor == add_row {
                    s.adding = Some(TextField::default());
                } else if s.cursor == seed_row {
                    s.status = self.seed_presets_status();
                } else if s.cursor == reset_row {
                    if s.reset.activate() == ResetOutcome::Apply {
                        self.extended.harnesses.clear();
                        s.status = self.seed_presets_status();
                    } else {
                        s.status = None;
                    }
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Seed missing verified presets whose `command` is installed on
    /// `PATH`, without clobbering existing (possibly user-edited) entries
    /// of the same name. Presets for harnesses not found on `PATH` are
    /// skipped entirely. Returns the number of presets that were installed
    /// (i.e. eligible), regardless of whether they were already present —
    /// `0` means no known harness resolved on `PATH`.
    fn seed_harness_presets(&mut self) -> usize {
        let mut installed = 0;
        for (name, preset) in builtin_harness_presets() {
            if !(self.command_installed)(&preset.command) {
                continue;
            }
            installed += 1;
            self.extended.harnesses.entry(name).or_insert(preset);
        }
        installed
    }

    /// Seed installed presets and produce the status line: the usual save
    /// status when at least one known harness was on `PATH`, or an explicit
    /// none-found message otherwise (nothing was seeded in that case).
    fn seed_presets_status(&mut self) -> Option<String> {
        if self.seed_harness_presets() == 0 {
            Some("no known harnesses found on `PATH`".into())
        } else {
            save_status(self.save_extended())
        }
    }

    /// Sorted harness names for stable display + indexing.
    fn harness_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.extended.harnesses.keys().cloned().collect();
        names.sort();
        names
    }

    // ── Edit view ────────────────────────────────────────────────────

    fn handle_harness_edit_key(&mut self, key: KeyEvent, s: &mut EditState) -> Nav {
        // The harness vanished out from under us (deleted elsewhere) — bail
        // back to the list.
        if !self.extended.harnesses.contains_key(&s.name) {
            return Nav::Replace(self.harness_list_page());
        }

        if let Some(buf) = s.editing.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    let raw = buf.text().to_string();
                    let field = FIELDS[s.cursor.min(FIELDS.len() - 1)];
                    if let Some(hc) = self.extended.harnesses.get_mut(&s.name) {
                        field.apply_text(hc, &raw);
                    }
                    s.editing = None;
                    s.status = save_status(self.save_extended());
                }
                KeyCode::Esc => s.editing = None,
                _ => {
                    buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Replace(self.harness_list_page());
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, FIELDS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, FIELDS.len());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let field = FIELDS[s.cursor.min(FIELDS.len() - 1)];
                if field.is_text() {
                    let current = self
                        .extended
                        .harnesses
                        .get(&s.name)
                        .map(|hc| field.value(hc))
                        .unwrap_or_default();
                    s.editing = Some(TextField::new(current));
                } else if let Some(hc) = self.extended.harnesses.get_mut(&s.name) {
                    field.cycle(hc);
                    s.status = save_status(self.save_extended());
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn harness_list_page(&self) -> Page {
        Page::Harnesses(HarnessesPage::List(ListState {
            cursor: 0,
            status: None,
            delete_pending: false,
            reset: ResetButton::default(),
            adding: None,
        }))
    }

    // ── Rendering ──────────────────────────────────────────────────────

    pub(super) fn render_harnesses_page(&self, frame: &mut Frame, area: Rect, p: &HarnessesPage) {
        match p {
            HarnessesPage::List(s) => self.render_harness_list(frame, area, s),
            HarnessesPage::Edit(s) => self.render_harness_edit(frame, area, s),
        }
    }

    fn render_harness_list(&self, frame: &mut Frame, area: Rect, s: &ListState) {
        let muted = muted_style();
        let yellow = warning_style();
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            "External harnesses (harness_invoke)".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::styled("config: ".to_string(), muted),
            Span::styled(
                crate::welcome::display_path(&self.extended_path),
                focused_field_style(),
            ),
        ]));
        if !self.extended_warnings.is_empty() {
            lines.push(Line::from(Span::styled(
                self.extended_warnings.join("; "),
                yellow,
            )));
        }
        lines.push(Line::default());

        let names = self.harness_names();
        for (i, name) in names.iter().enumerate() {
            let hc = &self.extended.harnesses[name];
            let marker = marker(i == s.cursor);
            let label_style = if i == s.cursor {
                selected_style()
            } else {
                focused_field_style()
            };
            let summary = format!(
                "{} ({}, {} models)",
                hc.command,
                hc.prompt_input.as_str(),
                hc.models.len()
            );
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{name:<14}"), label_style),
                Span::raw("  "),
                Span::styled(summary, muted),
            ]));
        }

        let add_row = names.len();
        let seed_row = names.len() + 1;
        let reset_row = names.len() + 2;
        lines.push(Line::default());
        lines.push(synthetic_row("[+ add harness]", s.cursor == add_row));
        lines.push(synthetic_row(
            "[seed installed presets]",
            s.cursor == seed_row,
        ));
        lines.push(
            s.reset
                .render_line(s.cursor == reset_row, "reset to verified presets"),
        );

        if let Some(buf) = &s.adding {
            lines.push(Line::default());
            push_text_field_at_cursor(
                &mut lines,
                area.width,
                "new harness name",
                buf.text(),
                buf.cursor(),
                true,
                None,
            );
        }
        if let Some(status) = &s.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }
        let lines = window_lines(&lines, Some(s.cursor + 4), area.height);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn render_harness_edit(&self, frame: &mut Frame, area: Rect, s: &EditState) {
        let muted = muted_style();
        let yellow = warning_style();
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            format!("Harness: {}", s.name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());

        let Some(hc) = self.extended.harnesses.get(&s.name) else {
            frame.render_widget(Paragraph::new(lines), area);
            return;
        };

        for (i, field) in FIELDS.iter().enumerate() {
            let marker = marker(i == s.cursor);
            let label_style = if i == s.cursor {
                selected_style()
            } else {
                focused_field_style()
            };
            let value = field.value(hc);
            let shown = if value.is_empty() {
                "(unset)".to_string()
            } else {
                value
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{:<18}", field.label()), label_style),
                Span::raw("  "),
                Span::styled(shown, muted),
            ]));
        }

        if let Some(buf) = &s.editing {
            let field = FIELDS[s.cursor.min(FIELDS.len() - 1)];
            lines.push(Line::default());
            push_text_field_at_cursor(
                &mut lines,
                area.width,
                field.label(),
                buf.text(),
                buf.cursor(),
                true,
                None,
            );
        }
        if let Some(status) = &s.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }
        let lines = window_lines(&lines, Some(s.cursor + 2), area.height);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

/// A fresh blank harness — `stdin` delivery, default timeout, otherwise
/// empty so the user fills it in (or seeds a preset instead).
fn blank_harness() -> HarnessConfig {
    HarnessConfig {
        command: String::new(),
        args: vec![],
        prompt_input: PromptInputMode::Stdin,
        argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
        model_args: vec![],
        default_model: None,
        models: vec![],
        model_list_args: vec![],
        supports_json_output: false,
        json_output_args: vec![],
        supports_agent_file: false,
        agent_file_args: vec![],
        agent_file_env: None,
        auth_env_vars: vec![],
        auth_probe_args: vec![],
        timeout_secs: DEFAULT_HARNESS_TIMEOUT_SECS,
    }
}

fn synthetic_row(label: &str, selected: bool) -> Line<'static> {
    Line::from(vec![
        Span::raw(marker(selected)),
        Span::styled(
            label.to_string(),
            if selected {
                selected_style()
            } else {
                muted_style()
            },
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_cover_all_editable_harness_fields() {
        // 16 fields, all distinct.
        let mut seen = std::collections::HashSet::new();
        for f in FIELDS {
            assert!(
                seen.insert(f.label()),
                "duplicate field label {}",
                f.label()
            );
        }
        assert_eq!(FIELDS.len(), 16);
    }

    #[test]
    fn args_round_trip_through_join_split() {
        let args = vec![
            "-c".to_string(),
            "approval_policy=never".to_string(),
            "with space".to_string(),
        ];
        let joined = join_args(&args);
        assert_eq!(split_args(&joined), args);
    }

    #[test]
    fn split_handles_plain_and_quoted() {
        assert_eq!(split_args("-p --json"), vec!["-p", "--json"]);
        assert_eq!(split_args("run \"a b\" c"), vec!["run", "a b", "c"]);
        assert!(split_args("   ").is_empty());
    }

    #[test]
    fn apply_text_updates_scalar_list_and_timeout() {
        let mut hc = blank_harness();
        Field::Command.apply_text(&mut hc, " claude ");
        assert_eq!(hc.command, "claude");
        Field::Args.apply_text(&mut hc, "-p --json");
        assert_eq!(hc.args, vec!["-p", "--json"]);
        Field::DefaultModel.apply_text(&mut hc, "  ");
        assert!(hc.default_model.is_none());
        Field::DefaultModel.apply_text(&mut hc, "opus");
        assert_eq!(hc.default_model.as_deref(), Some("opus"));
        Field::Timeout.apply_text(&mut hc, "120");
        assert_eq!(hc.timeout_secs, 120);
        // A non-numeric / zero timeout is ignored (keeps prior value).
        Field::Timeout.apply_text(&mut hc, "abc");
        assert_eq!(hc.timeout_secs, 120);
        Field::Timeout.apply_text(&mut hc, "0");
        assert_eq!(hc.timeout_secs, 120);
    }

    #[test]
    fn cycle_toggles_and_enums() {
        let mut hc = blank_harness();
        assert!(!hc.supports_json_output);
        Field::SupportsJson.cycle(&mut hc);
        assert!(hc.supports_json_output);
        assert_eq!(hc.prompt_input, PromptInputMode::Stdin);
        Field::PromptInput.cycle(&mut hc);
        assert_eq!(hc.prompt_input, PromptInputMode::Argv);
        Field::ArgvOverflow.cycle(&mut hc);
        assert_eq!(hc.argv_overflow, ArgvOverflowBehavior::SpillToStdin);
    }
}
