//! `/quick` session settings dialog.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use cockpit_config::extended::{ApprovalMode, LlmMode};
use cockpit_config::providers::ModelTrust;
use cockpit_core::tools::sandbox_mode::SandboxMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickModelChoice {
    pub provider_id: String,
    pub model_id: String,
    pub label: String,
    pub trust: ModelTrust,
    pub mode: LlmMode,
}

impl From<crate::tui::model_picker::ModelChoice> for QuickModelChoice {
    fn from(choice: crate::tui::model_picker::ModelChoice) -> Self {
        Self {
            provider_id: choice.provider_id,
            model_id: choice.model_id,
            label: choice.label,
            trust: choice.trust,
            mode: choice.mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickCurrent {
    pub llm_mode: LlmMode,
    pub recursion_enabled: bool,
    pub recursion_depth: u32,
    pub trusted_only: bool,
    pub sandbox_mode: SandboxMode,
    pub container_network_enabled: bool,
    pub container_availability: cockpit_core::container::ContainerAvailability,
    pub approval_mode: ApprovalMode,
    pub active_model: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuickCommit {
    pub llm_mode: Option<LlmMode>,
    pub recursion: Option<(bool, u32)>,
    pub trusted_only: Option<bool>,
    pub sandbox_mode: Option<SandboxMode>,
    pub container_network_enabled: Option<bool>,
    pub approval_mode: Option<ApprovalMode>,
    pub active_model: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickOutcome {
    Close,
    Commit(QuickCommit),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Mode,
    Recursion,
    Trust,
    Sandbox,
    Permissions,
    Model,
}

const TABS: [Tab; 6] = [
    Tab::Mode,
    Tab::Recursion,
    Tab::Trust,
    Tab::Sandbox,
    Tab::Permissions,
    Tab::Model,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecursionChoice {
    Off,
    Depth(u32),
}

pub struct QuickDialog {
    current: QuickCurrent,
    models: Vec<QuickModelChoice>,
    tab: usize,
    cursors: [usize; 6],
    staged_llm_mode: Option<LlmMode>,
    staged_recursion: Option<RecursionChoice>,
    staged_trusted_only: Option<bool>,
    staged_sandbox_mode: Option<SandboxMode>,
    staged_container_network_enabled: Option<bool>,
    staged_approval_mode: Option<ApprovalMode>,
    staged_model: Option<usize>,
}

impl QuickDialog {
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Quick settings",
            bindings: &[
                KeyBinding {
                    key: "Tab/→/l",
                    action: "next",
                    desc: "switch to the next settings tab",
                },
                KeyBinding {
                    key: "Shift+Tab/←/h",
                    action: "previous",
                    desc: "switch to the previous settings tab",
                },
                KeyBinding {
                    key: "↑/↓/j/k",
                    action: "move",
                    desc: "highlight an option in the active tab",
                },
                KeyBinding {
                    key: "Space",
                    action: "stage",
                    desc: "stage the highlighted option",
                },
                KeyBinding {
                    key: "Enter",
                    action: "commit",
                    desc: "apply staged session-only changes",
                },
                KeyBinding {
                    key: "Esc",
                    action: "discard",
                    desc: "close without applying staged changes",
                },
            ],
        }
    }

    pub fn open(current: QuickCurrent, models: Vec<QuickModelChoice>) -> Self {
        let mut dialog = Self {
            current,
            models,
            tab: 0,
            cursors: [0; 6],
            staged_llm_mode: None,
            staged_recursion: None,
            staged_trusted_only: None,
            staged_sandbox_mode: None,
            staged_container_network_enabled: None,
            staged_approval_mode: None,
            staged_model: None,
        };
        dialog.align_cursors_to_current();
        dialog
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<QuickOutcome> {
        match key.code {
            KeyCode::Esc => Some(QuickOutcome::Close),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.tab = crate::tui::nav::wrap_prev(self.tab, TABS.len());
                None
            }
            KeyCode::BackTab => {
                self.tab = crate::tui::nav::wrap_prev(self.tab, TABS.len());
                None
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.tab = crate::tui::nav::wrap_next(self.tab, TABS.len());
                None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.tab = crate::tui::nav::wrap_prev(self.tab, TABS.len());
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let idx = self.tab;
                self.cursors[idx] =
                    crate::tui::nav::wrap_prev(self.cursors[idx], self.option_count(TABS[idx]));
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let idx = self.tab;
                self.cursors[idx] =
                    crate::tui::nav::wrap_next(self.cursors[idx], self.option_count(TABS[idx]));
                None
            }
            KeyCode::Char(' ') => {
                self.stage_active();
                None
            }
            KeyCode::Enter => {
                self.stage_active();
                Some(QuickOutcome::Commit(self.commit()))
            }
            _ => None,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(" /quick ");
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);
        frame.render_widget(Paragraph::new(self.tabs_line()), layout[0]);
        frame.render_widget(Paragraph::new(self.option_lines()), layout[1]);
        frame.render_widget(
            Paragraph::new(
                "tab/→/l: next  shift+tab/←/h: previous  ↑/↓/j/k: move  space: stage  enter: commit  esc: discard",
            )
            .style(Style::default().fg(Color::Indexed(crate::tui::theme::MUTED_COLOR_INDEX))),
            layout[2],
        );
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> String {
        let mut out = String::new();
        for span in self.tabs_line().spans {
            out.push_str(span.content.as_ref());
        }
        for line in self.option_lines() {
            out.push('\n');
            for span in line.spans {
                out.push_str(span.content.as_ref());
            }
        }
        out
    }

    #[cfg(test)]
    fn active_tab(&self) -> Tab {
        TABS[self.tab]
    }

    #[cfg(test)]
    fn active_cursor(&self) -> usize {
        self.cursors[self.tab]
    }

    #[cfg(test)]
    fn has_staged_changes(&self) -> bool {
        self.commit() != QuickCommit::default()
    }

    fn align_cursors_to_current(&mut self) {
        self.cursors[0] = mode_options()
            .iter()
            .position(|mode| *mode == self.current.llm_mode)
            .unwrap_or(0);
        self.cursors[1] = recursion_options()
            .iter()
            .position(|choice| *choice == self.current_recursion())
            .unwrap_or(0);
        self.cursors[2] = usize::from(self.current.trusted_only);
        self.cursors[3] = sandbox_mode_options()
            .iter()
            .position(|mode| *mode == self.current.sandbox_mode)
            .unwrap_or(1);
        self.cursors[4] = approval_options()
            .iter()
            .position(|mode| *mode == self.current.approval_mode)
            .unwrap_or(0);
        self.cursors[5] = self
            .current
            .active_model
            .as_ref()
            .and_then(|(provider, model)| {
                self.models
                    .iter()
                    .position(|choice| &choice.provider_id == provider && &choice.model_id == model)
            })
            .unwrap_or(0);
    }

    fn active_staged_recursion(&self) -> RecursionChoice {
        self.staged_recursion
            .unwrap_or_else(|| self.current_recursion())
    }

    fn current_recursion(&self) -> RecursionChoice {
        if self.current.recursion_enabled && self.current.recursion_depth > 0 {
            RecursionChoice::Depth(self.current.recursion_depth.min(6))
        } else {
            RecursionChoice::Off
        }
    }

    fn option_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Mode => mode_options().len(),
            Tab::Recursion => recursion_options().len(),
            Tab::Trust => 2,
            Tab::Sandbox => sandbox_mode_options().len() + 1,
            Tab::Permissions => approval_options().len(),
            Tab::Model => self.models.len().max(1),
        }
    }

    fn stage_active(&mut self) {
        match TABS[self.tab] {
            Tab::Mode => {
                self.staged_llm_mode = Some(mode_options()[self.cursors[self.tab]]);
            }
            Tab::Recursion => {
                self.staged_recursion = Some(recursion_options()[self.cursors[self.tab]]);
            }
            Tab::Trust => {
                self.staged_trusted_only = Some(self.cursors[self.tab] == 1);
            }
            Tab::Sandbox => {
                let cursor = self.cursors[self.tab];
                let modes = sandbox_mode_options();
                if let Some(mode) = modes.get(cursor).copied() {
                    if mode.is_container() && !self.current.container_availability.available {
                        return;
                    }
                    self.staged_sandbox_mode = Some(mode);
                } else {
                    let active_mode = self
                        .staged_sandbox_mode
                        .unwrap_or(self.current.sandbox_mode);
                    if active_mode.is_container() {
                        self.staged_container_network_enabled =
                            Some(!self.active_container_network_enabled());
                    }
                }
            }
            Tab::Permissions => {
                self.staged_approval_mode = Some(approval_options()[self.cursors[self.tab]]);
            }
            Tab::Model => {
                if !self.models.is_empty() {
                    self.staged_model = Some(self.cursors[self.tab].min(self.models.len() - 1));
                }
            }
        }
    }

    fn active_container_network_enabled(&self) -> bool {
        self.staged_container_network_enabled
            .unwrap_or(self.current.container_network_enabled)
    }

    fn commit(&self) -> QuickCommit {
        let mut commit = QuickCommit::default();
        if let Some(mode) = self.staged_llm_mode
            && mode != self.current.llm_mode
        {
            commit.llm_mode = Some(mode);
        }
        if let Some(choice) = self.staged_recursion
            && choice != self.current_recursion()
        {
            commit.recursion = Some(match choice {
                RecursionChoice::Off => (false, 0),
                RecursionChoice::Depth(depth) => (true, depth),
            });
        }
        if let Some(enabled) = self.staged_trusted_only
            && enabled != self.current.trusted_only
        {
            commit.trusted_only = Some(enabled);
        }
        if let Some(mode) = self.staged_sandbox_mode
            && mode != self.current.sandbox_mode
        {
            commit.sandbox_mode = Some(mode);
        }
        if let Some(enabled) = self.staged_container_network_enabled
            && enabled != self.current.container_network_enabled
        {
            commit.container_network_enabled = Some(enabled);
        }
        if let Some(mode) = self.staged_approval_mode
            && mode != self.current.approval_mode
        {
            commit.approval_mode = Some(mode);
        }
        if let Some(index) = self.staged_model
            && let Some(choice) = self.models.get(index)
        {
            let selected = (choice.provider_id.clone(), choice.model_id.clone());
            if self.current.active_model.as_ref() != Some(&selected) {
                commit.active_model = Some(selected);
            }
        }
        commit
    }

    fn tabs_line(&self) -> Line<'static> {
        let mut spans = Vec::new();
        for (i, tab) in TABS.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            let style = if i == self.tab {
                Style::default()
                    .fg(Color::Indexed(crate::tui::theme::ACCENT_BLUE_INDEX))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Indexed(crate::tui::theme::MUTED_COLOR_INDEX))
            };
            spans.push(Span::styled(tab.label(), style));
        }
        Line::from(spans)
    }

    fn option_lines(&self) -> Vec<Line<'static>> {
        match TABS[self.tab] {
            Tab::Mode => mode_options()
                .iter()
                .enumerate()
                .map(|(i, mode)| {
                    self.option_line(
                        i,
                        mode.as_str(),
                        mode_description(*mode),
                        self.current.llm_mode == *mode,
                        self.staged_llm_mode == Some(*mode),
                        false,
                    )
                })
                .collect(),
            Tab::Recursion => recursion_options()
                .iter()
                .enumerate()
                .map(|(i, choice)| {
                    self.option_line(
                        i,
                        recursion_label(*choice),
                        recursion_description(*choice),
                        self.current_recursion() == *choice,
                        self.active_staged_recursion() == *choice
                            && self.staged_recursion.is_some(),
                        false,
                    )
                })
                .collect(),
            Tab::Trust => [false, true]
                .iter()
                .enumerate()
                .map(|(i, enabled)| {
                    self.option_line(
                        i,
                        if *enabled {
                            "trusted only"
                        } else {
                            "allow untrusted"
                        },
                        if *enabled {
                            "require trusted models for every inference"
                        } else {
                            "allow configured untrusted models"
                        },
                        self.current.trusted_only == *enabled,
                        self.staged_trusted_only == Some(*enabled),
                        false,
                    )
                })
                .collect(),
            Tab::Sandbox => {
                let mut lines: Vec<Line<'static>> = sandbox_mode_options()
                    .iter()
                    .enumerate()
                    .map(|(i, mode)| {
                        let disabled =
                            mode.is_container() && !self.current.container_availability.available;
                        self.option_line(
                            i,
                            sandbox_mode_label(*mode),
                            &sandbox_mode_description(*mode, &self.current.container_availability),
                            self.current.sandbox_mode == *mode,
                            self.staged_sandbox_mode == Some(*mode),
                            disabled,
                        )
                    })
                    .collect();
                let active_mode = self
                    .staged_sandbox_mode
                    .unwrap_or(self.current.sandbox_mode);
                lines.push(self.option_line(
                    sandbox_mode_options().len(),
                    if self.active_container_network_enabled() {
                        "network on"
                    } else {
                        "network off"
                    },
                    "outbound network for container sandboxes",
                    self.current.container_network_enabled,
                    self.staged_container_network_enabled.is_some(),
                    !active_mode.is_container(),
                ));
                lines
            }
            Tab::Permissions => approval_options()
                .iter()
                .enumerate()
                .map(|(i, mode)| {
                    self.option_line(
                        i,
                        mode.as_str(),
                        approval_description(*mode),
                        self.current.approval_mode == *mode,
                        self.staged_approval_mode == Some(*mode),
                        false,
                    )
                })
                .collect(),
            Tab::Model => {
                if self.models.is_empty() {
                    vec![self.option_line(
                        0,
                        "no favorite models - use /model or /settings to mark favorites",
                        "",
                        false,
                        false,
                        true,
                    )]
                } else {
                    self.models
                        .iter()
                        .enumerate()
                        .map(|(i, choice)| {
                            let current = self.current.active_model.as_ref().is_some_and(
                                |(provider, model)| {
                                    provider == &choice.provider_id && model == &choice.model_id
                                },
                            );
                            let staged = self.staged_model == Some(i);
                            self.option_line(
                                i,
                                &choice.label,
                                &format!(
                                    "{}  {}",
                                    if choice.trust.is_trusted() {
                                        "trusted"
                                    } else {
                                        "untrusted"
                                    },
                                    choice.mode.as_str()
                                ),
                                current,
                                staged,
                                false,
                            )
                        })
                        .collect()
                }
            }
        }
    }

    fn option_line(
        &self,
        index: usize,
        label: &str,
        description: &str,
        current: bool,
        staged: bool,
        disabled: bool,
    ) -> Line<'static> {
        let selected = self.cursors[self.tab] == index;
        let marker = if selected { ">" } else { " " };
        let mut spans = vec![
            Span::styled(
                format!("{marker} "),
                if selected {
                    Style::default()
                        .fg(Color::Indexed(crate::tui::theme::ACCENT_BLUE_INDEX))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
            Span::styled(
                label.to_string(),
                if disabled {
                    Style::default().fg(Color::Indexed(crate::tui::theme::MUTED_COLOR_INDEX))
                } else if selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
        ];
        if !description.is_empty() {
            spans.push(Span::styled(
                format!("  {description}"),
                Style::default().fg(Color::Indexed(crate::tui::theme::MUTED_COLOR_INDEX)),
            ));
        }
        if current {
            spans.push(Span::styled("  current", Style::default().fg(Color::Green)));
        }
        if staged {
            spans.push(Span::styled(
                "  staged",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        Line::from(spans)
    }
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Mode => "Mode",
            Tab::Recursion => "Recursion",
            Tab::Trust => "Trust",
            Tab::Sandbox => "Sandbox",
            Tab::Permissions => "Permissions",
            Tab::Model => "Model",
        }
    }
}

fn mode_options() -> &'static [LlmMode] {
    &[LlmMode::Frontier, LlmMode::Normal, LlmMode::Defensive]
}

fn approval_options() -> &'static [ApprovalMode] {
    &[ApprovalMode::Manual, ApprovalMode::Auto, ApprovalMode::Yolo]
}

fn sandbox_mode_options() -> &'static [SandboxMode] {
    &[
        SandboxMode::Off,
        SandboxMode::Sandbox,
        SandboxMode::Container,
        SandboxMode::ContainerReadonly,
    ]
}

fn sandbox_mode_label(mode: SandboxMode) -> &'static str {
    match mode {
        SandboxMode::Off => "off",
        SandboxMode::Sandbox => "on",
        SandboxMode::Container => "container",
        SandboxMode::ContainerReadonly => "container readonly",
    }
}

fn sandbox_mode_description(
    mode: SandboxMode,
    availability: &cockpit_core::container::ContainerAvailability,
) -> String {
    match mode {
        SandboxMode::Off => "shell sandboxing disabled for this session".to_string(),
        SandboxMode::Sandbox => "filesystem sandboxing on host".to_string(),
        SandboxMode::Container | SandboxMode::ContainerReadonly if !availability.available => {
            format!("unavailable: {}", container_unavailable_label(availability))
        }
        SandboxMode::Container => "run bash in a writable project container".to_string(),
        SandboxMode::ContainerReadonly => "run bash in a read-only project container".to_string(),
    }
}

fn container_unavailable_label(
    availability: &cockpit_core::container::ContainerAvailability,
) -> &'static str {
    match availability.reason {
        Some(cockpit_core::container::ContainerUnavailableReason::HarnessInContainer) => {
            "Cockpit is running inside a container"
        }
        _ => "No docker/podman runtime found",
    }
}

fn recursion_options() -> &'static [RecursionChoice] {
    &[
        RecursionChoice::Off,
        RecursionChoice::Depth(1),
        RecursionChoice::Depth(2),
        RecursionChoice::Depth(3),
        RecursionChoice::Depth(4),
        RecursionChoice::Depth(5),
        RecursionChoice::Depth(6),
    ]
}

fn recursion_label(choice: RecursionChoice) -> &'static str {
    match choice {
        RecursionChoice::Off => "off",
        RecursionChoice::Depth(1) => "1",
        RecursionChoice::Depth(2) => "2",
        RecursionChoice::Depth(3) => "3",
        RecursionChoice::Depth(4) => "4",
        RecursionChoice::Depth(5) => "5",
        RecursionChoice::Depth(6) => "6",
        RecursionChoice::Depth(_) => "?",
    }
}

fn recursion_description(choice: RecursionChoice) -> &'static str {
    match choice {
        RecursionChoice::Off => "disable recursive subagent delegation",
        RecursionChoice::Depth(_) => "default remaining child-edge budget",
    }
}

fn mode_description(mode: LlmMode) -> &'static str {
    match mode {
        LlmMode::Frontier => "top-tier steering",
        LlmMode::Normal => "standard strong-model steering",
        LlmMode::Defensive => "explicit defensive steering",
    }
}

fn approval_description(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::Manual => "you approve anything that leaves the sandbox",
        ApprovalMode::Auto => "utility model can approve anything that leaves the sandbox",
        ApprovalMode::Yolo => "runs without approval prompts",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> QuickCurrent {
        QuickCurrent {
            llm_mode: LlmMode::Defensive,
            recursion_enabled: true,
            recursion_depth: 2,
            trusted_only: false,
            sandbox_mode: SandboxMode::Sandbox,
            container_network_enabled: false,
            container_availability: cockpit_core::container::ContainerAvailability {
                runtime: Some(cockpit_core::container::ContainerRuntimeKind::Docker),
                harness_in_container: false,
                available: true,
                reason: None,
            },
            approval_mode: ApprovalMode::Manual,
            active_model: Some(("p".to_string(), "a".to_string())),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn shift_tab() -> KeyEvent {
        KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)
    }

    fn model(label: &str) -> QuickModelChoice {
        let (provider, model) = label.split_once('/').unwrap();
        QuickModelChoice {
            provider_id: provider.to_string(),
            model_id: model.to_string(),
            label: label.to_string(),
            trust: ModelTrust::Trusted,
            mode: LlmMode::Normal,
        }
    }

    #[test]
    fn approval_mode_copy_describes_sandbox_as_the_gate() {
        let manual = approval_description(ApprovalMode::Manual);
        let auto = approval_description(ApprovalMode::Auto);
        let yolo = approval_description(ApprovalMode::Yolo);

        assert_eq!(manual, "you approve anything that leaves the sandbox");
        assert!(auto.contains("utility model"));
        assert!(auto.contains("leaves the sandbox"));
        let joined = [manual, auto, yolo].join("\n");
        assert!(!joined.contains("approve every command"));
        assert!(!joined.contains("gated commands"));
    }

    #[test]
    fn tab_forward_and_back() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        assert_eq!(dialog.active_tab(), Tab::Mode);
        dialog.handle_key(key(KeyCode::Tab));
        assert_eq!(dialog.active_tab(), Tab::Recursion);
        dialog.handle_key(shift_tab());
        assert_eq!(dialog.active_tab(), Tab::Mode);
    }

    #[test]
    fn horizontal_keys_switch_tabs_with_wrap_and_preserve_cursors() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Char('h')));
        assert_eq!(dialog.active_tab(), Tab::Model);
        dialog.handle_key(key(KeyCode::Char('l')));
        assert_eq!(dialog.active_tab(), Tab::Mode);
        dialog.handle_key(key(KeyCode::Right));
        assert_eq!(dialog.active_tab(), Tab::Recursion);
        dialog.handle_key(key(KeyCode::Down));
        let recursion_cursor = dialog.active_cursor();
        dialog.handle_key(key(KeyCode::Right));
        assert_eq!(dialog.active_tab(), Tab::Trust);
        let trust_cursor = dialog.active_cursor();
        dialog.handle_key(key(KeyCode::Right));
        assert_ne!(dialog.active_cursor(), trust_cursor);
        dialog.handle_key(key(KeyCode::Left));
        assert_eq!(dialog.active_tab(), Tab::Trust);
        assert_eq!(dialog.active_cursor(), trust_cursor);
        dialog.handle_key(key(KeyCode::Left));
        assert_eq!(dialog.active_tab(), Tab::Recursion);
        assert_eq!(dialog.active_cursor(), recursion_cursor);
    }

    #[test]
    fn keybindings_advertise_horizontal_tab_switching() {
        let group = QuickDialog::keybindings();
        assert!(
            group
                .bindings
                .iter()
                .any(|binding| binding.key == "Tab/→/l")
        );
        assert!(
            group
                .bindings
                .iter()
                .any(|binding| binding.key == "Shift+Tab/←/h")
        );
    }

    #[test]
    fn row_navigation_and_space_staging() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Up));
        assert_eq!(dialog.active_cursor(), 1);
        dialog.handle_key(key(KeyCode::Char(' ')));
        assert!(dialog.has_staged_changes());
        assert_eq!(
            dialog.commit(),
            QuickCommit {
                llm_mode: Some(LlmMode::Normal),
                ..QuickCommit::default()
            }
        );
    }

    #[test]
    fn enter_stages_commits_and_escape_discards() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Up));
        let outcome = dialog.handle_key(key(KeyCode::Enter));
        assert_eq!(
            outcome,
            Some(QuickOutcome::Commit(QuickCommit {
                llm_mode: Some(LlmMode::Normal),
                ..QuickCommit::default()
            }))
        );

        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Up));
        dialog.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(
            dialog.handle_key(key(KeyCode::Esc)),
            Some(QuickOutcome::Close)
        );
    }

    #[test]
    fn committed_staged_and_highlighted_are_visible() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Up));
        dialog.handle_key(key(KeyCode::Char(' ')));
        let snapshot = dialog.snapshot();
        assert!(snapshot.contains("> normal"));
        assert!(snapshot.contains("defensive"));
        assert!(snapshot.contains("current"));
        assert!(snapshot.contains("staged"));
    }

    #[test]
    fn recursion_options_have_no_zero() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        dialog.handle_key(key(KeyCode::Tab));
        let snapshot = dialog.snapshot();
        assert!(snapshot.contains("off"));
        for depth in 1..=6 {
            assert!(snapshot.contains(&depth.to_string()));
        }
        assert!(!snapshot.contains("> 0"));
    }

    #[test]
    fn sandbox_tab_stages_container_mode() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        for _ in 0..3 {
            dialog.handle_key(key(KeyCode::Tab));
        }
        assert_eq!(dialog.active_tab(), Tab::Sandbox);
        assert_eq!(dialog.active_cursor(), 1);

        dialog.handle_key(key(KeyCode::Down));
        dialog.handle_key(key(KeyCode::Char(' ')));

        assert_eq!(
            dialog.commit(),
            QuickCommit {
                sandbox_mode: Some(SandboxMode::Container),
                ..QuickCommit::default()
            }
        );
    }

    #[test]
    fn sandbox_tab_network_toggle_requires_staged_container_mode() {
        let mut dialog = QuickDialog::open(current(), vec![model("p/a")]);
        for _ in 0..3 {
            dialog.handle_key(key(KeyCode::Tab));
        }

        for _ in 0..3 {
            dialog.handle_key(key(KeyCode::Down));
        }
        dialog.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(dialog.commit(), QuickCommit::default());

        dialog.handle_key(key(KeyCode::Up));
        dialog.handle_key(key(KeyCode::Up));
        dialog.handle_key(key(KeyCode::Char(' ')));
        dialog.handle_key(key(KeyCode::Down));
        dialog.handle_key(key(KeyCode::Down));
        dialog.handle_key(key(KeyCode::Char(' ')));

        assert_eq!(
            dialog.commit(),
            QuickCommit {
                sandbox_mode: Some(SandboxMode::Container),
                container_network_enabled: Some(true),
                ..QuickCommit::default()
            }
        );
    }

    #[test]
    fn sandbox_tab_does_not_stage_unavailable_container_mode() {
        let mut current = current();
        current.container_availability = cockpit_core::container::ContainerAvailability {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(cockpit_core::container::ContainerUnavailableReason::NoRuntime),
        };
        let mut dialog = QuickDialog::open(current, vec![model("p/a")]);
        for _ in 0..3 {
            dialog.handle_key(key(KeyCode::Tab));
        }
        dialog.handle_key(key(KeyCode::Down));
        dialog.handle_key(key(KeyCode::Char(' ')));

        assert_eq!(dialog.commit(), QuickCommit::default());
        assert!(
            dialog
                .snapshot()
                .contains("unavailable: No docker/podman runtime found")
        );
    }

    #[test]
    fn disabled_empty_favorite_model_tab() {
        let mut dialog = QuickDialog::open(current(), Vec::new());
        for _ in 0..5 {
            dialog.handle_key(key(KeyCode::Tab));
        }
        assert_eq!(dialog.active_tab(), Tab::Model);
        assert!(dialog.snapshot().contains("no favorite models"));
        dialog.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(dialog.commit(), QuickCommit::default());
    }
}
