use std::collections::BTreeMap;

use cockpit_core::agents::{AgentDef, ToolSurfaceSelection, ToolTier};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;

#[derive(Default, Clone)]
pub(crate) struct ToolSurfacePicker {
    cursor: usize,
}

impl ToolSurfacePicker {
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn move_prev(&mut self) {
        let len = cockpit_core::agents::tool_surface_catalog().len();
        if len > 0 {
            self.cursor = crate::tui::nav::wrap_prev(self.cursor, len);
        }
    }

    pub(crate) fn move_next(&mut self) {
        let len = cockpit_core::agents::tool_surface_catalog().len();
        if len > 0 {
            self.cursor = crate::tui::nav::wrap_next(self.cursor, len);
        }
    }

    pub(crate) fn selected_tool(&self) -> Option<&'static str> {
        cockpit_core::agents::tool_surface_catalog()
            .get(self.cursor)
            .map(|item| item.name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolSurfaceDraft {
    selection: ToolSurfaceSelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolSurfaceEditOutcome {
    NoSelection,
    Granted(String),
    Ungranted(String),
    TierChanged { tool: String, tier: ToolTier },
    BlockedSafetyUngrant(String),
}

impl ToolSurfaceDraft {
    pub(crate) fn from_def(def: &AgentDef) -> Self {
        Self {
            selection: ToolSurfaceSelection {
                tools: def.tools.clone().unwrap_or_default(),
                tool_tiers: def.tool_tiers.clone(),
            },
        }
    }

    pub(crate) fn selection(&self) -> &ToolSurfaceSelection {
        &self.selection
    }

    #[cfg(test)]
    pub(crate) fn selection_mut(&mut self) -> &mut ToolSurfaceSelection {
        &mut self.selection
    }

    pub(crate) fn write_to_def(&self, def: &mut AgentDef) {
        def.tools = (!self.selection.tools.is_empty()).then_some(self.selection.tools.clone());
        def.tool_tiers = self.selection.tool_tiers.clone();
    }

    pub(crate) fn granted(&self, tool: &str) -> bool {
        self.selection.tools.iter().any(|item| item == tool)
    }

    pub(crate) fn tier(&self, tool: &str) -> ToolTier {
        self.selection
            .tool_tiers
            .get(tool)
            .copied()
            .unwrap_or(ToolTier::Enabled)
    }

    pub(crate) fn set_granted(&mut self, tool: &str, granted: bool) -> ToolSurfaceEditOutcome {
        if granted {
            if !self.granted(tool) {
                self.selection.tools.push(tool.to_string());
                self.selection.tools.sort();
            }
            ToolSurfaceEditOutcome::Granted(tool.to_string())
        } else {
            self.selection.tools.retain(|existing| existing != tool);
            self.selection.tool_tiers.remove(tool);
            ToolSurfaceEditOutcome::Ungranted(tool.to_string())
        }
    }

    pub(crate) fn toggle_selected_tool(
        &mut self,
        picker: &ToolSurfacePicker,
        block_safety_ungrant: bool,
    ) -> ToolSurfaceEditOutcome {
        let Some(tool) = picker.selected_tool() else {
            return ToolSurfaceEditOutcome::NoSelection;
        };
        if self.granted(tool) && block_safety_ungrant && is_safety_tool(tool) {
            return ToolSurfaceEditOutcome::BlockedSafetyUngrant(tool.to_string());
        }
        self.set_granted(tool, !self.granted(tool))
    }

    pub(crate) fn cycle_selected_tier(
        &mut self,
        picker: &ToolSurfacePicker,
    ) -> ToolSurfaceEditOutcome {
        let Some(tool) = picker.selected_tool() else {
            return ToolSurfaceEditOutcome::NoSelection;
        };
        if !self.granted(tool) {
            self.set_granted(tool, true);
        }
        let tiers = cockpit_core::agents::legal_tool_tiers(tool);
        let current = self.tier(tool);
        let index = tiers.iter().position(|tier| *tier == current).unwrap_or(0);
        let next = tiers[(index + 1) % tiers.len()];
        if next == ToolTier::Enabled {
            self.selection.tool_tiers.remove(tool);
        } else {
            self.selection.tool_tiers.insert(tool.to_string(), next);
        }
        ToolSurfaceEditOutcome::TierChanged {
            tool: tool.to_string(),
            tier: next,
        }
    }
}

pub(crate) fn is_safety_tool(tool: &str) -> bool {
    cockpit_core::agents::is_safety_tool(tool)
}

pub(crate) struct ToolSurfaceRender<'a> {
    pub(crate) title: &'a str,
    pub(crate) subtitle: &'a str,
    pub(crate) status: Option<&'a str>,
    pub(crate) row_errors: &'a BTreeMap<String, String>,
    pub(crate) block_safety_ungrant: bool,
}

pub(crate) type ToolSurfaceLines = (Vec<Line<'static>>, Option<usize>, Vec<(usize, usize, bool)>);

pub(crate) fn tool_surface_lines(
    picker: &ToolSurfacePicker,
    draft: &ToolSurfaceDraft,
    opts: ToolSurfaceRender<'_>,
) -> ToolSurfaceLines {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let green = Style::default().fg(Color::Green);
    let cyan = Style::default().fg(Color::Cyan);
    let disabled = muted.add_modifier(Modifier::DIM);
    let mut lines: Vec<Line<'static>> = vec![
        Line::from(vec![
            Span::styled(
                opts.title.to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  {}", opts.subtitle), muted),
        ]),
        Line::default(),
    ];
    let mut semantic_rows = Vec::new();
    let mut last_family = "";
    for (index, item) in cockpit_core::agents::tool_surface_catalog()
        .into_iter()
        .enumerate()
    {
        if item.family != last_family {
            if !last_family.is_empty() {
                lines.push(Line::default());
            }
            lines.push(Line::from(Span::styled(item.family.to_string(), muted)));
            last_family = item.family;
        }
        let on_cursor = index == picker.cursor();
        let marker = if on_cursor { "▸ " } else { "  " };
        let granted = draft.granted(item.name);
        let check = if granted { "[x]" } else { "[ ]" };
        let tier = if granted {
            draft.tier(item.name).label()
        } else {
            "-"
        };
        let safety_blocked = opts.block_safety_ungrant && granted && is_safety_tool(item.name);
        let name_style = if safety_blocked {
            disabled
        } else if on_cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let state_style = if safety_blocked {
            disabled
        } else if granted {
            green
        } else {
            muted
        };
        let mut spans = vec![
            Span::raw(marker),
            Span::styled(check.to_string(), state_style),
            Span::raw(" "),
            Span::styled(item.name.to_string(), name_style),
            Span::raw("  "),
            Span::styled(format!("tier: {tier}"), cyan),
        ];
        if item.tiers.len() == 1 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled("locked enabled", muted));
        } else if item.tiers.len() == 2 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled("no discoverable", muted));
        }
        if let Some(error) = opts.row_errors.get(item.name) {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(error.clone(), red));
        }
        semantic_rows.push((lines.len(), index, !safety_blocked));
        lines.push(Line::from(spans));
    }
    if let Some(status) = opts.status {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(status.to_string(), yellow)));
    }
    let selected_line = lines.iter().position(|line| {
        line.spans
            .first()
            .is_some_and(|span| span.content.starts_with('▸'))
    });
    (lines, selected_line, semantic_rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_picker_still_permits_safety_set_ungrant() {
        let mut picker = ToolSurfacePicker::default();
        let question = cockpit_core::agents::tool_surface_catalog()
            .iter()
            .position(|item| item.name == "question")
            .unwrap();
        picker.cursor = question;
        let mut draft = ToolSurfaceDraft {
            selection: ToolSurfaceSelection {
                tools: vec!["question".to_string()],
                tool_tiers: BTreeMap::new(),
            },
        };

        let outcome = draft.toggle_selected_tool(&picker, false);

        assert_eq!(
            outcome,
            ToolSurfaceEditOutcome::Ungranted("question".into())
        );
        assert!(!draft.granted("question"));
    }
}
