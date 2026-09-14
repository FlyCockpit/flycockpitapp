//! Composer bottom-border control deck.
//!
//! The input box's literal bottom border carries exactly five pills — agent,
//! model, effort/thinking, permissions/approval, sandbox — and a right-side
//! `[Send]` (idle) / `[Queue]` (working) action. Compact, export, and tools
//! never appear here: those stay at their transcript/header/slash surfaces.
//!
//! Layout is planned before paint so pill order, hit regions, and narrow-width
//! elision have one source of truth. Every label is built from daemon/launch
//! state; the pills are presentation, not local writers.

use ratatui::layout::Rect;

use crate::tui::button::{bracketed_label, display_width};

/// Chat widths at which placement/order fixtures run. Planning is
/// width-driven and continuous; these anchor the tests.
pub const COMPOSER_CONTROL_PROBE_WIDTHS: [u16; 3] = [120, 80, 40];

/// One column of separation between pills, and between the last pill and
/// the send action.
const CLUSTER_GAP: u16 = 1;

/// Bottom-border pill kinds in left-to-right order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ComposerControlKind {
    Agent,
    Model,
    Effort,
    Approval,
    Sandbox,
}

impl ComposerControlKind {
    pub(crate) const ALL: [Self; 5] = [
        Self::Agent,
        Self::Model,
        Self::Effort,
        Self::Approval,
        Self::Sandbox,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Model => "model",
            Self::Effort => "effort",
            Self::Approval => "approval",
            Self::Sandbox => "sandbox",
        }
    }
}

/// One frame's composer-control input snapshot. Built from App state; pure data.
#[derive(Debug, Clone, Default)]
pub(crate) struct ComposerControlState {
    pub agent_label: String,
    pub model_label: String,
    pub effort_label: String,
    pub approval_label: String,
    pub sandbox_label: String,
    /// Compact (narrow) labels, in ALL order.
    pub compact_agent: String,
    pub compact_model: String,
    pub compact_effort: String,
    pub compact_approval: String,
    pub compact_sandbox: String,
    /// `[Send]` while idle, `[Queue]` while a run is in flight.
    pub working: bool,
}

impl ComposerControlState {
    fn full_labels(&self) -> [&str; 5] {
        [
            self.agent_label.as_str(),
            self.model_label.as_str(),
            self.effort_label.as_str(),
            self.approval_label.as_str(),
            self.sandbox_label.as_str(),
        ]
    }

    fn compact_labels(&self) -> [&str; 5] {
        [
            self.compact_agent.as_str(),
            self.compact_model.as_str(),
            self.compact_effort.as_str(),
            self.compact_approval.as_str(),
            self.compact_sandbox.as_str(),
        ]
    }
}

/// Planned bottom-border layout: everything paint and hit-testing need.
#[derive(Debug, Clone, Default)]
pub(crate) struct ComposerControlLayout {
    /// The input box rect whose bottom row holds the pills.
    pub area: Rect,
    /// Visible pills in left-to-right draw order, with their rects on the
    /// bottom border row.
    pub pill_buttons: Vec<(ComposerControlKind, Rect)>,
    /// Right-side Send/Queue action, when it fits.
    pub send_button: Option<Rect>,
    /// Kinds that did not fit this frame (elided from the right of the
    /// cluster). Never includes a pill that was drawn.
    pub omitted: Vec<ComposerControlKind>,
    /// Whether compact labels were selected.
    pub compact: bool,
}

impl ComposerControlLayout {
    pub(crate) fn active_kinds(&self) -> Vec<ComposerControlKind> {
        self.pill_buttons.iter().map(|(k, _)| *k).collect()
    }

    pub(crate) fn pill_rect(&self, kind: ComposerControlKind) -> Option<Rect> {
        self.pill_buttons
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, rect)| *rect)
    }

    pub(crate) fn bottom_row(&self) -> u16 {
        self.area
            .y
            .saturating_add(self.area.height.saturating_sub(1))
    }
}

fn pill_width(label: &str) -> u16 {
    display_width(&bracketed_label(label))
}

fn cluster_width(labels: &[&str]) -> u16 {
    if labels.is_empty() {
        return 0;
    }
    let sum: u16 = labels.iter().map(|l| pill_width(l)).sum();
    sum.saturating_add((labels.len().saturating_sub(1) as u16).saturating_mul(CLUSTER_GAP))
}

pub fn send_label(working: bool) -> &'static str {
    if working { "Queue" } else { "Send" }
}

/// Plan the bottom-border pills and Send/Queue action for `state` inside
/// the input box `area`. Pure: same state + area ⇒ same layout.
///
/// Pills occupy the left of the bottom border in ALL order; Send/Queue is
/// right-aligned. When the full labels overflow the remaining budget,
/// compact labels are used. If those still overflow, pills elide from the
/// right (sandbox first) so the left-to-right order of whatever remains is
/// unchanged. Compact/export/tools are never planned here.
pub(crate) fn plan_composer_controls(
    state: &ComposerControlState,
    area: Rect,
) -> ComposerControlLayout {
    let mut layout = ComposerControlLayout {
        area,
        ..ComposerControlLayout::default()
    };
    if area.width < 2 || area.height == 0 {
        return layout;
    }
    let y = area.y.saturating_add(area.height.saturating_sub(1));
    let send = send_label(state.working);
    let send_w = pill_width(send);
    // Opening corner, send, closing corner, one gap before send.
    let send_fits = area.width >= send_w.saturating_add(2);
    if send_fits {
        let send_x = area
            .x
            .saturating_add(area.width.saturating_sub(1))
            .saturating_sub(send_w);
        layout.send_button = Some(Rect {
            x: send_x,
            y,
            width: send_w,
            height: 1,
        });
    }
    let send_reserve = if send_fits {
        send_w.saturating_add(1)
    } else {
        0
    };
    // Interior after the left corner, before the send gap/action/right corner.
    let budget = area.width.saturating_sub(2).saturating_sub(send_reserve);
    let full = state.full_labels();
    let compact = state.compact_labels();
    let (labels, used_compact) = if cluster_width(&full) <= budget {
        (full, false)
    } else {
        (compact, true)
    };
    layout.compact = used_compact;

    let mut keep = labels.len();
    while keep > 0 && cluster_width(&labels[..keep]) > budget {
        keep -= 1;
    }
    let mut x = area.x.saturating_add(1);
    let end = layout
        .send_button
        .map(|rect| rect.x.saturating_sub(CLUSTER_GAP))
        .unwrap_or_else(|| area.x.saturating_add(area.width.saturating_sub(1)));
    for (i, kind) in ComposerControlKind::ALL.iter().copied().enumerate() {
        if i >= keep {
            layout.omitted.push(kind);
            continue;
        }
        let w = pill_width(labels[i]);
        if x.saturating_add(w) > end {
            layout.omitted.push(kind);
            continue;
        }
        layout.pill_buttons.push((
            kind,
            Rect {
                x,
                y,
                width: w,
                height: 1,
            },
        ));
        x = x.saturating_add(w).saturating_add(CLUSTER_GAP);
    }
    layout
}

/// Current-feature → replacement surface → parity proof. A `proof` must
/// be a declared `#[test]` in `tui/app/composer_controls_tests.rs`.
pub struct ComposerParityRow {
    pub control: &'static str,
    pub surface: &'static str,
    pub proof: &'static str,
}

pub fn capability_parity_table() -> &'static [ComposerParityRow] {
    &[
        ComposerParityRow {
            control: "image paste/attachments",
            surface: "registered composer (unchanged ownership)",
            proof: "composer_registry_stays_private_two_value_owner",
        },
        ComposerParityRow {
            control: "slash commands",
            surface: "existing slash discovery/execution from the composer",
            proof: "slash_commands_remain_reachable_from_composer",
        },
        ComposerParityRow {
            control: "composer modes/settings",
            surface: "existing vim/editor modes and Settings from the composer",
            proof: "composer_modes_remain_reachable",
        },
        ComposerParityRow {
            control: "agent/model/effort",
            surface: "composer bottom-border pills → hierarchical pickers",
            proof: "composer_pills_open_hierarchical_pickers",
        },
        ComposerParityRow {
            control: "approval/sandbox",
            surface: "composer bottom-border pills → gated hierarchical pickers",
            proof: "approval_and_sandbox_pills_are_capability_gated",
        },
        ComposerParityRow {
            control: "tools detail",
            surface: "header tools pill → tools pane SetToolSurfaceOverride",
            proof: "header_tools_pill_reconciles_tool_surface_override",
        },
        ComposerParityRow {
            control: "queue edit/cancel/send",
            surface: "queue box Held/Steer/Send now + existing daemon actions",
            proof: "queue_item_and_box_controls_have_mouse_and_key_parity",
        },
        ComposerParityRow {
            control: "footer agent/model pickers",
            surface: "composer agent/model pills (footer route deleted)",
            proof: "footer_agent_and_model_routes_are_gone",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ComposerControlState {
        ComposerControlState {
            agent_label: "Build".to_string(),
            model_label: "openai/gpt-test".to_string(),
            effort_label: "high".to_string(),
            approval_label: "permissions: manual".to_string(),
            sandbox_label: "sandbox: on".to_string(),
            compact_agent: "Build".to_string(),
            compact_model: "gpt-test".to_string(),
            compact_effort: "high".to_string(),
            compact_approval: "manual".to_string(),
            compact_sandbox: "on".to_string(),
            working: false,
        }
    }

    #[test]
    fn wide_layout_keeps_all_five_pills_then_send_in_order() {
        let area = Rect::new(0, 10, 120, 4);
        let layout = plan_composer_controls(&state(), area);
        let kinds: Vec<_> = layout.active_kinds();
        assert_eq!(kinds, ComposerControlKind::ALL);
        assert!(layout.omitted.is_empty());
        let send = layout.send_button.expect("send fits");
        assert_eq!(send.y, 13);
        assert!(send.x > layout.pill_buttons.last().unwrap().1.x);
        let mut x = 0;
        for (kind, rect) in &layout.pill_buttons {
            assert_eq!(rect.y, 13);
            assert!(rect.x >= x, "{kind:?} overlaps previous");
            x = rect.x + rect.width;
        }
    }

    #[test]
    fn working_uses_queue_label_budget() {
        let mut state = state();
        state.working = true;
        let layout = plan_composer_controls(&state, Rect::new(0, 0, 80, 3));
        let send = layout.send_button.expect("queue fits");
        assert_eq!(send.width, pill_width("Queue"));
    }

    #[test]
    fn narrow_width_elides_from_the_right_preserving_order() {
        let layout = plan_composer_controls(&state(), Rect::new(0, 0, 40, 3));
        let kinds = layout.active_kinds();
        assert!(!kinds.is_empty(), "at least agent survives");
        assert_eq!(kinds.first().copied(), Some(ComposerControlKind::Agent));
        for window in kinds.windows(2) {
            assert!(window[0] < window[1], "elision keeps ALL order");
        }
        for omitted in &layout.omitted {
            assert!(
                kinds.iter().all(|k| k < omitted),
                "omitted {omitted:?} is to the right of visible pills"
            );
        }
        assert!(layout.send_button.is_some());
    }

    #[test]
    fn planner_never_emits_compact_export_or_tools() {
        for width in COMPOSER_CONTROL_PROBE_WIDTHS {
            let layout = plan_composer_controls(&state(), Rect::new(0, 0, width, 3));
            for (kind, _) in &layout.pill_buttons {
                assert!(
                    ComposerControlKind::ALL.contains(kind),
                    "unexpected pill {kind:?}"
                );
            }
        }
    }
}
