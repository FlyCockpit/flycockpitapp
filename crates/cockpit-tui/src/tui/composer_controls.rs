//! Composer bottom-border control deck.
//!
//! The input box's literal bottom border carries exactly five pills — agent,
//! model, effort/thinking, permissions/approval, sandbox — and a right-side
//! `[Send]` (idle) / `[Queue]` (working) action. Compact, export, and tools
//! never appear here: those stay at their transcript/header/slash surfaces.
//!
//! Layout is planned before paint so pill order, hit regions, and label
//! compression have one source of truth. The five required pills are never
//! omitted at the probe widths; labels compress (full → compact → glyph)
//! before Send/Queue is dropped, and only a degenerate width may elide from
//! the right as a last resort. Every label is built from daemon/launch
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

    /// Stable one-character label used when compact names still overflow.
    pub(crate) fn glyph_label(self) -> &'static str {
        match self {
            Self::Agent => "A",
            Self::Model => "M",
            Self::Effort => "E",
            Self::Approval => "P",
            Self::Sandbox => "S",
        }
    }
}

/// Which label set the planner selected for this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ComposerLabelTier {
    #[default]
    Full,
    Compact,
    Glyph,
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
    /// cluster). Empty at the probe widths; only a degenerate interior
    /// may omit a required pill.
    pub omitted: Vec<ComposerControlKind>,
    /// Label compression selected for this frame.
    pub tier: ComposerLabelTier,
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

fn cluster_width_with_gap(labels: &[&str], gap: u16) -> u16 {
    if labels.is_empty() {
        return 0;
    }
    let sum: u16 = labels.iter().map(|l| pill_width(l)).sum();
    sum.saturating_add((labels.len().saturating_sub(1) as u16).saturating_mul(gap))
}

fn glyph_labels() -> [&'static str; 5] {
    [
        ComposerControlKind::Agent.glyph_label(),
        ComposerControlKind::Model.glyph_label(),
        ComposerControlKind::Effort.glyph_label(),
        ComposerControlKind::Approval.glyph_label(),
        ComposerControlKind::Sandbox.glyph_label(),
    ]
}

pub fn send_label(working: bool) -> &'static str {
    if working { "Queue" } else { "Send" }
}

/// Plan the bottom-border pills and Send/Queue action for `state` inside
/// the input box `area`. Pure: same state + area ⇒ same layout.
///
/// Pills occupy the left of the bottom border in ALL order; Send/Queue is
/// right-aligned. When the full labels overflow the remaining budget,
/// compact then glyph labels are used. Send/Queue is dropped only after
/// glyph labels still cannot keep all five pills. A degenerate interior
/// may elide from the right as a last resort. Compact/export/tools are
/// never planned here.
pub(crate) fn plan_composer_controls(
    state: &ComposerControlState,
    area: Rect,
) -> ComposerControlLayout {
    let mut layout = ComposerControlLayout {
        area,
        ..ComposerControlLayout::default()
    };
    if area.width < 2 || area.height == 0 {
        layout.omitted.extend(ComposerControlKind::ALL);
        return layout;
    }
    let y = area.y.saturating_add(area.height.saturating_sub(1));
    let send = send_label(state.working);
    let send_w = pill_width(send);
    let send_fits_space = area.width >= send_w.saturating_add(2);
    let full = state.full_labels();
    let compact = state.compact_labels();
    let glyph = glyph_labels();
    for (labels, tier, include_send, gap) in [
        (full.as_slice(), ComposerLabelTier::Full, true, CLUSTER_GAP),
        (
            compact.as_slice(),
            ComposerLabelTier::Compact,
            true,
            CLUSTER_GAP,
        ),
        (
            glyph.as_slice(),
            ComposerLabelTier::Glyph,
            true,
            CLUSTER_GAP,
        ),
        (
            glyph.as_slice(),
            ComposerLabelTier::Glyph,
            false,
            CLUSTER_GAP,
        ),
        (glyph.as_slice(), ComposerLabelTier::Glyph, false, 0),
    ] {
        if include_send && !send_fits_space {
            continue;
        }
        let send_reserve = if include_send {
            send_w.saturating_add(1)
        } else {
            0
        };
        let budget = area.width.saturating_sub(2).saturating_sub(send_reserve);
        if cluster_width_with_gap(labels, gap) > budget {
            continue;
        }
        return place_pills(
            layout,
            labels,
            tier,
            include_send.then_some((send_w, y)),
            gap,
            y,
        );
    }

    // Degenerate last resort: glyph labels, no send, elide from the right.
    let budget = area.width.saturating_sub(2);
    let mut keep = glyph.len();
    while keep > 0 && cluster_width_with_gap(&glyph[..keep], 0) > budget {
        keep -= 1;
    }
    place_pills_truncated(layout, &glyph, keep, y)
}

fn place_pills(
    mut layout: ComposerControlLayout,
    labels: &[&str],
    tier: ComposerLabelTier,
    send: Option<(u16, u16)>,
    gap: u16,
    y: u16,
) -> ComposerControlLayout {
    let area = layout.area;
    if let Some((send_w, send_y)) = send {
        let send_x = area
            .x
            .saturating_add(area.width.saturating_sub(1))
            .saturating_sub(send_w);
        layout.send_button = Some(Rect {
            x: send_x,
            y: send_y,
            width: send_w,
            height: 1,
        });
    }
    layout.tier = tier;
    let end = layout
        .send_button
        .map(|rect| rect.x.saturating_sub(gap.max(1)))
        .unwrap_or_else(|| area.x.saturating_add(area.width.saturating_sub(1)));
    let mut x = area.x.saturating_add(1);
    for (i, kind) in ComposerControlKind::ALL.iter().copied().enumerate() {
        let Some(label) = labels.get(i) else {
            layout.omitted.push(kind);
            continue;
        };
        let w = pill_width(label);
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
        x = x.saturating_add(w).saturating_add(gap);
    }
    layout
}

fn place_pills_truncated(
    mut layout: ComposerControlLayout,
    labels: &[&str],
    keep: usize,
    y: u16,
) -> ComposerControlLayout {
    layout.tier = ComposerLabelTier::Glyph;
    let mut x = layout.area.x.saturating_add(1);
    let end = layout
        .area
        .x
        .saturating_add(layout.area.width.saturating_sub(1));
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
        x = x.saturating_add(w);
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
    fn narrow_width_keeps_all_five_pills_in_order() {
        let layout = plan_composer_controls(&state(), Rect::new(0, 0, 40, 3));
        let kinds = layout.active_kinds();
        assert_eq!(kinds, ComposerControlKind::ALL);
        assert!(layout.omitted.is_empty());
        assert_eq!(layout.tier, ComposerLabelTier::Glyph);
        assert!(layout.send_button.is_some());
        let mut x = 0;
        for (kind, rect) in &layout.pill_buttons {
            assert_eq!(rect.y, 2);
            assert!(rect.x >= x, "{kind:?} overlaps previous");
            x = rect.x + rect.width;
        }
        let send = layout.send_button.expect("send fits next to glyphs");
        assert!(send.x > layout.pill_buttons.last().unwrap().1.x);
    }

    #[test]
    fn probe_widths_keep_all_five_pills_in_order() {
        for width in COMPOSER_CONTROL_PROBE_WIDTHS {
            let layout = plan_composer_controls(&state(), Rect::new(0, 0, width, 3));
            assert_eq!(
                layout.active_kinds(),
                ComposerControlKind::ALL,
                "width {width}"
            );
            assert!(layout.omitted.is_empty(), "width {width}");
            assert!(layout.send_button.is_some(), "width {width}");
        }
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
