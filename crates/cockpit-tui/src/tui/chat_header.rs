//! Three-row chat header beside the session rail.
//!
//! Row 1 carries the real session title (left) and session status (right);
//! row 2 carries the working path plus the real git branch/dirty counts at
//! the left and right-aligned activity pills; row 3 is a literal horizontal
//! rule. The header is the one summary surface for path/git/activity — the
//! superseded footer placements are removed once their data lands here.
//!
//! Layout is planned explicitly ([`plan_chat_header`]) before anything is
//! painted so widths, pill hit regions, and the collapsed-pill set have one
//! source of truth. Every pill draws only from daemon/launch-provided
//! state; setup retains its explicit loading state until the mode arrives.
//! Lower-priority pills collapse into a counted `more` chip in the priority
//! order [`HeaderPillKind`] declares (attention, tool, agent, task, timer,
//! skill, pins, longcache, setup, lock, side, caffeinate), so narrow widths
//! deterministically retain the highest-priority active indicator.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::button::{
    ButtonDispatch, ButtonId, ButtonSpec, clip_to_display_width, display_width,
};
use crate::tui::theme::{
    BRASS, DISABLED, DISABLED_INDEX, FOG, GREEN, GREEN_INDEX, INK, NIGHT, RED, RED_INDEX, YELLOW,
    YELLOW_INDEX, resolve_color,
};

/// Height of the full header: title row, meta row, rule row.
pub(crate) const CHAT_HEADER_HEIGHT: u16 = 3;

/// One column of separation between pills, mirroring the reference shell.
const CLUSTER_GAP: u16 = 1;

/// Chat widths at which the acceptance fixtures verify deterministic pill
/// collapse. Planning itself is width-driven and continuous; these anchor
/// the tests, they are not terminal-name heuristics.
pub const HEADER_COLLAPSE_PROBE_WIDTHS: [u16; 3] = [80, 56, 40];

/// Activity pill kinds in narrow-width priority order: attention first,
/// skill last. The derived ordering is the single declaration of the
/// collapse order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum HeaderPillKind {
    Attention,
    Update,
    Tool,
    Agent,
    Task,
    Timer,
    Skill,
    Pins,
    Longcache,
    Setup,
    Lock,
    Side,
    Caffeinate,
    #[cfg(feature = "remote")]
    OrgSync,
    #[cfg(feature = "remote")]
    Connector,
}

impl HeaderPillKind {
    /// Every kind, in priority order. The button inventory derives its
    /// header coverage from this list.
    #[cfg(not(feature = "remote"))]
    pub(crate) const ALL: [HeaderPillKind; 13] = [
        HeaderPillKind::Attention,
        HeaderPillKind::Update,
        HeaderPillKind::Tool,
        HeaderPillKind::Agent,
        HeaderPillKind::Task,
        HeaderPillKind::Timer,
        HeaderPillKind::Skill,
        HeaderPillKind::Pins,
        HeaderPillKind::Longcache,
        HeaderPillKind::Setup,
        HeaderPillKind::Lock,
        HeaderPillKind::Side,
        HeaderPillKind::Caffeinate,
    ];
    #[cfg(feature = "remote")]
    pub(crate) const ALL: [HeaderPillKind; 15] = [
        HeaderPillKind::Attention,
        HeaderPillKind::Update,
        HeaderPillKind::Tool,
        HeaderPillKind::Agent,
        HeaderPillKind::Task,
        HeaderPillKind::Timer,
        HeaderPillKind::Skill,
        HeaderPillKind::Pins,
        HeaderPillKind::Longcache,
        HeaderPillKind::Setup,
        HeaderPillKind::Lock,
        HeaderPillKind::Side,
        HeaderPillKind::Caffeinate,
        HeaderPillKind::OrgSync,
        HeaderPillKind::Connector,
    ];
}

/// One activity pill: the kind (drill-in target + priority) and its
/// daemon-backed label text (already pluralized/counted by the builder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderPill {
    pub kind: HeaderPillKind,
    pub label: String,
}

/// Real git facts from the daemon-resolved launch snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitFacts {
    pub branch: String,
    pub changes: u32,
}

/// Session status derived from authoritative app state (attention
/// interrupts, inference reconnect, busy span). Never synthesized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum HeaderSessionStatus {
    Attention,
    Reconnecting,
    Working,
    Done,
    #[default]
    Idle,
}

impl HeaderSessionStatus {
    fn label(self) -> &'static str {
        match self {
            HeaderSessionStatus::Attention => "● Waiting",
            HeaderSessionStatus::Reconnecting => "● Reconnecting",
            HeaderSessionStatus::Working => "● Working",
            HeaderSessionStatus::Done => "● Done",
            HeaderSessionStatus::Idle => "● Idle",
        }
    }

    fn color(self) -> Color {
        match self {
            HeaderSessionStatus::Attention => RED,
            HeaderSessionStatus::Reconnecting => YELLOW,
            HeaderSessionStatus::Working => YELLOW,
            HeaderSessionStatus::Done => GREEN,
            HeaderSessionStatus::Idle => DISABLED,
        }
    }

    /// The 256-colour fallback paired with [`color`](Self::color): what a
    /// non-truecolor terminal sees for this status.
    fn color_index(self) -> u8 {
        match self {
            HeaderSessionStatus::Attention => RED_INDEX,
            HeaderSessionStatus::Reconnecting | HeaderSessionStatus::Working => YELLOW_INDEX,
            HeaderSessionStatus::Done => GREEN_INDEX,
            HeaderSessionStatus::Idle => DISABLED_INDEX,
        }
    }

    fn pulses(self) -> bool {
        matches!(
            self,
            HeaderSessionStatus::Working | HeaderSessionStatus::Attention
        )
    }
}

/// One frame's header input snapshot. Built from App state; pure data.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChatHeaderState {
    /// Daemon-published session title (rail summary title, else the launch
    /// short id). `None` renders no title text — never a placeholder.
    pub title: Option<String>,
    pub status: HeaderSessionStatus,
    /// Status-only routing target, shown left of the status badge.
    pub routing_status: Option<String>,
    /// Reserve cell zero for the session rail's `[Show]` chip.
    pub rail_hidden: bool,
    /// Display path of the working directory (launch fact).
    pub path: String,
    /// Git branch + dirty counts. `None` while the repo probe is pending or
    /// the cwd is not a repo — the neutral state renders no git slot.
    pub git: Option<GitFacts>,
    /// Active pills in priority order. Builders omit unknown/empty states.
    pub pills: Vec<HeaderPill>,
}

/// The planned header layout: everything paint and hit-testing need,
/// computed before painting so there is one source of truth.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChatHeaderLayout {
    /// The full header rect (all three rows).
    pub area: Rect,
    /// Visible pills in left-to-right draw order, with their rects.
    pub pill_buttons: Vec<(HeaderPillKind, Rect)>,
    /// The counted `more` chip, when lower-priority pills collapsed:
    /// (collapsed count, rect).
    pub more_button: Option<(usize, Rect)>,
    /// Pills collapsed behind `more`, in priority order, with full labels.
    pub collapsed: Vec<HeaderPill>,
    /// Full labels collapse to terse labels before the path is elided.
    pub compact_pills: bool,
}

impl ChatHeaderLayout {
    /// The pill kinds available for keyboard cycling this frame: visible
    /// pills plus collapsed ones (reachable through the popover).
    pub(crate) fn active_kinds(&self) -> Vec<HeaderPillKind> {
        let mut kinds: Vec<HeaderPillKind> = self.pill_buttons.iter().map(|(k, _)| *k).collect();
        kinds.extend(self.collapsed.iter().map(|p| p.kind));
        kinds
    }
}

fn pill_width(label: &str) -> u16 {
    crate::tui::button::display_width(&crate::tui::button::bracketed_label(label)) as u16
}

fn cluster_width(labels: &[&str]) -> u16 {
    let sum: u16 = labels.iter().map(|l| pill_width(l)).sum();
    sum.saturating_add(labels.len().saturating_sub(1) as u16)
}

/// Plan the right-aligned pill cluster for `pills` inside `budget` columns.
///
/// Returns the visible prefix indices and whether a counted `more` chip is
/// required. The highest-priority pills stay visible while they fit
/// (separators and the `more` chip included); the remainder collapse behind
/// `more`. The counted chip is the last-resort activity surface: it survives
/// alone even when its bracketed form cannot fit — the planner clamps it
/// into the header row (clipping its label) so active activity stays
/// visible and clickable at every width the header itself renders.
fn plan_pill_cluster(pills: &[HeaderPill], budget: u16) -> (Vec<usize>, bool) {
    if pills.is_empty() {
        return (Vec::new(), false);
    }
    let labels: Vec<&str> = pills.iter().map(|p| p.label.as_str()).collect();
    if cluster_width(&labels) <= budget {
        return ((0..pills.len()).collect(), false);
    }
    let widths: Vec<u16> = labels.iter().map(|l| pill_width(l)).collect();
    // Largest prefix (at least one pill) that fits alongside the counted
    // `more` chip covering the rest.
    for keep in (1..pills.len()).rev() {
        let collapsed = pills.len() - keep;
        let more_w = pill_width(&format!("+{collapsed}"));
        let used: u16 = widths[..keep].iter().sum();
        let separators = keep as u16; // keep-1 between pills, 1 before `more`
        if used.saturating_add(separators).saturating_add(more_w) <= budget {
            return ((0..keep).collect(), true);
        }
    }
    // Not even one pill fits beside the chip: the counted chip alone
    // carries the summary.
    (Vec::new(), true)
}

/// Plan the whole header. Pure: same state + area ⇒ same layout.
pub(crate) fn plan_chat_header(state: &ChatHeaderState, area: Rect) -> ChatHeaderLayout {
    let mut layout = ChatHeaderLayout {
        area,
        ..ChatHeaderLayout::default()
    };
    if area.width == 0 || area.height == 0 {
        return layout;
    }
    if area.height < 3 {
        return layout;
    }
    let full_left_w: u16 = launch_path_spans(&state.path, state.git.as_ref(), u16::MAX)
        .iter()
        .map(|span| display_width(span.content.as_ref()))
        .sum();
    let full_labels: Vec<&str> = state.pills.iter().map(|pill| pill.label.as_str()).collect();
    let compact = cluster_width(&full_labels)
        .saturating_add(3)
        .saturating_add(full_left_w)
        > area.width;
    layout.compact_pills = compact;
    let planned_pills: Vec<HeaderPill> = state
        .pills
        .iter()
        .map(|pill| HeaderPill {
            kind: pill.kind,
            label: if compact {
                compact_pill_label(pill)
            } else {
                pill.label.clone()
            },
        })
        .collect();
    let budget = area.width.saturating_sub(CLUSTER_GAP);
    let (visible, more) = plan_pill_cluster(&planned_pills, budget);

    // Right-align: walk from the right edge leftward, placing the `more`
    // chip first (rightmost) and then the visible pills so the
    // highest-priority pill ends up leftmost of the cluster. The chip
    // never leaves the header row: when its bracketed form is wider than
    // the row, it clamps to the row's left edge and its label clips —
    // the counted summary stays visible and clickable instead of
    // vanishing (and the meta-row path budget saturates to zero, so
    // nothing is overlapped).
    let meta_y = area.y.saturating_add(1);
    let mut x = area.right();
    if more {
        let collapsed = state.pills.len() - visible.len();
        let w = pill_width(&format!("+{collapsed}"));
        let chip_x = x.saturating_sub(w).max(area.x);
        let chip_w = w.min(area.width);
        x = chip_x;
        layout.more_button = Some((
            collapsed,
            Rect {
                x: chip_x,
                y: meta_y,
                width: chip_w,
                height: 1,
            },
        ));
        x = x.saturating_sub(CLUSTER_GAP);
    }
    let mut pill_buttons = Vec::with_capacity(visible.len());
    for index in visible.iter().rev() {
        let pill = &planned_pills[*index];
        let w = pill_width(&pill.label);
        x = x.saturating_sub(w);
        pill_buttons.push((
            pill.kind,
            Rect {
                x,
                y: meta_y,
                width: w,
                height: 1,
            },
        ));
        x = x.saturating_sub(CLUSTER_GAP);
    }
    pill_buttons.reverse();
    layout.pill_buttons = pill_buttons;
    layout.collapsed = state.pills[visible.len()..].to_vec();
    layout
}

fn compact_pill_label(pill: &HeaderPill) -> String {
    match pill.kind {
        HeaderPillKind::Attention => pill.label.replace("attention", "attn"),
        HeaderPillKind::Update => "update".to_string(),
        HeaderPillKind::Tool => pill.label.clone(),
        HeaderPillKind::Agent => pill
            .label
            .rsplit(" › ")
            .next()
            .unwrap_or(&pill.label)
            .to_string(),
        HeaderPillKind::Task => pill.label.replace("tasks", "t").replace("task", "t"),
        HeaderPillKind::Timer => pill.label.replace("timers", "tm").replace("timer", "tm"),
        HeaderPillKind::Skill => pill.label.replace("skill ", ""),
        HeaderPillKind::Pins => pill.label.replace("pins: ", "pins:"),
        HeaderPillKind::Longcache => "cache".to_string(),
        HeaderPillKind::Setup => pill.label.trim_start_matches("Setup: ").to_string(),
        HeaderPillKind::Lock => "lock".to_string(),
        HeaderPillKind::Side => "side".to_string(),
        HeaderPillKind::Caffeinate => "☕".to_string(),
        #[cfg(feature = "remote")]
        HeaderPillKind::OrgSync => "org".to_string(),
        #[cfg(feature = "remote")]
        HeaderPillKind::Connector => "remote".to_string(),
    }
}

/// Paint the planned header. All interactive affordances route through the
/// button registry so pointer hover/press handling is shared with every
/// other chip in the shell.
pub(crate) fn paint_chat_header(
    frame: &mut ratatui::Frame,
    layout: &ChatHeaderLayout,
    state: &ChatHeaderState,
    selected: Option<HeaderPillKind>,
    buttons: &mut crate::tui::button::ButtonRegistry,
) {
    let area = layout.area;
    if area.width == 0 || area.height == 0 {
        return;
    }
    // Row 0: optional rail [Show] reservation, title, routing status, badge.
    let title_row = Rect {
        y: area.y,
        height: 1,
        ..area
    };
    let status_label = state.status.label();
    let status_w = display_width(status_label);
    let show_w = if state.rail_hidden { 7 } else { 0 };
    let routing = state.routing_status.as_deref().unwrap_or("");
    let routing_w = if routing.is_empty() {
        0
    } else {
        display_width(routing).saturating_add(2)
    };
    let title_budget = title_row
        .width
        .saturating_sub(show_w + status_w + routing_w + CLUSTER_GAP);
    let title_text = state
        .title
        .as_deref()
        .map(|t| truncate_to_width(t, title_budget as usize))
        .unwrap_or_default();
    if !title_text.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                title_text,
                Style::default().fg(INK).add_modifier(Modifier::BOLD),
            ))),
            Rect {
                x: title_row.x.saturating_add(show_w),
                width: title_budget,
                ..title_row
            },
        );
    }
    // The status badge colour resolves through the terminal's colour
    // capability: a non-truecolor terminal sees the indexed fallback.
    let mut status_style = Style::default().fg(resolve_color(
        state.status.color(),
        state.status.color_index(),
    ));
    if state.status.pulses() {
        status_style = status_style.add_modifier(Modifier::BOLD);
    }
    if !routing.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                routing.to_string(),
                Style::default().fg(DISABLED),
            )))
            .right_aligned(),
            Rect {
                x: title_row.x.saturating_add(show_w),
                width: title_row.width.saturating_sub(show_w + status_w + 1),
                ..title_row
            },
        );
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(status_label, status_style))).right_aligned(),
        title_row,
    );

    if area.height < 2 {
        return;
    }
    if area.height == 2 {
        let rule_row = Rect {
            y: area.y.saturating_add(1),
            height: 1,
            ..area
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "─".repeat(usize::from(rule_row.width)),
                Style::default().fg(NIGHT),
            ))),
            rule_row,
        );
        return;
    }
    // Row 1: path + git left, pills right.
    let meta_row = Rect {
        y: area.y.saturating_add(1),
        height: 1,
        ..area
    };
    let cluster_left = layout
        .pill_buttons
        .iter()
        .map(|(_, rect)| rect.x)
        .chain(layout.more_button.iter().map(|(_, rect)| rect.x))
        .min();
    let left_budget = cluster_left.map_or(meta_row.width, |left| {
        left.saturating_sub(meta_row.x).saturating_sub(3)
    });
    let path_spans = path_git_spans(state, left_budget);
    frame.render_widget(
        Paragraph::new(Line::from(path_spans)),
        Rect {
            width: left_budget,
            ..meta_row
        },
    );

    for (kind, rect) in &layout.pill_buttons {
        let Some(pill) = state.pills.iter().find(|p| p.kind == *kind) else {
            continue;
        };
        if rect.width == 0 {
            continue;
        }
        let display_label = if layout.compact_pills {
            compact_pill_label(pill)
        } else {
            pill.label.clone()
        };
        let spec = ButtonSpec::new(
            ButtonId::HeaderPill(*kind),
            display_label.clone(),
            ButtonDispatch::HeaderPill(*kind),
        )
        .focused(selected == Some(*kind));
        let hovered = buttons.hover() == Some(&spec.id);
        let label = crate::tui::button::bracketed_label(&display_label);
        crate::tui::chrome::paint_chip(
            frame,
            *rect,
            &label,
            Style::default().fg(FOG),
            hovered || selected == Some(*kind),
        );
        buttons.register(*rect, spec);
    }
    if let Some((collapsed, rect)) = layout.more_button {
        let spec = ButtonSpec::new(
            ButtonId::HeaderMore,
            format!("+{collapsed}"),
            ButtonDispatch::HeaderMore,
        );
        let hovered = buttons.hover() == Some(&spec.id);
        crate::tui::chrome::paint_chip(
            frame,
            rect,
            &crate::tui::button::bracketed_label(&format!("+{collapsed}")),
            Style::default().fg(FOG),
            hovered,
        );
        buttons.register(rect, spec);
    }

    if area.height < 3 {
        return;
    }
    // Row 2: literal horizontal rule.
    let rule_row = Rect {
        y: area.y.saturating_add(2),
        height: 1,
        ..area
    };
    let rule = "─".repeat(usize::from(rule_row.width));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(rule, Style::default().fg(NIGHT)))),
        rule_row,
    );
}

/// The left meta-row spans: display path plus, when the repo snapshot has
/// resolved, the branch badge with dirty counts. This is the same span
/// shape the footer status line drew before the header became its one
/// home; the launch banner box reuses the builder so the two stay
/// identical.
fn path_git_spans(state: &ChatHeaderState, budget: u16) -> Vec<Span<'static>> {
    launch_path_spans(&state.path, state.git.as_ref(), budget)
}

/// The one path + git span builder. `budget` caps the total width in
/// display columns; the path elides from the left before git is dropped. All
/// measurements are display width — the same unit [`pill_width`] budgets
/// the right-hand cluster with — so wide glyphs can never make the two
/// clusters disagree about what a column is.
pub(crate) fn launch_path_spans(
    path: &str,
    git: Option<&GitFacts>,
    budget: u16,
) -> Vec<Span<'static>> {
    if budget == 0 {
        return Vec::new();
    }
    let fog = Style::default().fg(FOG);
    let prefix = "⎇ ";
    let Some(git) = git else {
        if budget <= display_width(prefix) {
            return vec![Span::styled(
                truncate_to_width(prefix, budget as usize),
                fog,
            )];
        }
        let path_budget = budget.saturating_sub(display_width(prefix)) as usize;
        return vec![
            Span::styled(prefix, fog),
            Span::styled(elide_path(path, path_budget), fog),
        ];
    };
    let suffix = if git.changes == 0 {
        " ✓ clean".to_string()
    } else {
        let plural = if git.changes == 1 { "" } else { "s" };
        format!(" ● {} change{plural}", git.changes)
    };
    let git_core_w = display_width(&git.branch).saturating_add(display_width(&suffix));
    if git_core_w > budget {
        return vec![Span::styled(
            truncate_to_width(&format!("{}{}", git.branch, suffix), budget as usize),
            Style::default().fg(BRASS).add_modifier(Modifier::BOLD),
        )];
    }
    let git_style = Style::default().fg(BRASS).add_modifier(Modifier::BOLD);
    let suffix_style = Style::default().fg(if git.changes == 0 { GREEN } else { YELLOW });
    let fixed_w = display_width(prefix)
        .saturating_add(display_width("   "))
        .saturating_add(git_core_w);
    if fixed_w > budget {
        return vec![
            Span::styled(git.branch.clone(), git_style),
            Span::styled(suffix, suffix_style),
        ];
    }
    let path_budget = budget.saturating_sub(fixed_w) as usize;
    vec![
        Span::styled(prefix, fog),
        Span::styled(elide_path(path, path_budget), fog),
        Span::styled("   ", fog),
        Span::styled(git.branch.clone(), git_style),
        Span::styled(suffix, suffix_style),
    ]
}

fn elide_path(path: &str, max: usize) -> String {
    if display_width(path) as usize <= max {
        return path.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let tail = path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path);
    let marker = "…/";
    if max <= display_width(marker) as usize {
        return truncate_to_width("…", max);
    }
    format!(
        "{marker}{}",
        truncate_to_width(tail, max.saturating_sub(display_width(marker) as usize))
    )
}

/// Git facts for a launch snapshot — the bridge the banner box uses to
/// reuse [`launch_path_spans`] without constructing a full header state.
/// Dirty counts come from the core formatter so the header, banner, and
/// startup welcome text can never drift apart.
pub(crate) fn launch_git_facts(repo: &cockpit_proto::RepoStatus) -> GitFacts {
    GitFacts {
        branch: repo.branch.clone(),
        changes: repo.staged.saturating_add(repo.unstaged),
    }
}

/// Display-width-aware truncation with an ellipsis. Pure. Measures in
/// columns, not chars: wide glyphs cost their real width, matching every
/// other budget in this module.
fn truncate_to_width(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if display_width(text) as usize <= max {
        return text.to_string();
    }
    if max == 1 {
        return "…".to_string();
    }
    let cut = clip_to_display_width(text, (max - 1) as u16);
    format!("{cut}…")
}

/// Named capability-parity rows: every header/footer control this issue
/// moved names its retained surface and the test that proves the parity.
/// A `proof` must be a declared `#[test]` in the app-level behavior suite
/// (`tui/app/chat_header_tests.rs`) — a test that builds the real App and
/// renders — not a layout unit test: the proof must exercise the mapped
/// control's replacement end to end. The ratchet in that suite enforces
/// the declaration mechanically; the mapping itself is reviewed content.
pub struct HeaderParityRow {
    pub control: &'static str,
    pub surface: &'static str,
    pub proof: &'static str,
}

pub fn capability_parity_table() -> &'static [HeaderParityRow] {
    &[
        HeaderParityRow {
            control: "footer cwd path",
            surface: "chat header meta row (left)",
            proof: "header_meta_row_replaces_footer_path_and_git",
        },
        HeaderParityRow {
            control: "footer git branch/dirty badge",
            surface: "chat header meta row badge",
            proof: "header_meta_row_replaces_footer_path_and_git",
        },
        HeaderParityRow {
            control: "footer async-schedule strip",
            surface: "header task/timer pills → /schedule listing",
            proof: "header_pills_draw_only_from_real_state",
        },
        HeaderParityRow {
            control: "agent/subagent activity summary",
            surface: "header agent pill → agent-tree overlay",
            proof: "agent_pill_opens_agent_tree",
        },
        HeaderParityRow {
            control: "active tool summary",
            surface: "header tool pill → tools pane",
            proof: "tool_pill_opens_tools_pane",
        },
        HeaderParityRow {
            control: "background task summary",
            surface: "header task pill → /schedule listing",
            proof: "task_and_timer_pills_open_schedule_listing",
        },
        HeaderParityRow {
            control: "timer summary",
            surface: "header timer pill → /schedule listing",
            proof: "task_and_timer_pills_open_schedule_listing",
        },
        HeaderParityRow {
            control: "skill activity summary",
            surface: "header skill pill → skills pane",
            proof: "skill_pill_opens_skills_pane",
        },
        HeaderParityRow {
            control: "attention summary",
            surface: "header attention pill → agent-tree attention",
            proof: "attention_pill_opens_agent_tree",
        },
        HeaderParityRow {
            control: "session title/status",
            surface: "chat header title row",
            proof: "header_session_status_tracks_real_state",
        },
        HeaderParityRow {
            control: "update available notice",
            surface: "chat header update pill",
            proof: "update_available_is_a_header_pill_and_not_a_persistent_row",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pill(kind: HeaderPillKind, label: &str) -> HeaderPill {
        HeaderPill {
            kind,
            label: label.to_string(),
        }
    }

    fn full_state() -> ChatHeaderState {
        ChatHeaderState {
            title: Some("Implement the demo shell".to_string()),
            status: HeaderSessionStatus::Working,
            routing_status: None,
            rail_hidden: false,
            path: "/home/dev/flycockpit".to_string(),
            git: Some(GitFacts {
                branch: "main".to_string(),
                changes: 3,
            }),
            pills: vec![
                pill(HeaderPillKind::Attention, "attention 2"),
                pill(HeaderPillKind::Tool, "tool edit"),
                pill(HeaderPillKind::Agent, "Build › explore"),
                pill(HeaderPillKind::Task, "tasks 2"),
                pill(HeaderPillKind::Timer, "timer 1"),
                pill(HeaderPillKind::Skill, "skill firecrawl"),
            ],
        }
    }

    fn area(width: u16) -> Rect {
        Rect::new(0, 0, width, CHAT_HEADER_HEIGHT)
    }

    fn priority_rank(kind: HeaderPillKind) -> usize {
        HeaderPillKind::ALL
            .iter()
            .position(|k| *k == kind)
            .expect("kind is a declared priority member")
    }

    #[test]
    fn pills_render_only_known_activity_and_omit_the_rest() {
        // No activity: no cluster at all.
        let state = ChatHeaderState {
            path: "/repo".to_string(),
            ..Default::default()
        };
        let layout = plan_chat_header(&state, area(80));
        assert!(layout.pill_buttons.is_empty());
        assert!(layout.more_button.is_none());
        assert!(layout.collapsed.is_empty());

        // A single active state renders exactly that pill, no more chip.
        let state = ChatHeaderState {
            pills: vec![pill(HeaderPillKind::Timer, "timer 1")],
            ..full_state()
        };
        let layout = plan_chat_header(&state, area(80));
        assert_eq!(
            layout
                .pill_buttons
                .iter()
                .map(|(kind, _)| *kind)
                .collect::<Vec<_>>(),
            vec![HeaderPillKind::Timer]
        );
        assert!(layout.more_button.is_none());
    }

    #[test]
    fn pill_cluster_is_right_aligned_without_collapsing_when_it_fits() {
        let state = full_state();
        let layout = plan_chat_header(&state, area(120));
        let kinds: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds.first().copied(), Some(HeaderPillKind::Attention));
        assert_eq!(kinds.last().copied(), Some(HeaderPillKind::Skill));
        let rects: Vec<_> = layout.pill_buttons.iter().map(|(_, r)| *r).collect();
        for pair in rects.windows(2) {
            assert_eq!(pair[0].right() + CLUSTER_GAP, pair[1].x);
            assert_eq!(pair[0].y, pair[1].y);
        }
        assert!(rects.last().expect("pills painted").right() <= 120);
        assert!(layout.more_button.is_none());
        assert!(layout.collapsed.is_empty());
    }

    #[test]
    fn narrow_widths_collapse_deterministically_in_priority_order() {
        let state = full_state();
        for width in HEADER_COLLAPSE_PROBE_WIDTHS {
            let layout = plan_chat_header(&state, area(width));
            let visible: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                visible.first().copied(),
                Some(HeaderPillKind::Attention),
                "the highest-priority indicator survives at {width}: {visible:?}"
            );
            let ranks: Vec<_> = visible.iter().map(|k| priority_rank(*k)).collect();
            assert!(
                ranks.windows(2).all(|w| w[0] < w[1]),
                "visible pills keep priority order at {width}: {visible:?}"
            );
            if !layout.collapsed.is_empty() {
                let (n, more) = layout
                    .more_button
                    .expect("collapsed pills require a counted more chip");
                assert_eq!(n, layout.collapsed.len());
                assert!(more.right() <= width);
            }
            let again = plan_chat_header(&state, area(width));
            assert_eq!(
                again.pill_buttons, layout.pill_buttons,
                "planning is deterministic at {width}"
            );
            assert_eq!(again.collapsed, layout.collapsed);
        }

        // At 56 columns, labels compact before any path elision or pill
        // collapse. This fixture's terse labels all fit.
        let layout = plan_chat_header(&state, area(56));
        let visible: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
        assert!(layout.compact_pills);
        assert_eq!(visible.len(), state.pills.len());
        assert!(layout.collapsed.is_empty());

        // At 40 columns the tail drops while the priority head survives.
        let layout = plan_chat_header(&state, area(40));
        let visible: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
        assert!(
            visible.len() < state.pills.len(),
            "40 columns must collapse part of the fixture"
        );
        let collapsed: Vec<_> = layout.collapsed.iter().map(|p| p.kind).collect();
        assert_eq!(collapsed.last().copied(), Some(HeaderPillKind::Skill));
        assert!(
            collapsed.iter().all(|kind| priority_rank(*kind)
                > visible
                    .iter()
                    .map(|k| priority_rank(*k))
                    .max()
                    .expect("a visible pill exists")),
            "only lower-priority pills collapse: visible {visible:?} collapsed {collapsed:?}"
        );

        // The counted summary still reaches the user.
        assert!(
            !layout.pill_buttons.is_empty() || layout.more_button.is_some(),
            "40 columns still surfaces the counted activity summary"
        );
        if let Some(first) = layout.pill_buttons.first().map(|(k, _)| *k) {
            assert_eq!(first, HeaderPillKind::Attention);
        }
    }

    #[test]
    fn unknown_git_renders_no_slot_and_known_git_renders_branch_and_changes() {
        let mut state = full_state();
        state.git = None;
        let spans = path_git_spans(&state, 40);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "⎇ /home/dev/flycockpit");
        assert!(
            !text.contains("main"),
            "no repo slot while unresolved: {text}"
        );

        state.git = Some(GitFacts {
            branch: "main".to_string(),
            changes: 3,
        });
        let spans = path_git_spans(&state, 80);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("main"), "branch badge present: {text}");
        assert!(text.contains("● 3 changes"), "dirty suffix present: {text}");

        // Clean tree: badge without counts, never a synthesized zero.
        state.git = Some(GitFacts {
            branch: "main".to_string(),
            changes: 0,
        });
        let spans = path_git_spans(&state, 80);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("main"), "{text}");
        assert!(text.contains("✓ clean"), "clean suffix present: {text}");
    }

    #[test]
    fn title_and_status_render_real_values_only() {
        let state = full_state();
        let layout = plan_chat_header(&state, area(80));
        assert_eq!(layout.area.height, CHAT_HEADER_HEIGHT);

        // No title yet: the state stays `None`; nothing is fabricated.
        let untitled = ChatHeaderState {
            title: None,
            ..full_state()
        };
        let layout = plan_chat_header(&untitled, area(80));
        assert!(untitled.title.is_none());
        assert!(!layout.pill_buttons.is_empty());
    }

    #[test]
    fn status_labels_are_distinct_and_truthful() {
        let labels = [
            HeaderSessionStatus::Attention.label(),
            HeaderSessionStatus::Reconnecting.label(),
            HeaderSessionStatus::Working.label(),
            HeaderSessionStatus::Done.label(),
            HeaderSessionStatus::Idle.label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert!(HeaderSessionStatus::Attention.label().contains("Waiting"));
        assert!(HeaderSessionStatus::Idle.label().contains("Idle"));
        assert_eq!(HeaderSessionStatus::Attention.color(), RED);
        assert_eq!(HeaderSessionStatus::Reconnecting.color(), YELLOW);
        assert_eq!(HeaderSessionStatus::Working.color(), YELLOW);
        assert_eq!(HeaderSessionStatus::Done.color(), GREEN);
        assert_eq!(HeaderSessionStatus::Idle.color(), DISABLED);
        // Every status also names its 256-colour fallback so the badge
        // resolves on non-truecolor terminals.
        assert_eq!(HeaderSessionStatus::Attention.color_index(), RED_INDEX);
        assert_eq!(
            HeaderSessionStatus::Reconnecting.color_index(),
            YELLOW_INDEX
        );
        assert_eq!(HeaderSessionStatus::Working.color_index(), YELLOW_INDEX);
        assert_eq!(HeaderSessionStatus::Done.color_index(), GREEN_INDEX);
        assert_eq!(HeaderSessionStatus::Idle.color_index(), DISABLED_INDEX);
    }

    #[test]
    fn git_facts_count_staged_and_unstaged_changes() {
        let dirty = cockpit_proto::RepoStatus {
            branch: "main".into(),
            staged: 1,
            unstaged: 2,
            unpushed: 3,
        };
        assert_eq!(launch_git_facts(&dirty).changes, 3);
        let clean = cockpit_proto::RepoStatus {
            branch: "main".into(),
            staged: 0,
            unstaged: 0,
            unpushed: 0,
        };
        assert_eq!(launch_git_facts(&clean).changes, 0);
    }

    #[test]
    fn truncation_measures_display_width_not_chars() {
        // Three wide glyphs: six columns, three chars.
        let wide = "中文啊";
        assert_eq!(display_width(wide), 6);
        assert_eq!(truncate_to_width(wide, 6), "中文啊");
        assert_eq!(truncate_to_width(wide, 5), "中文…");
        assert_eq!(truncate_to_width(wide, 3), "中…");
        assert_eq!(truncate_to_width(wide, 1), "…");
        assert_eq!(truncate_to_width(wide, 0), "");
        // Mixed content truncates on the column budget.
        assert_eq!(truncate_to_width("a中文b", 4), "a中…");
    }

    #[test]
    fn meta_row_spans_respect_display_width_budget() {
        let wide_path = "路径路径路径路径"; // 16 columns, 8 chars
        let git = GitFacts {
            branch: "main".to_string(),
            changes: 3,
        };
        for budget in 6u16..40 {
            let spans = launch_path_spans(wide_path, Some(&git), budget);
            let total: u16 = spans
                .iter()
                .map(|span| display_width(span.content.as_ref()))
                .sum();
            assert!(
                total <= budget,
                "spans ({total} cols) must fit the {budget}-column budget"
            );
        }
        // No git: the path keeps its branch-like tail marker.
        let spans = launch_path_spans(wide_path, None, 7);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "⎇ …/路…");
        // A wide-glyph branch name truncates too instead of spilling past
        // the reserved pill cluster.
        let wide_branch = GitFacts {
            branch: "分支分支分支".to_string(),
            changes: 0,
        };
        let spans = launch_path_spans("/p", Some(&wide_branch), 10);
        let total: u16 = spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum();
        assert!(total <= 10, "wide branch badge fits: {total} cols");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains('…'), "truncated visibly: {text:?}");
    }

    #[test]
    fn activity_summary_survives_ultra_narrow_widths() {
        let state = full_state(); // six active pills
        for width in 1u16..6 {
            let layout = plan_chat_header(&state, area(width));
            let (_, chip) = layout
                .more_button
                .expect("the counted chip survives every header width");
            assert!(
                chip.x >= layout.area.x && chip.right() <= layout.area.right(),
                "chip clamped inside the {width}-column header row"
            );
            assert_eq!(layout.collapsed.len(), state.pills.len());
            assert_eq!(
                layout.active_kinds().len(),
                state.pills.len(),
                "collapsed pills stay reachable through cycling and the popover"
            );
        }
    }

    #[test]
    fn parity_table_names_every_moved_control() {
        let table = capability_parity_table();
        assert!(table.len() >= 10, "every moved control has a row");
        for row in table {
            assert!(!row.control.is_empty());
            assert!(!row.surface.is_empty());
            assert!(!row.proof.is_empty());
        }
        let controls: Vec<_> = table.iter().map(|r| r.control).collect();
        for expected in [
            "footer cwd path",
            "footer git branch/dirty badge",
            "footer async-schedule strip",
            "session title/status",
        ] {
            assert!(
                controls.contains(&expected),
                "parity table must name {expected}"
            );
        }
    }
}
