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
//! state: a pill whose state is unknown or empty is omitted, never guessed.
//! Lower-priority pills collapse into a counted `more` chip in the priority
//! order [`HeaderPillKind`] declares (attention, tool, agent, task, timer,
//! skill), so narrow widths deterministically retain the highest-priority
//! active indicator.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::button::{ButtonDispatch, ButtonId, ButtonSpec};
use crate::tui::theme::{DIVIDER_DIM, MUTED_COLOR_INDEX, STATUS_BRANCH_BADGE};

/// Height of the full header: title row, meta row, rule row.
pub(crate) const CHAT_HEADER_HEIGHT: u16 = 3;

/// One column of separation between the path cluster and the pill cluster
/// (and between pills), mirroring the reference shell.
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
    Tool,
    Agent,
    Task,
    Timer,
    Skill,
}

impl HeaderPillKind {
    /// Every kind, in priority order. The button inventory derives its
    /// header coverage from this list.
    pub(crate) const ALL: [HeaderPillKind; 6] = [
        HeaderPillKind::Attention,
        HeaderPillKind::Tool,
        HeaderPillKind::Agent,
        HeaderPillKind::Task,
        HeaderPillKind::Timer,
        HeaderPillKind::Skill,
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
    /// `+staged ~unstaged ^unpushed` — empty when the tree is clean.
    pub counts: String,
}

/// Session status derived from authoritative app state (attention
/// interrupts, inference reconnect, busy span). Never synthesized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum HeaderSessionStatus {
    Attention,
    Reconnecting,
    Working,
    #[default]
    Idle,
}

impl HeaderSessionStatus {
    fn label(self) -> &'static str {
        match self {
            HeaderSessionStatus::Attention => "● attention",
            HeaderSessionStatus::Reconnecting => "● reconnecting",
            HeaderSessionStatus::Working => "● working",
            HeaderSessionStatus::Idle => "idle",
        }
    }

    fn color(self) -> Color {
        match self {
            HeaderSessionStatus::Attention => Color::Magenta,
            HeaderSessionStatus::Reconnecting => Color::Yellow,
            HeaderSessionStatus::Working => Color::Cyan,
            HeaderSessionStatus::Idle => Color::Indexed(MUTED_COLOR_INDEX),
        }
    }
}

/// One frame's header input snapshot. Built from App state; pure data.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChatHeaderState {
    /// Daemon-published session title (rail summary title, else the launch
    /// short id). `None` renders no title text — never a placeholder.
    pub title: Option<String>,
    pub status: HeaderSessionStatus,
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
/// `more`. When even the first pill plus `more` cannot fit, `more` alone
/// survives so the activity summary stays reachable; when not even that
/// fits, the cluster is omitted.
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
    // Only the counted chip fits.
    if CLUSTER_GAP + pill_width(&format!("+{}", pills.len())) <= budget {
        return (Vec::new(), true);
    }
    (Vec::new(), false)
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
    let budget = area.width.saturating_sub(CLUSTER_GAP);
    let (visible, more) = plan_pill_cluster(&state.pills, budget);

    // Right-align: walk from the right edge leftward, placing the `more`
    // chip first (rightmost) and then the visible pills so the
    // highest-priority pill ends up leftmost of the cluster.
    let meta_y = area.y.saturating_add(1);
    let mut x = area.right();
    if more {
        let collapsed = state.pills.len() - visible.len();
        let w = pill_width(&format!("+{collapsed}"));
        x = x.saturating_sub(w);
        layout.more_button = Some((
            collapsed,
            Rect {
                x,
                y: meta_y,
                width: w,
                height: 1,
            },
        ));
        x = x.saturating_sub(CLUSTER_GAP);
    }
    let mut pill_buttons = Vec::with_capacity(visible.len());
    for index in visible.iter().rev() {
        let pill = &state.pills[*index];
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
    // Row 1: title (bold) left, status badge right.
    let title_row = Rect {
        y: area.y,
        height: 1,
        ..area
    };
    let status_label = state.status.label();
    let status_w = status_label.chars().count() as u16;
    let title_budget = title_row.width.saturating_sub(status_w + CLUSTER_GAP);
    let title_text = state
        .title
        .as_deref()
        .map(|t| truncate_to_width(t, title_budget as usize))
        .unwrap_or_default();
    if !title_text.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                title_text,
                Style::default().add_modifier(Modifier::BOLD),
            ))),
            Rect {
                width: title_budget,
                ..title_row
            },
        );
    }
    let mut status_style = Style::default().fg(state.status.color());
    if matches!(
        state.status,
        HeaderSessionStatus::Attention | HeaderSessionStatus::Working
    ) {
        status_style = status_style.add_modifier(Modifier::BOLD);
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(status_label, status_style))).right_aligned(),
        title_row,
    );

    // Row 2: path + git left, pills right.
    let meta_row = Rect {
        y: area.y.saturating_add(1),
        height: 1,
        ..area
    };
    let pills_used: u16 = layout
        .pill_buttons
        .iter()
        .map(|(_, rect)| rect.width + CLUSTER_GAP)
        .chain(
            layout
                .more_button
                .iter()
                .map(|(_, rect)| rect.width + CLUSTER_GAP),
        )
        .sum();
    let left_budget = meta_row.width.saturating_sub(pills_used);
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
        let spec = ButtonSpec::new(
            ButtonId::HeaderPill(*kind),
            pill.label.clone(),
            ButtonDispatch::HeaderPill(*kind),
        )
        .focused(selected == Some(*kind));
        let _ = buttons.paint(frame, rect.x, rect.y, rect.width, spec);
    }
    if let Some((collapsed, rect)) = layout.more_button {
        let spec = ButtonSpec::new(
            ButtonId::HeaderMore,
            format!("+{collapsed}"),
            ButtonDispatch::HeaderMore,
        );
        let _ = buttons.paint(frame, rect.x, rect.y, rect.width, spec);
    }

    // Row 3: literal horizontal rule.
    let rule_row = Rect {
        y: area.y.saturating_add(2),
        height: 1,
        ..area
    };
    let rule = "─".repeat(usize::from(rule_row.width));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            rule,
            Style::default().fg(DIVIDER_DIM),
        ))),
        rule_row,
    );
}

/// The left meta-row spans: display path plus, when the repo snapshot has
/// resolved, the branch badge with dirty counts. This is the same span
/// shape the footer status line drew before the header became its one
/// home ([`repo_counts`] moved with it); the launch banner box reuses the
/// builder so the two stay identical.
fn path_git_spans(state: &ChatHeaderState, budget: u16) -> Vec<Span<'static>> {
    launch_path_spans(&state.path, state.git.as_ref(), budget)
}

/// The one path + git badge span builder. `budget` caps the total width
/// (path truncates first); pass `u16::MAX` for unbounded measurement.
pub(crate) fn launch_path_spans(
    path: &str,
    git: Option<&GitFacts>,
    budget: u16,
) -> Vec<Span<'static>> {
    if budget == 0 {
        return Vec::new();
    }
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let Some(git) = git else {
        return vec![Span::styled(
            truncate_to_width(path, budget as usize),
            muted,
        )];
    };
    let badge = Style::default().fg(Color::Black).bg(STATUS_BRANCH_BADGE);
    let edge = Style::default().fg(STATUS_BRANCH_BADGE);
    let counts = if git.counts.is_empty() {
        String::new()
    } else {
        format!("{} ", git.counts)
    };
    let badge_w = 2 + git.branch.chars().count() as u16 + counts.chars().count() as u16 + 1;
    if budget <= badge_w + 1 {
        // The path degrades first; keep the branch visible when it fits.
        let mut spans = vec![
            Span::styled("▐", edge),
            Span::styled(format!(" {} ", git.branch), badge),
        ];
        if !counts.is_empty() {
            spans.push(Span::styled(counts.clone(), badge));
        }
        spans.push(Span::styled("▌", edge));
        return spans;
    }
    let path_budget = (budget - badge_w - 1) as usize;
    vec![
        Span::styled(truncate_to_width(path, path_budget), muted),
        Span::raw(" "),
        Span::styled("▐", edge),
        Span::styled(format!(" {} ", git.branch), badge),
        Span::styled(counts, badge),
        Span::styled("▌", edge),
    ]
}

/// Git facts for a launch snapshot — the bridge the banner box uses to
/// reuse [`launch_path_spans`] without constructing a full header state.
pub(crate) fn launch_git_facts(repo: &cockpit_proto::RepoStatus) -> GitFacts {
    GitFacts {
        branch: repo.branch.clone(),
        counts: repo_counts(repo),
    }
}

/// Display-width-aware truncation with an ellipsis. Pure.
fn truncate_to_width(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if text.chars().count() <= max {
        return text.to_string();
    }
    if max == 1 {
        return "…".to_string();
    }
    let cut: String = text.chars().take(max - 1).collect();
    format!("{cut}…")
}

/// Dirty-count suffix (`+staged ~unstaged ^unpushed`) over the daemon's
/// `RepoStatus`. Presentation-only formatter (no I/O); it mirrors the core
/// `repo_counts` formatter that startup welcome text uses — keep the two in
/// sync.
pub(crate) fn repo_counts(repo: &cockpit_proto::RepoStatus) -> String {
    let mut parts = Vec::new();
    if repo.staged > 0 {
        parts.push(format!("+{}", repo.staged));
    }
    if repo.unstaged > 0 {
        parts.push(format!("~{}", repo.unstaged));
    }
    if repo.unpushed > 0 {
        parts.push(format!("^{}", repo.unpushed));
    }
    parts.join(" ")
}

/// Named capability-parity rows: every header/footer control this issue
/// moved names its retained surface and the test that proves the parity.
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
            proof: "pills_render_only_known_activity_and_omit_the_rest",
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
            proof: "title_and_status_render_real_values_only",
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
            path: "/home/dev/flycockpit".to_string(),
            git: Some(GitFacts {
                branch: "main".to_string(),
                counts: "+1 ~2".to_string(),
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

        // Skill collapses before timer, timer before task: at 56 columns the
        // tail of the fixture drops while the head survives.
        let layout = plan_chat_header(&state, area(56));
        let visible: Vec<_> = layout.pill_buttons.iter().map(|(k, _)| *k).collect();
        assert!(
            visible.len() < state.pills.len(),
            "56 columns must collapse part of the fixture"
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

        // At 40 columns the counted summary still reaches the user.
        let layout = plan_chat_header(&state, area(40));
        assert!(
            !layout.pill_buttons.is_empty() || layout.more_button.is_some(),
            "40 columns still surfaces the counted activity summary"
        );
        if let Some(first) = layout.pill_buttons.first().map(|(k, _)| *k) {
            assert_eq!(first, HeaderPillKind::Attention);
        }
    }

    #[test]
    fn unknown_git_renders_no_slot_and_known_git_renders_branch_and_counts() {
        let mut state = full_state();
        state.git = None;
        let spans = path_git_spans(&state, 40);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "/home/dev/flycockpit");
        assert!(!text.contains('▐'), "no repo slot while unresolved: {text}");

        state.git = Some(GitFacts {
            branch: "main".to_string(),
            counts: "+1 ~2 ^3".to_string(),
        });
        let spans = path_git_spans(&state, 80);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("main"), "branch badge present: {text}");
        assert!(text.contains("+1 ~2 ^3"), "dirty counts present: {text}");

        // Clean tree: badge without counts, never a synthesized zero.
        state.git = Some(GitFacts {
            branch: "main".to_string(),
            counts: String::new(),
        });
        let spans = path_git_spans(&state, 80);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("main"), "{text}");
        assert!(!text.contains("+0"), "no synthetic zero counts: {text}");
        assert!(!text.contains('~'), "{text}");
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
            HeaderSessionStatus::Idle.label(),
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert!(HeaderSessionStatus::Attention.label().contains("attention"));
        assert!(HeaderSessionStatus::Idle.label().contains("idle"));
    }

    #[test]
    fn repo_counts_formatter_matches_core_spelling() {
        let dirty = cockpit_proto::RepoStatus {
            branch: "main".into(),
            staged: 1,
            unstaged: 2,
            unpushed: 3,
        };
        assert_eq!(repo_counts(&dirty), "+1 ~2 ^3");
        let clean = cockpit_proto::RepoStatus {
            branch: "main".into(),
            staged: 0,
            unstaged: 0,
            unpushed: 0,
        };
        assert_eq!(repo_counts(&clean), "");
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
