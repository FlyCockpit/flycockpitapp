//! TUI status line / chrome.
//!
//! Per `the design notes` §1a, the chrome **always** shows:
//!   - The current working directory (abbreviated if it overflows).
//!   - The git branch (with a leading `` glyph) when the cwd is in a
//!     git repo. When not in a repo, no slot — no placeholder text.
//!
//! Other slots (active agent, model, token count, …) compose around
//! these two.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

use crate::config::extended::LlmMode;
use crate::db::connector::ConnectorDisclosure;
use crate::db::org_sync::OrgSyncDisclosure;
use crate::git::RepoStatus;
use crate::tui::theme::{
    FAVORITE_MODEL, MUTED_COLOR_INDEX, PLAN_YELLOW, STATUS_BRANCH_BADGE, WARNING_TEXT,
};
use crate::welcome::LaunchInfo;

pub fn status_line_spans(info: &LaunchInfo) -> Vec<Span<'static>> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut spans = vec![Span::styled(info.cwd_display.clone(), muted)];

    if let Some(repo) = &info.repo_status {
        // Pill-shaped badge: `▐ branch counts ▌` where the edge
        // glyphs (▐ ▌) are yellow-on-terminal-default and the body is
        // black-on-yellow. The half-block edges produce a "rounded"
        // visual without needing Nerd Fonts (which a true Powerline
        // semicircle would require).
        let badge = Style::default().fg(Color::Black).bg(STATUS_BRANCH_BADGE);
        let edge = Style::default().fg(STATUS_BRANCH_BADGE);
        spans.push(Span::raw(" "));
        spans.push(Span::styled("▐", edge));
        spans.push(Span::styled(format!(" {} ", repo.branch), badge));
        let counts = repo_counts(repo);
        if !counts.is_empty() {
            spans.push(Span::styled(format!("{counts} "), badge));
        }
        spans.push(Span::styled("▌", edge));
    }

    spans
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FooterControl {
    Agent,
    Model,
    Mode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FooterHit {
    pub control: FooterControl,
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct LeftStatus {
    pub spans: Vec<Span<'static>>,
    pub hits: Vec<FooterHit>,
}

/// Bottom-left status: `agent path · provider/model · mode`.
///
///   - The model glyph is green when trusted, dark yellow when marked
///     favorite, light grey otherwise.
///   - Agent segments use the same styling as delegated child-agent names in
///     the history view.
pub fn left_status(
    info: &LaunchInfo,
    llm_mode: LlmMode,
    agent_path: &[String],
    selected: Option<FooterControl>,
) -> LeftStatus {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut hits = Vec::new();
    let mut col: u16 = 0;

    let path = if agent_path.is_empty() {
        vec![info.agent_name.clone()]
    } else {
        agent_path.to_vec()
    };
    let agent_start = col;
    for (idx, name) in path.iter().enumerate() {
        if idx > 0 {
            push_span(&mut spans, &mut col, Span::styled(" › ".to_string(), muted));
        }
        push_span(
            &mut spans,
            &mut col,
            Span::styled(
                crate::tui::history::agent_display_label(name).to_string(),
                selected_style(
                    crate::tui::history::subagent_child_name_style(name),
                    selected == Some(FooterControl::Agent),
                ),
            ),
        );
    }
    hits.push(FooterHit {
        control: FooterControl::Agent,
        start: agent_start,
        end: col,
    });

    if let Some((provider, model)) = &info.active_model {
        push_span(&mut spans, &mut col, Span::styled(" · ".to_string(), muted));
        let model_style = if info.active_model_is_trusted {
            Style::default().fg(Color::Green)
        } else if info.active_model_is_favorite {
            // Dark yellow / amber (xterm 220 is the bright shade we use
            // for the branch badge — 178 reads as "dark yellow" alongside
            // the light grey).
            Style::default().fg(FAVORITE_MODEL)
        } else {
            muted
        };
        let start = col;
        push_span(
            &mut spans,
            &mut col,
            Span::styled(
                format!("{provider}/{model}"),
                selected_style(model_style, selected == Some(FooterControl::Model)),
            ),
        );
        hits.push(FooterHit {
            control: FooterControl::Model,
            start,
            end: col,
        });
    }

    push_span(&mut spans, &mut col, Span::styled(" · ".to_string(), muted));
    let start = col;
    push_span(
        &mut spans,
        &mut col,
        Span::styled(
            llm_mode.as_str().to_string(),
            selected_style(muted, selected == Some(FooterControl::Mode)),
        ),
    );
    hits.push(FooterHit {
        control: FooterControl::Mode,
        start,
        end: col,
    });

    LeftStatus { spans, hits }
}

fn push_span(spans: &mut Vec<Span<'static>>, col: &mut u16, span: Span<'static>) {
    *col = col.saturating_add(span.width() as u16);
    spans.push(span);
}

fn selected_style(style: Style, selected: bool) -> Style {
    if selected {
        style
            .fg(style.fg.unwrap_or(Color::White))
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        style
    }
}

/// Transient async-schedule strip (GOALS §22). Rendered **only** when ≥1
/// scheduled task is active — additive to the fixed chrome, never a permanent
/// slot. Each gets a glyph by kind: `⟳` loop, `⏲` timer, `⤓` background. The
/// caller passes `(kind, label, iteration)` tuples; this returns
/// the spans to append to the bottom-left status line, prefixed with a
/// separator. Returns an empty vec when there is nothing scheduled.
pub fn schedule_strip_spans(scheduled: &[(String, String, u64)]) -> Vec<Span<'static>> {
    if scheduled.is_empty() {
        return Vec::new();
    }
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let active = Style::default().fg(Color::Cyan);
    let mut spans: Vec<Span<'static>> = vec![Span::styled("  ".to_string(), muted)];
    for (i, (kind, label, iteration)) in scheduled.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ".to_string(), muted));
        }
        let glyph = match kind.as_str() {
            "timer" => "⏲",
            "background" => "⤓",
            _ => "⟳",
        };
        let detail = if kind == "background" {
            label.clone()
        } else {
            format!("{label} {iteration}")
        };
        spans.push(Span::styled(format!("{glyph} {detail}"), active));
    }
    spans
}

/// Persistent enterprise session-log sync disclosure. Rendered only while an
/// org policy mandates sync for this instance. Additive to the fixed chrome.
pub fn org_sync_spans(disclosure: Option<&OrgSyncDisclosure>) -> Vec<Span<'static>> {
    let Some(disclosure) = disclosure else {
        return Vec::new();
    };
    vec![Span::styled(
        format!("org sync {} ", disclosure.org_id),
        Style::default().fg(WARNING_TEXT),
    )]
}

/// Persistent remote relay connector indicator. Rendered while remote access is
/// enabled or the daemon has a non-off connector state. Additive to fixed chrome.
pub fn connector_spans(disclosure: Option<&ConnectorDisclosure>) -> Vec<Span<'static>> {
    let Some(disclosure) = disclosure else {
        return Vec::new();
    };
    if !disclosure.enabled && disclosure.status == "off" {
        return Vec::new();
    }
    let style = match disclosure.status.as_str() {
        "connected" => Style::default().fg(Color::Cyan),
        "reconnecting" => Style::default().fg(PLAN_YELLOW),
        _ => Style::default().fg(WARNING_TEXT),
    };
    vec![Span::styled(
        format!("remote {} ", disclosure.status),
        style,
    )]
}

/// Persistent caffeination indicator (`/caffeinate`, GOALS §1a). Rendered
/// **only** while caffeination is active — additive to the fixed chrome,
/// never a permanent slot. Driven by the daemon-broadcast state so the
/// glyph appears (and clears) on every connected client in lockstep.
/// Returns the spans to prepend to the right-hand status line (`☕` plus a
/// trailing space separating it from the cwd), or an empty vec when off.
pub fn caffeinate_glyph_spans(active: bool) -> Vec<Span<'static>> {
    if !active {
        return Vec::new();
    }
    // Cyan reads as "kept awake" without competing with the yellow branch
    // badge; the trailing space keeps it off the cwd text.
    vec![Span::styled(
        "☕ ".to_string(),
        Style::default().fg(Color::Cyan),
    )]
}

/// Transient "waiting for lock" indicator
/// (`readlock-wait-and-lock-expiry.md`). Rendered **only** while a `readlock`
/// in this session is blocked on a lock another agent/session holds —
/// additive to the fixed chrome (cwd + branch + context + active agent,
/// GOALS §1a), never displacing a slot, the same pattern as the `☕`
/// caffeinate glyph. Names the contended path (basename, to stay compact)
/// and the holding agent; clears when the wait ends (lock acquired or
/// cancelled). Yellow reads as "blocked, waiting" without the red of an
/// error. Returns an empty vec when not waiting.
pub fn waiting_for_lock_spans(state: Option<&(String, String)>) -> Vec<Span<'static>> {
    let Some((path, holder)) = state else {
        return Vec::new();
    };
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path.as_str());
    vec![Span::styled(
        format!("⏳ waiting for lock on `{name}` (held by `{holder}`) "),
        Style::default().fg(WARNING_TEXT),
    )]
}

/// Side-conversation indicator (`/side`, GOALS §1a). Rendered **only**
/// while a throwaway side conversation is open — additive to the fixed
/// chrome (cwd + branch), never displacing a slot, the same pattern as the
/// `☕` caffeinate glyph. Magenta reads as "you're somewhere temporary"
/// without competing with the yellow branch badge; the trailing space keeps
/// it off the cwd text. Returns an empty vec in the main session.
pub fn side_glyph_spans(active: bool) -> Vec<Span<'static>> {
    if !active {
        return Vec::new();
    }
    vec![Span::styled(
        "⑃ side · /side end ".to_string(),
        Style::default().fg(Color::Magenta),
    )]
}

/// Additive plan-status indicator (`plan-status-chrome-and-resolver.md`).
/// Rendered **only** when this project has something unfinished — additive to
/// the fixed chrome (cwd + branch + context + active agent, GOALS §1a), never
/// displacing a slot, the same pattern as the `☕` caffeinate glyph. Up to
/// three segments, each omitted when its count is zero; an all-zero state
/// returns an empty vec so a normal coding session stays uncluttered.
///
///   - **ready** `⧖N` — queued (`Pending`) plans.
///   - **in-progress** `▶N` — the executing plan (≤1 per project).
///   - **interruptions** `?N` — open `needs_attention` items blocking
///     progress; the actionable, attention-grabbing segment (rendered last so
///     it reads as the thing to act on, and bold to stand out).
///
/// Driven by daemon-broadcast state, so a reconnecting / late-opened TUI shows
/// the correct counts. Returns the spans to prepend to the right-hand status
/// line (a trailing space separates the slot from what follows), or an empty
pub fn repo_counts(repo: &RepoStatus) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_info(agent: &str) -> LaunchInfo {
        LaunchInfo {
            version: "test",
            session_id: None,
            session_short_id: None,
            provider_line: String::new(),
            active_model: Some(("openai".into(), "gpt-test".into())),
            active_model_is_favorite: true,
            active_model_is_trusted: false,
            active_model_max_context: None,
            active_model_supports_images: false,
            cwd: std::path::PathBuf::from("/repo"),
            cwd_display: "/repo".into(),
            repo_status: None,
            agent_name: agent.into(),
            user_name: None,
            banner_enabled: false,
        }
    }

    /// The waiting-for-lock indicator surfaces the contended path (basename)
    /// and the holder while waiting, and is absent (empty) when not waiting —
    /// the same additive-chrome contract as the ☕ glyph.
    #[test]
    fn waiting_for_lock_indicator_shows_path_and_holder_and_clears() {
        // Not waiting → no spans (never displaces the fixed chrome).
        assert!(waiting_for_lock_spans(None).is_empty());

        // Waiting → one transient span naming the basename + holder.
        let state = ("/repo/src/main.rs".to_string(), "builder".to_string());
        let spans = waiting_for_lock_spans(Some(&state));
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("waiting for lock"), "{text}");
        assert!(text.contains("main.rs"), "names the contended path: {text}");
        assert!(text.contains("builder"), "names the holder: {text}");
        // Yellow ("blocked, waiting"), not the red of an error.
        assert_eq!(spans[0].style.fg, Some(WARNING_TEXT));
    }

    #[test]
    fn org_sync_spans_disclose_active_policy() {
        let spans = org_sync_spans(Some(&OrgSyncDisclosure {
            org_id: "org-1".to_string(),
            cursor_seq: 7,
            last_synced_at_ms: None,
        }));
        let text: String = spans.iter().map(|span| span.content.as_ref()).collect();
        assert_eq!(text, "org sync org-1 ");
        assert!(org_sync_spans(None).is_empty());
    }

    #[test]
    fn side_glyph_present_only_when_active() {
        // Off in the main session; an additive indicator while a `/side`
        // side conversation is open (never a permanent slot).
        assert!(side_glyph_spans(false).is_empty());
        let spans = side_glyph_spans(true);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].content.contains("side"));
        assert!(spans[0].content.contains("/side end"));
    }

    #[test]
    fn left_status_agent_uses_history_subagent_child_name_foreground() {
        let mut info = launch_info("explore");
        info.active_model_is_favorite = false;

        let spans = left_status(
            &info,
            LlmMode::Defensive,
            std::slice::from_ref(&info.agent_name),
            None,
        )
        .spans;
        let agent = spans
            .iter()
            .find(|span| span.content == "explore")
            .expect("active-agent span present");
        assert_eq!(
            agent.style.fg,
            crate::tui::history::subagent_child_name_style("explore").fg
        );
    }

    #[test]
    fn left_status_trusted_model_renders_green() {
        let mut info = launch_info("Build");
        info.active_model_is_favorite = false;
        info.active_model_is_trusted = true;
        let spans = left_status(
            &info,
            LlmMode::Defensive,
            std::slice::from_ref(&info.agent_name),
            None,
        )
        .spans;
        let model = spans
            .iter()
            .find(|span| span.content == "openai/gpt-test")
            .expect("active model span present");
        assert_eq!(model.style.fg, Some(Color::Green));
    }

    #[test]
    fn left_status_renders_agent_path_model_and_mode_with_hits() {
        let info = launch_info("Build");
        let path = vec!["Build".to_string(), "explore".to_string()];
        let status = left_status(&info, LlmMode::Frontier, &path, Some(FooterControl::Mode));
        let text = status
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert_eq!(text, "Build › explore · openai/gpt-test · frontier");
        assert_eq!(
            status
                .hits
                .iter()
                .map(|hit| hit.control)
                .collect::<Vec<_>>(),
            vec![
                FooterControl::Agent,
                FooterControl::Model,
                FooterControl::Mode
            ]
        );
        let mode = status
            .spans
            .iter()
            .find(|span| span.content == "frontier")
            .expect("mode segment present");
        assert!(
            mode.style
                .add_modifier
                .contains(ratatui::style::Modifier::UNDERLINED)
        );
    }
}

#[cfg(test)]
mod connector_tests {
    use super::*;

    #[test]
    fn connector_spans_render_enabled_state() {
        let disclosure = ConnectorDisclosure {
            enabled: true,
            status: "connected".to_string(),
            relay_url: Some("wss://relay.example/ws".to_string()),
            relay_id: Some("relay-1".to_string()),
            relay_region: Some("iad".to_string()),
            last_error: None,
        };
        let spans = connector_spans(Some(&disclosure));
        assert_eq!(spans[0].content.as_ref(), "remote connected ");
        assert!(connector_spans(None).is_empty());
    }
}
