//! In-TUI launch banner box.
//!
//! Renders the full welcome header (P-51 art + version / welcome /
//! provider / path-branch lines) inside a rounded, accent-blue box that
//! lives in the chat pane as the topmost scroll entry. Replaces the old
//! pre-alt-screen stdout banner (`welcome::print_header`), which was
//! only ever visible in scrollback after the TUI exited.
//!
//! The vertical placement (centered-until-messages-reach-it, then
//! scrolls off) is owned by `render_history`; this module only builds
//! the horizontally-centered, bordered lines.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::banner;
use crate::tui::chrome;
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};
use cockpit_core::welcome::{APP_NAME, LaunchInfo};

const ACCENT: Color = Color::Indexed(ACCENT_BLUE_INDEX);
const GREY: Color = Color::Indexed(MUTED_COLOR_INDEX);
/// One space of breathing room inside each vertical rail.
const INNER_PAD: usize = 1;

/// Build the bordered, horizontally-centered banner box as ready-to-
/// blit lines, or `None` when it shouldn't show: suppressed by config /
/// env, or the box doesn't fit the pane (too narrow or too short — we
/// skip rather than clip a half-drawn box).
pub fn build(info: &LaunchInfo, pane_w: u16, pane_h: u16) -> Option<Vec<Line<'static>>> {
    let suppressed = banner::suppressed_for_tui(info.banner_enabled);
    #[cfg(test)]
    let suppressed = suppressed && !TEST_FORCE_VISIBLE.with(std::cell::Cell::get);
    if suppressed {
        return None;
    }
    build_box(info, pane_w, pane_h)
}

#[cfg(test)]
std::thread_local! {
    static TEST_FORCE_VISIBLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn with_test_banner_visible<T>(f: impl FnOnce() -> T) -> T {
    struct ResetVisibility<'a> {
        force: &'a std::cell::Cell<bool>,
        previous: bool,
    }

    impl Drop for ResetVisibility<'_> {
        fn drop(&mut self) {
            self.force.set(self.previous);
        }
    }

    TEST_FORCE_VISIBLE.with(|force| {
        let previous = force.replace(true);
        let _reset = ResetVisibility { force, previous };
        f()
    })
}

/// The pure box construction, without the config/env suppression gate.
/// Split out so the geometry is testable independent of process env.
fn build_box(info: &LaunchInfo, pane_w: u16, pane_h: u16) -> Option<Vec<Line<'static>>> {
    let content = content_lines(info);
    let content_w = content.iter().map(Line::width).max().unwrap_or(0);
    let box_inner = content_w + INNER_PAD * 2;
    let box_w = box_inner + 2; // + 2 vertical rails
    let box_h = content.len() + 2; // + top/bottom borders
    if box_w > pane_w as usize || box_h > pane_h as usize {
        return None;
    }

    let left_pad = (pane_w as usize - box_w) / 2;
    let pad = || Span::raw(" ".repeat(left_pad));
    let accent = Style::default().fg(ACCENT);

    let mut out: Vec<Line<'static>> = Vec::with_capacity(box_h);
    out.push(Line::from(vec![
        pad(),
        Span::styled(format!("╭{}╮", "─".repeat(box_inner)), accent),
    ]));
    for line in content {
        let used = line.width();
        let trailing = content_w.saturating_sub(used);
        let mut spans = vec![
            pad(),
            Span::styled("│", accent),
            Span::raw(" ".repeat(INNER_PAD)),
        ];
        spans.extend(line.spans);
        spans.push(Span::raw(" ".repeat(trailing + INNER_PAD)));
        spans.push(Span::styled("│", accent));
        out.push(Line::from(spans));
    }
    out.push(Line::from(vec![
        pad(),
        Span::styled(format!("╰{}╯", "─".repeat(box_inner)), accent),
    ]));
    Some(out)
}

/// The header content lines (art + text), without border or centering.
/// Mirrors `welcome::header_lines` but as styled ratatui lines: the
/// welcome-name line shifts the text rows down by one when a name is
/// configured, leaving the two art-only rows as the art's natural
/// bottom padding.
fn content_lines(info: &LaunchInfo) -> Vec<Line<'static>> {
    let art = banner::render_styled_lines();
    let mut title = vec![
        Span::styled(APP_NAME, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!("v{}", info.version), Style::default().fg(GREY)),
    ];
    // Current session's short id, right after the version in the same grey
    // (session-id-short-display). The short id is assigned by the daemon at
    // attach, so it's absent until the TUI has connected; never fall back to
    // the full UUID.
    if let Some(short_id) = info.session_short_id.as_deref() {
        title.push(Span::raw("  "));
        title.push(Span::styled(
            short_id.to_string(),
            Style::default().fg(GREY),
        ));
    }
    let provider = vec![Span::styled(
        info.provider_line.clone(),
        Style::default().fg(GREY),
    )];
    // cwd + git-branch badge — identical to the persistent chrome's
    // status line, so the box matches it exactly.
    let path = chrome::status_line_spans(info);

    let texts: Vec<Option<Vec<Span<'static>>>> = match info.user_name.as_deref() {
        Some(name) if !name.is_empty() => {
            let welcome = vec![
                Span::styled("Welcome, ", Style::default().fg(GREY)),
                Span::styled(
                    name.to_string(),
                    Style::default().fg(GREY).add_modifier(Modifier::BOLD),
                ),
            ];
            vec![
                None,
                Some(title),
                Some(welcome),
                Some(provider),
                Some(path),
                None,
            ]
        }
        _ => vec![None, Some(title), Some(provider), Some(path), None, None],
    };

    let mut lines: Vec<Line<'static>> = art
        .into_iter()
        .zip(texts)
        .map(|(art_row, text)| {
            let mut spans = art_row;
            if let Some(t) = text {
                spans.push(Span::raw("   "));
                spans.extend(t);
            }
            Line::from(spans)
        })
        .collect();
    lines.push(Line::from(vec![
        Span::styled("Tip: ", Style::default().fg(GREY)),
        Span::styled(
            "/help",
            Style::default().fg(GREY).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" gets you oriented", Style::default().fg(GREY)),
    ]));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample(enabled: bool, name: Option<&str>) -> LaunchInfo {
        LaunchInfo {
            version: "9.9.9",
            session_id: None,
            session_short_id: None,
            provider_line: "anthropic / claude".to_string(),
            active_model: None,
            active_model_diverged: false,
            active_model_is_favorite: false,
            active_model_is_trusted: false,
            active_model_max_context: None,
            active_model_supports_images: false,
            cwd: PathBuf::from("/tmp/project"),
            cwd_display: "~/project".to_string(),
            repo_status: None,
            agent_name: "Build".to_string(),
            user_name: name.map(str::to_string),
            banner_enabled: enabled,
        }
    }

    fn joined(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn disabled_config_suppresses_box() {
        // enabled = false short-circuits regardless of env.
        assert!(build(&sample(false, None), 200, 50).is_none());
    }

    #[test]
    fn box_is_rectangular_and_bordered() {
        let lines = build_box(&sample(true, Some("Ada")), 200, 50).expect("fits a roomy pane");
        // 7 content rows + top/bottom border.
        assert_eq!(lines.len(), 9);
        // Every row renders to the same display width (centered box with
        // a shared left pad), so the right rail stays flush.
        let w0 = lines[0].width();
        for l in &lines {
            assert_eq!(l.width(), w0, "ragged box edge");
        }
        let top = joined(&lines[0]);
        let bottom = joined(&lines[8]);
        assert!(top.trim_start().starts_with('╭') && top.trim_end().ends_with('╮'));
        assert!(bottom.trim_start().starts_with('╰') && bottom.trim_end().ends_with('╯'));
    }

    #[test]
    fn name_adds_a_welcome_line() {
        let with = build_box(&sample(true, Some("Ada")), 200, 50).unwrap();
        let joined_all: String = with.iter().map(joined).collect::<Vec<_>>().join("\n");
        assert!(joined_all.contains("Welcome, Ada"));
        let without = build_box(&sample(true, None), 200, 50).unwrap();
        let joined_none: String = without.iter().map(joined).collect::<Vec<_>>().join("\n");
        assert!(!joined_none.contains("Welcome"));
    }

    #[test]
    fn session_id_shows_after_version_when_set() {
        // No short id set → the title line carries the version but no id.
        let none = build_box(&sample(true, None), 200, 50).unwrap();
        let joined_none: String = none.iter().map(joined).collect::<Vec<_>>().join("\n");
        assert!(joined_none.contains("v9.9.9"));

        // Short id set → it appears, right after the version, on the title row.
        let short_id = "k3m7qz";
        let mut info = sample(true, None);
        info.session_short_id = Some(short_id.to_string());
        let with = build_box(&info, 200, 50).unwrap();
        let title_row = with
            .iter()
            .map(joined)
            .find(|l| l.contains("v9.9.9"))
            .expect("title row");
        assert!(
            title_row.contains(short_id),
            "short id missing from title: {title_row:?}"
        );
        // Ordering: version precedes the short id on the same line.
        let vpos = title_row.find("v9.9.9").unwrap();
        let ipos = title_row.find(short_id).unwrap();
        assert!(vpos < ipos, "version should precede the session short id");
    }

    #[test]
    fn banner_includes_help_tip() {
        let lines = build_box(&sample(true, None), 200, 50).unwrap();
        let joined_all: String = lines.iter().map(joined).collect::<Vec<_>>().join("\n");

        assert!(
            joined_all.contains("Tip: /help gets you oriented"),
            "banner should advertise /help:\n{joined_all}"
        );
    }

    #[test]
    fn too_small_pane_skips_box() {
        // Skip (None) rather than clip, whether too narrow or too short.
        assert!(build_box(&sample(true, None), 10, 50).is_none());
        assert!(build_box(&sample(true, None), 200, 4).is_none());
    }
}
