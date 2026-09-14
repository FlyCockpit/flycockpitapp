//! TUI status line / chrome.
//!
//! The fixed path/git chrome and the async-schedule strip moved to the
//! three-row chat header (`crate::tui::chat_header`); agent/model/sandbox
//! pickers live on the composer bottom-border deck. This module keeps the
//! additive transient indicators (longcache, caffeination, lock wait, …).

use ratatui::style::{Color, Style};
use ratatui::text::Span;

#[cfg(feature = "remote")]
use crate::tui::theme::PLAN_YELLOW;
use crate::tui::theme::{MUTED_COLOR_INDEX, WARNING_TEXT};
#[cfg(feature = "remote")]
use cockpit_proto::{ConnectorDisclosure, OrgSyncDisclosure};

#[derive(Debug, Clone)]
pub struct LeftStatus {
    pub spans: Vec<Span<'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongcacheStatus {
    enabled: bool,
    supported: bool,
}

impl LongcacheStatus {
    pub const fn new(enabled: bool, supported: bool) -> Self {
        Self { enabled, supported }
    }
}

/// Bottom-left status: additive indicators that are not composer pills
/// (currently longcache). Agent, model, effort, approval, and sandbox live
/// on the composer bottom-border deck.
pub fn left_status(longcache: LongcacheStatus) -> LeftStatus {
    let LongcacheStatus {
        enabled: longcache_enabled,
        supported: longcache_supported,
    } = longcache;
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut col: u16 = 0;

    if longcache_enabled {
        let (label, style) = if longcache_supported {
            ("longcache".to_string(), muted)
        } else {
            (
                "longcache unsupported".to_string(),
                Style::default().fg(Color::Yellow),
            )
        };
        push_span(&mut spans, &mut col, Span::styled(label, style));
    }

    LeftStatus { spans }
}

fn push_span(spans: &mut Vec<Span<'static>>, col: &mut u16, span: Span<'static>) {
    *col = col.saturating_add(span.width() as u16);
    spans.push(span);
}

/// Persistent enterprise session-log sync disclosure. Rendered only while an
/// org policy mandates sync for this instance. Additive to the fixed chrome.
#[cfg(feature = "remote")]
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
#[cfg(feature = "remote")]
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
/// (`readlock-wait-and-lock-expiry.md` historical prompt slug). Rendered
/// **only** while a write/edit implicit acquire in this session is blocked on a
/// lock another agent/session holds — additive to the fixed chrome (cwd +
/// branch + context + active agent, GOALS §1a), never displacing a slot, the same pattern as the `☕`
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

#[cfg(test)]
mod tests {
    use super::*;

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
    #[cfg(feature = "remote")]
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
    fn left_status_omits_agent_model_and_sandbox() {
        let text: String = left_status(LongcacheStatus::new(false, true))
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!text.contains("Build"), "{text}");
        assert!(!text.contains("gpt-test"), "{text}");
        assert!(!text.contains("sandbox"), "{text}");
        assert!(!text.contains("compact"), "{text}");
        assert!(!text.contains("export"), "{text}");
        assert!(!text.contains("tools"), "{text}");
    }

    #[test]
    fn longcache_status_indicator_renders_supported_and_unsupported() {
        let off = left_status(LongcacheStatus::new(false, true));
        let off_text: String = off.spans.iter().map(|span| span.content.as_ref()).collect();
        assert!(!off_text.contains("longcache"), "{off_text}");

        let supported = left_status(LongcacheStatus::new(true, true));
        let supported_text: String = supported
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(supported_text.contains("longcache"), "{supported_text}");
        assert!(!supported_text.contains("unsupported"), "{supported_text}");

        let unsupported = left_status(LongcacheStatus::new(true, false));
        let unsupported_text: String = unsupported
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(
            unsupported_text.contains("longcache unsupported"),
            "{unsupported_text}"
        );
    }
}

#[cfg(all(test, feature = "remote"))]
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
