use super::*;

#[test]
fn colorterm_truecolor_detection() {
    assert!(colorterm_is_truecolor("truecolor"));
    assert!(colorterm_is_truecolor("24bit"));
    // Common combined / vendor-prefixed values still match.
    assert!(colorterm_is_truecolor("truecolor:24bit"));
    // Empty and non-truecolor values do not.
    assert!(!colorterm_is_truecolor(""));
    assert!(!colorterm_is_truecolor("256color"));
}

#[test]
fn rgb_downgrades_to_yellow_without_truecolor() {
    let plan = PLAN_YELLOW;
    // Truecolor terminal: the RGB passes through unchanged.
    assert_eq!(downgrade_for_terminal(plan, true), plan);
    // Non-truecolor terminal: the RGB falls back to ANSI yellow.
    assert_eq!(downgrade_for_terminal(plan, false), WARNING_TEXT);
    // Non-RGB palette entries pass through regardless of capability.
    assert_eq!(downgrade_for_terminal(Color::Cyan, false), Color::Cyan);
    assert_eq!(downgrade_for_terminal(Color::Cyan, true), Color::Cyan);
}

#[test]
fn commit_boundary_survives_open_fence() {
    let prefix = "safe paragraph\n\n";
    let text = format!("{prefix}```rust\nfn main() {{\n");

    assert_eq!(stable_pending_commit_byte(&text), prefix.len());
}

#[test]
fn commit_boundary_bails_on_line_initial_link_reference() {
    let text = "safe paragraph\n\n[ref]: https://example.com\nuse [ref]\n";

    assert_eq!(stable_pending_commit_byte(text), 0);

    let mut msg = PendingMsg {
        name: "Build".to_string(),
        text: String::new(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        started_at: std::time::Instant::now(),
        text_started_at: Some(std::time::Instant::now()),
        inside_think: false,
        body_started: true,
        tag_partial: String::new(),
        seq: None,
        strip_think: true,
    };
    let mut state = PendingRenderState::default();
    for chunk in text.as_bytes().chunks(11) {
        msg.text.push_str(std::str::from_utf8(chunk).unwrap());
        let incremental = render_pending_incremental(&msg, 72, &mut state);
        let full = render_pending(&msg, 72);
        assert_eq!(incremental, full);
    }
}

#[test]
fn commit_boundary_ignores_inline_bracket_colon() {
    let text = "safe paragraph\n\nmap[key]: value\n\n";

    assert_eq!(stable_pending_commit_byte(text), text.len());
}

#[test]
fn link_reference_definition_start_shape_is_position_aware() {
    assert!(is_link_reference_definition_start(
        "[ref]: https://example.com"
    ));
    assert!(is_link_reference_definition_start("   [ref]: target"));
    assert!(is_link_reference_definition_start("[a\\]]: target"));
    assert!(!is_link_reference_definition_start("    [ref]: code"));
    assert!(!is_link_reference_definition_start("prefix [ref]: target"));
    assert!(!is_link_reference_definition_start("[]: target"));
    assert!(!is_link_reference_definition_start("[a[b]: target"));
    assert!(!is_link_reference_definition_start("[ref] : target"));
}

/// `/export` serializes the live transcript as an ordered turns
/// array; tool calls carry the user-facing input (`full_input`) +
/// recovery `state`, never the wire form (GOALS §14).
#[test]
fn export_transcript_is_ordered_user_facing_turns() {
    let ts = chrono::Local::now();
    let history = vec![
        HistoryEntry::User {
            text: "do a thing".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: ts,
            seq: Some(1),
            preflight_pending: false,
            persist_failed: false,
        },
        HistoryEntry::Agent {
            name: "builder".to_string(),
            text: "on it".to_string(),
            reasoning: "thinking".to_string(),
            timestamp: ts,
            expanded: false,
            reasoning_offset: 0,
            think_duration: Some(Duration::from_millis(1200)),
            seq: Some(2),
        },
        HistoryEntry::ToolBox {
            calls: vec![ToolCall {
                call_id: "tc-1".to_string(),
                tool: "read".to_string(),
                // User-facing summary/input — NOT the wire path.
                summary: "a.rs".to_string(),
                full_input: "a.rs".to_string(),
                output: "fn main() {}".to_string(),
                expanded: false,
                result_offset: 0,
                state: ToolCallState::Success,
                hint: None,
                mcp_child: None,
            }],
            view_offset: 0,
            follow: true,
        },
    ];

    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr.len(), 3, "one turn per history entry, in order");
    assert_eq!(arr[0]["type"], "user");
    assert_eq!(arr[0]["text"], "do a thing");
    assert_eq!(arr[1]["type"], "assistant");
    assert_eq!(arr[1]["agent"], "builder");
    assert_eq!(arr[2]["type"], "tool_calls");
    let call = &arr[2]["calls"][0];
    assert_eq!(call["tool"], "read");
    // User-facing input + recovery state, never the wire form.
    assert_eq!(call["input"], "a.rs");
    assert_eq!(call["state"], "success");
    assert!(
        call.get("wire_input").is_none(),
        "the JSON export must never carry the wire form"
    );
}

/// A `/note` entry exports as a clearly-labeled `user_note` turn in its
/// chronological position (implementation note), distinct
/// from a normal `user` turn so `analyze-session-prompts` can pick it out.
#[test]
fn export_transcript_includes_user_note_in_order() {
    let ts = chrono::Local::now();
    let history = vec![
        HistoryEntry::User {
            text: "go".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: ts,
            seq: Some(1),
            preflight_pending: false,
            persist_failed: false,
        },
        HistoryEntry::UserNote {
            text: "remember the retry change broke it".to_string(),
            timestamp: ts,
        },
        HistoryEntry::Agent {
            name: "Build".to_string(),
            text: "ok".to_string(),
            reasoning: String::new(),
            timestamp: ts,
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq: Some(2),
        },
    ];
    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["type"], "user");
    // The note keeps its own distinct type + verbatim text, in place.
    assert_eq!(arr[1]["type"], "user_note");
    assert_eq!(arr[1]["text"], "remember the retry change broke it");
    assert!(arr[1].get("timestamp").is_some());
    assert_eq!(arr[2]["type"], "assistant");
}

#[test]
fn export_transcript_includes_interrupt_decision_rows() {
    let history = vec![HistoryEntry::InterruptDecision {
        decision: cockpit_core::daemon::proto::InterruptDecision {
            permission: false,
            cancelled: true,
            lines: vec![cockpit_core::daemon::proto::InterruptDecisionLine {
                prompt: "Proceed?".to_string(),
                answer: "No".to_string(),
            }],
        },
    }];

    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr[0]["type"], "interrupt_decision");
    assert_eq!(arr[0]["cancelled"], true);
    assert_eq!(arr[0]["lines"][0]["prompt"], "Proceed?");
}

#[test]
fn interrupt_decision_renders_as_dedicated_styled_dismissed_row() {
    let entry = HistoryEntry::InterruptDecision {
        decision: cockpit_core::daemon::proto::InterruptDecision {
            permission: true,
            cancelled: true,
            lines: vec![cockpit_core::daemon::proto::InterruptDecisionLine {
                prompt: "Run command?".to_string(),
                answer: "Allow".to_string(),
            }],
        },
    };

    let rendered = render_entry(
        &entry,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );

    assert_eq!(rendered.lines.len(), 1);
    assert_eq!(
        line_text(&rendered.lines[0]),
        "  approval: Run command? → dismissed"
    );
    let spans = &rendered.lines[0].spans;
    assert_eq!(spans[1].style.add_modifier, Modifier::BOLD);
    assert_eq!(spans[5].content.as_ref(), "dismissed");
    assert_eq!(spans[5].style.fg, Some(WARNING_TEXT));
    assert_eq!(spans[5].style.add_modifier, Modifier::BOLD);
}

#[test]
fn export_transcript_distinguishes_inference_warning_from_backup_warning() {
    let history = vec![
        HistoryEntry::InferenceWarning {
            line: "local/slow has not produced another token after 1s. Press Ctrl+C to cancel."
                .to_string(),
        },
        HistoryEntry::BackupWarning {
            line: "primary `q` failed (timeout) — answered with backup `c`.".to_string(),
        },
    ];
    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr[0]["type"], "inference_warning");
    assert_eq!(arr[1]["type"], "backup_warning");
}

#[test]
fn export_transcript_includes_inference_error_summary_and_detail() {
    let history = vec![HistoryEntry::InferenceError {
        summary: "Inference failed (p/m): network: first line".to_string(),
        detail: "first line\nrequest id: abc".to_string(),
        expanded: false,
    }];
    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr[0]["type"], "inference_error");
    assert_eq!(
        arr[0]["text"],
        "Inference failed (p/m): network: first line"
    );
    assert_eq!(
        arr[0]["summary"],
        "Inference failed (p/m): network: first line"
    );
    assert_eq!(arr[0]["detail"], "first line\nrequest id: abc");
}

#[test]
fn inference_error_collapsed_and_expanded_render_clickable_rows() {
    let collapsed = HistoryEntry::InferenceError {
        summary: "Inference failed (p/m): network: first line".to_string(),
        detail: "first line\nsecond line".to_string(),
        expanded: false,
    };
    let r = render_entry(
        &collapsed,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert_eq!(r.lines.len(), 1);
    assert_eq!(
        line_text(&r.lines[0]),
        "Inference failed (p/m): network: first line"
    );
    assert_eq!(r.chip_row, Some(0));
    assert!(
        r.lines[0]
            .spans
            .iter()
            .any(|s| s.style.fg == Some(ERROR_TEXT))
    );

    let expanded = HistoryEntry::InferenceError {
        summary: "Inference failed (p/m): network: first line".to_string(),
        detail: "first line\nsecond line".to_string(),
        expanded: true,
    };
    let r = render_entry(
        &expanded,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert_eq!(r.chip_row, Some(0));
    let text = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(text.contains("Inference failed (p/m)"));
    assert!(text.contains("second line"));
}

#[test]
fn inference_error_without_detail_expands_to_safe_placeholder() {
    let entry = HistoryEntry::InferenceError {
        summary: "Inference failed: timeout".to_string(),
        detail: String::new(),
        expanded: true,
    };
    let r = render_entry(
        &entry,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    let text = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(text.contains("No additional inference detail was recorded."));
}

#[test]
fn export_transcript_keeps_command_error_distinct() {
    let history = vec![HistoryEntry::CommandError {
        line: "/resume: could not attach to session: missing".to_string(),
    }];
    let v = export_transcript(&history);
    let arr = v.as_array().expect("turns array");
    assert_eq!(arr[0]["type"], "command_error");
    assert_eq!(
        arr[0]["text"],
        "/resume: could not attach to session: missing"
    );
}

/// The user-note row renders as a distinct "note to self" block — not a
/// rounded user bubble and not assistant output — with the full (wrapping)
/// note text present.
#[test]
fn render_user_note_is_a_distinct_labeled_row() {
    let entry = HistoryEntry::UserNote {
        text: "alpha beta gamma delta epsilon zeta eta theta".to_string(),
        timestamp: chrono::Local::now(),
    };
    let r = render_entry(
        &entry,
        40,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &HashSet::new(),
        0,
        None,
    );
    let joined: String = r
        .lines
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
        .collect::<Vec<_>>()
        .join("");
    assert!(
        joined.contains("note to self"),
        "carries the distinct label"
    );
    // No rounded user-bubble border glyphs (that's a normal user message).
    assert!(!joined.contains('╭') && !joined.contains('╰'));
    // The full note text is present (wrapped across rows).
    assert!(joined.contains("alpha"));
    assert!(joined.contains("theta"));
}

#[test]
fn plain_and_maintenance_lines_are_indented_and_muted() {
    for entry in [
        HistoryEntry::Plain {
            line: "daemon: spawned".to_string(),
        },
        HistoryEntry::Maintenance {
            line: "maintenance note".to_string(),
        },
    ] {
        let r = render_entry(
            &entry,
            80,
            ThinkingDisplay::Condensed,
            MarkdownOpts::default(),
            cockpit_config::extended::DiffStyle::default(),
            false,
            &HashSet::new(),
            0,
            None,
        );
        assert_eq!(r.lines.len(), 1);
        let text = line_text(&r.lines[0]);
        assert!(
            text.starts_with(&" ".repeat(AGENT_INDENT)),
            "system line should share the transcript indent: {text:?}"
        );
        assert!(
            r.lines[0]
                .spans
                .iter()
                .any(|span| !span.content.trim().is_empty() && span.style.fg == Some(INFO_TEXT)),
            "system text should use muted foreground"
        );
    }
}

#[test]
fn semantic_warning_and_error_colors_are_not_muted() {
    let entries = [
        (
            HistoryEntry::CommandError {
                line: "bad command".to_string(),
            },
            ERROR_TEXT,
        ),
        (
            HistoryEntry::BackupWarning {
                line: "backup warning".to_string(),
            },
            WARNING_TEXT,
        ),
        (
            HistoryEntry::InferenceWarning {
                line: "slow model".to_string(),
            },
            WARNING_TEXT,
        ),
        (
            HistoryEntry::InferenceError {
                summary: "Inference failed".to_string(),
                detail: String::new(),
                expanded: false,
            },
            ERROR_TEXT,
        ),
    ];

    for (entry, expected) in entries {
        let r = render_entry(
            &entry,
            80,
            ThinkingDisplay::Condensed,
            MarkdownOpts::default(),
            cockpit_config::extended::DiffStyle::default(),
            false,
            &HashSet::new(),
            0,
            None,
        );
        assert!(
            r.lines[0]
                .spans
                .iter()
                .any(|span| span.style.fg == Some(expected)),
            "semantic entry should retain {expected:?}: {:?}",
            line_text(&r.lines[0])
        );
    }
}

#[test]
#[rustfmt::skip]
fn timestamp_helpers_keep_right_margin() {
    let width: u16 = 40;
    let line =
        render_first_line_timestamped(vec![Span::raw("  body")], fixed_ts(), width, true);
    let text = line_text(&line);
    assert_eq!(line_width(&line), width as usize);
    let ts_start = text
        .char_indices()
        .find_map(|(idx, ch)| (ch == ':').then_some(idx.saturating_sub(2)))
        .expect("timestamp present");
    assert_eq!(
        ts_start + TIMESTAMP_WIDTH,
        width as usize - TIMESTAMP_RIGHT_MARGIN
    );
    assert_eq!(
        text.chars()
            .rev()
            .take(TIMESTAMP_RIGHT_MARGIN)
            .collect::<String>(),
        " ".repeat(TIMESTAMP_RIGHT_MARGIN)
    );
}

#[test]
fn dots_cycle_four_phases() {
    assert_eq!(thinking_dots(0), "");
    assert_eq!(thinking_dots(333), ".");
    assert_eq!(thinking_dots(700), "..");
    assert_eq!(thinking_dots(1000), "...");
    // phase 4 wraps to ""
    assert_eq!(thinking_dots(333 * 4), "");
}

#[test]
fn format_duration_human_readable() {
    assert_eq!(
        format_think_duration(Duration::from_millis(500)),
        "<1 second"
    );
    assert_eq!(
        format_think_duration(Duration::from_millis(1500)),
        "1.5 seconds"
    );
    assert_eq!(format_think_duration(Duration::from_secs(7)), "7.0 seconds");
    assert_eq!(format_think_duration(Duration::from_secs(45)), "45 seconds");
    assert_eq!(format_think_duration(Duration::from_secs(134)), "2m 14s");
}

#[test]
fn padded_dots_are_always_width_three() {
    for ms in [0u128, 333, 700, 1000] {
        assert_eq!(thinking_dots_padded(ms).chars().count(), 3);
    }
    assert_eq!(thinking_dots_padded(0), "   ");
    assert_eq!(thinking_dots_padded(1000), "...");
}

#[test]
fn status_elapsed_switches_to_minutes_at_sixty_seconds() {
    assert_eq!(format_status_elapsed(Duration::from_secs(0)), "(0s)");
    assert_eq!(format_status_elapsed(Duration::from_secs(5)), "(5s)");
    assert_eq!(format_status_elapsed(Duration::from_secs(59)), "(59s)");
    assert_eq!(format_status_elapsed(Duration::from_secs(60)), "(1m 0s)");
    assert_eq!(format_status_elapsed(Duration::from_secs(134)), "(2m 14s)");
    // Sub-second is floored, not rounded up.
    assert_eq!(format_status_elapsed(Duration::from_millis(1900)), "(1s)");
}

#[test]
fn wrap_handles_short_lines() {
    let chunks = wrap_with_reserved_first_line("hi there", 40, 6);
    assert_eq!(chunks, vec!["hi there".to_string()]);
}

#[test]
fn wrap_breaks_when_first_line_would_overlap_timestamp() {
    // area=20, reserve=6 → first line gets 14 chars
    let chunks = wrap_with_reserved_first_line("hello world how are you today", 20, 6);
    // First chunk fits in 14, rest wraps to 20-wide.
    assert!(chunks[0].chars().count() <= 14);
}

fn line_text(line: &Line<'static>) -> String {
    line.spans
        .iter()
        .map(|s| s.content.as_ref())
        .collect::<String>()
}

fn line_width(line: &Line<'static>) -> usize {
    UnicodeWidthStr::width(line_text(line).as_str())
}

fn spans_text(spans: &[Span<'static>]) -> String {
    spans.iter().map(|s| s.content.as_ref()).collect::<String>()
}

fn spans_width(spans: &[Span<'static>]) -> usize {
    UnicodeWidthStr::width(spans_text(spans).as_str())
}

fn fixed_ts() -> DateTime<Local> {
    // Any concrete instant works — only the formatted "HH:MM"
    // width matters for these tests.
    Local::now()
}

fn assert_user_border_fg(lines: &[Line<'static>], expected: Color) {
    let border_chars = ['╭', '─', '╮', '│', '╰', '╯'];
    let mut styled_border_spans = 0;
    for line in lines {
        for span in &line.spans {
            if span.content.chars().any(|ch| border_chars.contains(&ch)) {
                assert_eq!(span.style.fg, Some(expected), "border span {span:?}");
                styled_border_spans += 1;
            }
        }
    }
    assert!(styled_border_spans >= 4, "expected styled border spans");
}

#[test]
fn failed_user_bubble_recolors_border_without_adding_chip_or_rows() {
    let ts = fixed_ts();
    let (normal, _) = render_user("hello", ts, 60, false, None, false, None);
    let (failed, _) = render_user("hello", ts, 60, false, None, true, None);

    assert_eq!(failed.len(), normal.len());
    assert_eq!(
        failed.iter().map(line_text).collect::<Vec<_>>(),
        normal.iter().map(line_text).collect::<Vec<_>>()
    );
    assert!(
        failed
            .iter()
            .all(|line| !line_text(line).contains("send failed")),
        "failed bubble should not render a failure chip"
    );
    assert_user_border_fg(&normal, USER_BORDER_FG);
    assert_user_border_fg(&failed, ERROR_TEXT);
}

#[test]
fn user_top_border_draws_fork_left_of_pin_and_drops_fork_first() {
    let ctrl = PinControl {
        seq: 42,
        pinned: false,
        show_control: true,
        is_pick: false,
    };

    let (wide, wide_region) = user_top_border(20, Style::default(), Some(ctrl), 3);
    let wide_text = line_text(&Line::from(wide));
    assert_eq!(wide_text, "╭────────[fork]─[pin]╮");
    let wide_region = wide_region.expect("wide border records controls");
    assert_eq!(wide_region.fork_col_start, Some(11));
    assert_eq!(wide_region.fork_col_end, Some(17));
    assert_eq!((wide_region.col_start, wide_region.col_end), (18, 23));

    let (pin_only, pin_only_region) = user_top_border(12, Style::default(), Some(ctrl), 3);
    let pin_only_text = line_text(&Line::from(pin_only));
    assert_eq!(pin_only_text, "╭───────[pin]╮");
    let pin_only_region = pin_only_region.expect("pin survives narrow fallback");
    assert_eq!(pin_only_region.fork_col_start, None);
    assert_eq!(pin_only_region.fork_col_end, None);
    assert_eq!(pin_only_region.col_end - pin_only_region.col_start, 5);

    let (too_narrow, too_narrow_region) = user_top_border(5, Style::default(), Some(ctrl), 3);
    assert_eq!(line_text(&Line::from(too_narrow)), "╭─────╮");
    assert!(too_narrow_region.is_none());
}

#[test]
fn failed_user_markdown_recolors_left_bar_without_adding_chip_or_rows() {
    let ts = fixed_ts();
    let (normal, _) = render_user("**hello**", ts, 60, true, None, false, None);
    let (failed, _) = render_user("**hello**", ts, 60, true, None, true, None);

    assert_eq!(failed.len(), normal.len());
    assert_eq!(
        failed.iter().map(line_text).collect::<Vec<_>>(),
        normal.iter().map(line_text).collect::<Vec<_>>()
    );
    assert_eq!(normal[0].spans[0].content.as_ref(), "│ ");
    assert_eq!(normal[0].spans[0].style.fg, Some(USER_BORDER_FG));
    assert_eq!(failed[0].spans[0].content.as_ref(), "│ ");
    assert_eq!(failed[0].spans[0].style.fg, Some(ERROR_TEXT));
}

#[test]
fn failed_user_entry_has_no_chip_target() {
    let entry = HistoryEntry::User {
        text: "hello".to_string(),
        cleaned: None,
        expanded: false,
        timestamp: fixed_ts(),
        seq: None,
        preflight_pending: false,
        persist_failed: true,
    };
    let rendered = render_entry(
        &entry,
        60,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &HashSet::new(),
        0,
        None,
    );

    assert_eq!(rendered.chip_row, None);
    assert!(
        rendered
            .lines
            .iter()
            .all(|line| !line_text(line).contains("send failed"))
    );
    assert_user_border_fg(&rendered.lines, ERROR_TEXT);
}

#[test]
fn agent_timestamp_stays_anchored_when_text_would_overlap() {
    // A long single-paragraph reply with no reasoning + no markdown.
    // Width 60 → text budget for first line is 60 - 2 (indent) - 5
    // (timestamp) - 1 (gap) = 52. The renderer must wrap before
    // that so the first row never exceeds the area width.
    let text = "x".repeat(200);
    let width: u16 = 60;
    let rendered = render_agent(
        "builder",
        &text,
        "",
        fixed_ts(),
        false,
        0,
        None,
        width,
        false,
        None,
    );
    assert!(!rendered.lines.is_empty());
    // The first line carries the timestamp and must fit in `width`
    // so ratatui's auto-wrap can't push the timestamp to row 2.
    assert!(
        line_width(&rendered.lines[0]) <= width as usize,
        "row 1 width = {}, area = {}",
        line_width(&rendered.lines[0]),
        width
    );
}

#[test]
fn collapsed_chip_does_not_push_timestamp_off_row_one() {
    // Reasoning present + collapsed → chip label + " " + first
    // chunk + " " + timestamp must all fit in `width`.
    let width: u16 = 80;
    let rendered = render_agent(
        "builder",
        &"a ".repeat(200),
        "some hidden reasoning",
        fixed_ts(),
        /* expanded */ false,
        0,
        Some(Duration::from_secs(3)),
        width,
        /* markdown */ false,
        None,
    );
    assert!(line_width(&rendered.lines[0]) <= width as usize);
}

#[test]
fn expanded_short_reasoning_renders_without_window_ui() {
    let reasoning = "r0\nr1\nr2";
    let rendered = render_agent(
        "builder",
        "final answer",
        reasoning,
        fixed_ts(),
        true,
        0,
        None,
        80,
        false,
        None,
    );
    let text = rendered
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("r0"));
    assert!(text.contains("r1"));
    assert!(text.contains("r2"));
    assert!(text.contains("final answer"));
    assert!(!text.contains("more below"));
    assert!(rendered.reasoning_scroll_region.is_none());
}

#[test]
fn expanded_long_reasoning_windows_and_keeps_answer_after_it() {
    let reasoning = (0..25)
        .map(|idx| format!("r{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let rendered = render_agent(
        "builder",
        "final answer",
        &reasoning,
        fixed_ts(),
        true,
        0,
        None,
        80,
        false,
        None,
    );
    let text = rendered
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("r0"));
    assert!(text.contains("r19"));
    assert!(!text.contains("r20"));
    assert!(text.contains("5 more below"));
    assert!(text.contains("final"));
    assert!(text.contains("answer"));
    let region = rendered
        .reasoning_scroll_region
        .expect("long reasoning scroll region");
    assert_eq!(region.offset, 0);
    assert_eq!(region.max_offset, 5);
}

#[test]
fn expanded_long_reasoning_offset_clamps_and_shows_more_above() {
    let reasoning = (0..25)
        .map(|idx| format!("r{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let rendered = render_agent(
        "builder",
        "final answer",
        &reasoning,
        fixed_ts(),
        true,
        99,
        None,
        80,
        false,
        None,
    );
    let text = rendered
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("5 more above"));
    assert!(text.contains("r5"));
    assert!(text.contains("r24"));
    assert!(!text.contains("more below"));
    let region = rendered
        .reasoning_scroll_region
        .expect("long reasoning scroll region");
    assert_eq!(region.offset, 5);
    assert_eq!(region.max_offset, 5);
}

#[test]
fn expanded_long_wrapped_reasoning_windows_by_display_rows() {
    let reasoning = "word ".repeat(80);
    let rendered = render_agent(
        "builder",
        "final answer",
        &reasoning,
        fixed_ts(),
        true,
        0,
        None,
        12,
        false,
        None,
    );
    let text = rendered
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("more below"));
    assert!(text.contains("final"));
    assert!(text.contains("answer"));
    let region = rendered
        .reasoning_scroll_region
        .expect("wrapped reasoning scroll region");
    assert_eq!(region.offset, 0);
    assert_eq!(region.row_end - region.row_start + 1, THINKING_VISIBLE + 1);
}

#[test]
#[rustfmt::skip]
fn agent_markdown_first_line_has_no_timestamp_orphan() {
    // Regression: the no-reasoning + markdown path used to wrap the
    // body to the full content width, then slice the first row for
    // the timestamp *after* — pushing the trailing word(s) onto row
    // 2 as a standalone orphan with the paragraph's real continuation
    // already on row 3. The fix reserves the timestamp width on the
    // first visual row *before* wrapping, so row 2 fills the width.
    let text =
        "one two three four five six seven eight nine ten eleven twelve thirteen fourteen";
    let width: u16 = 40;
    let rendered = render_agent(
        "builder",
        text,
        "",
        fixed_ts(),
        false,
        0,
        None,
        width,
        true,
        None,
    );
    assert!(rendered.lines.len() >= 3, "long text must wrap >= 3 rows");
    // Row 1 carries the timestamp and must fit inside the area.
    assert!(
        line_width(&rendered.lines[0]) <= width as usize,
        "row 1 width = {}, area = {}",
        line_width(&rendered.lines[0]),
        width
    );
    // Row 2 must be a real, full continuation — not a one-word
    // orphan that is far shorter than row 1's text-equivalent budget.
    // body_content_w = 40 - 4 = 36; first row reserves 6 → 30 cells
    // of text. A genuine wrapped row 2 should be much wider than a
    // single leftover word.
    let row2_text: String = rendered.lines[1]
        .spans
        .iter()
        .map(|s| s.content.as_ref())
        .collect::<String>();
    let row2_words = row2_text.split_whitespace().count();
    assert!(
        row2_words >= 2,
        "row 2 should fill the width, not be a one-word orphan; got {row2_words} word(s): {row2_text:?}"
    );
    // Row 2 is a soft-wrap continuation of the first logical line, so
    // the copy path must rejoin it with a space (cont = true).
    assert!(
        rendered.continuations[1],
        "row 2 must be marked a soft-wrap continuation"
    );
}

#[test]
fn wrap_reserving_first_narrows_only_first_visual_row() {
    // One logical line longer than the reserved-first budget: the
    // first visual row wraps at max_width - reserve_first, the rest
    // (continuations of the SAME logical line) wrap at full max_width
    // and are flagged as continuations.
    let lines = vec![Line::from(vec![Span::raw(
        "alpha beta gamma delta epsilon zeta eta theta iota kappa".to_string(),
    )])];
    let (wrapped, conts) = wrap_lines_to_width_reserving_first(lines, 20, 6);
    assert!(wrapped.len() >= 2, "must wrap");
    // First visual row constrained to 20 - 6 = 14.
    assert!(line_width(&wrapped[0]) <= 14);
    // Subsequent rows use the full 20.
    assert!(line_width(&wrapped[1]) <= 20);
    // Every row after the first is a continuation of the same line.
    assert!(!conts[0]);
    assert!(conts[1..].iter().all(|&c| c));
}

#[test]
fn slice_spans_breaks_on_whitespace_when_possible() {
    let spans = vec![Span::raw("hello world how are you today".to_string())];
    let (head, tail) = slice_spans_at_width(spans, 14);
    let head_text: String = head.iter().map(|s| s.content.to_string()).collect();
    assert!(head_text.chars().count() <= 14);
    // "hello world " is 12 chars and breaks on a whitespace ≤ 14.
    assert!(head_text.ends_with(' '));
    assert!(tail.is_some());
}

#[test]
fn slice_spans_preserves_styles_across_split() {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    // No whitespace inside the bold span and the split lands in
    // the middle of it, so the bold style must appear on both
    // halves after grouping.
    let spans = vec![
        Span::raw("ab".to_string()),
        Span::styled("BOLDEDTOKEN".to_string(), bold),
        Span::raw("cd".to_string()),
    ];
    let (head, tail) = slice_spans_at_width(spans, 6);
    let tail = tail.expect("has tail");
    assert!(head.iter().any(|s| s.style == bold));
    assert!(tail.iter().any(|s| s.style == bold));
}

#[test]
fn slice_spans_wide_chars_no_panic() {
    let spans = vec![Span::raw("你好你好".to_string())];
    let (head, tail) = slice_spans_at_width(spans, 6);

    assert!(spans_width(&head) <= 6);
    assert!(tail.is_some());
}

#[test]
fn slice_spans_wide_chars_head_within_budget() {
    for max_width in [4usize, 5, 6, 7, 8] {
        let spans = vec![Span::raw("ab你好cd你好".to_string())];
        let (head, tail) = slice_spans_at_width(spans, max_width);

        assert!(
            spans_width(&head) <= max_width,
            "head {:?} exceeded width {max_width}",
            spans_text(&head)
        );
        assert!(tail.is_some(), "expected tail for width {max_width}");
    }
}

#[test]
fn slice_spans_single_wide_grapheme_makes_progress() {
    let spans = vec![Span::raw("好".to_string())];
    let (head, tail) = slice_spans_at_width(spans, 1);

    assert_eq!(spans_text(&head), "好");
    assert_eq!(spans_width(&head), 2);
    assert!(tail.is_none());
}

#[test]
fn slice_spans_wide_emoji_no_panic() {
    let spans = vec![Span::raw("🚀🚀🚀".to_string())];
    let (head, tail) = slice_spans_at_width(spans, 4);

    assert!(spans_width(&head) <= 4);
    assert!(tail.is_some());
}

#[test]
fn wrap_reserving_first_terminates_on_wide_line() {
    let lines = vec![Line::from(vec![Span::raw("你好你好".to_string())])];
    let (wrapped, conts) = wrap_lines_to_width_reserving_first(lines, 6, 4);

    assert!(!wrapped.is_empty());
    assert_eq!(wrapped.len(), conts.len());
    assert!(!conts[0]);
    for (i, line) in wrapped.iter().enumerate() {
        let budget = if i == 0 { 2 } else { 6 };
        let width = line_width(line);
        assert!(
            width <= budget || line_text(line).chars().count() == 1,
            "row {i} width {width} exceeded budget {budget}: {:?}",
            line_text(line)
        );
    }
}

// ── tool box ──────────────────────────────────────────────────────

fn mk_call(tool: &str, summary: &str, state: ToolCallState) -> ToolCall {
    ToolCall {
        call_id: "id".into(),
        tool: tool.into(),
        summary: summary.into(),
        full_input: summary.into(),
        output: String::new(),
        expanded: false,
        result_offset: 0,
        state,
        hint: None,
        mcp_child: None,
    }
}

fn mcp_child_meta(
    parent_call_id: &str,
    index: i64,
    server: Option<&str>,
    builtin: Option<bool>,
    kind: &str,
) -> McpChildMeta {
    McpChildMeta {
        parent_call_id: parent_call_id.to_string(),
        parent_child_index: index,
        server: server.map(str::to_string),
        builtin,
        kind: Some(kind.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
fn child_call(
    parent_call_id: &str,
    index: i64,
    server: Option<&str>,
    builtin: Option<bool>,
    kind: &str,
    tool: &str,
    args: serde_json::Value,
    output: &str,
    state: ToolCallState,
) -> ToolCall {
    let meta = mcp_child_meta(parent_call_id, index, server, builtin, kind);
    let presentation = resolve_tool_presentation(tool, &args, Some(&meta));
    ToolCall {
        call_id: format!("{parent_call_id}:mcp:{index}"),
        tool: tool.to_string(),
        summary: presentation.summary,
        full_input: presentation.full_input,
        output: output.to_string(),
        expanded: kind == "invoke",
        result_offset: 0,
        state,
        hint: None,
        mcp_child: Some(meta),
    }
}

fn rendered_text(rendered: &Rendered) -> Vec<String> {
    rendered.lines.iter().map(line_text).collect()
}

/// No wire-side elisions — the default for tests that don't exercise
/// the prune-dimming path.
fn no_elided() -> HashSet<String> {
    HashSet::new()
}

#[test]
fn render_toolbox_smoke() {
    let calls = vec![mk_call("bash", "echo ok", ToolCallState::Success)];
    let rendered = render_toolbox(&calls, 0, true, 80, false, &no_elided());

    assert_eq!(line_text(&rendered.lines[0]), "│ bash: echo ok");
}

#[test]
fn builtin_child_renders_as_first_class_tool_call() {
    let parent = mk_call("mcp", "script=\"opaque python\"", ToolCallState::Success);
    let child = child_call(
        &parent.call_id,
        0,
        Some("cockpit"),
        Some(true),
        "invoke",
        "rename_session",
        serde_json::json!({
            "server": "cockpit",
            "tool": "rename_session",
            "args": { "name": "Test session" }
        }),
        "{\"renamed\":true}",
        ToolCallState::Success,
    );

    let lines = rendered_text(&render_toolbox(
        &[parent, child],
        0,
        true,
        100,
        false,
        &no_elided(),
    ));

    assert!(
        lines
            .iter()
            .any(|line| line.contains("rename_session: name=\"Test session\"")),
        "{lines:?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("mcp: cockpit.rename_session")),
        "{lines:?}"
    );
}

#[test]
fn external_child_renders_as_mcp_call() {
    let parent = mk_call("mcp", "script=\"opaque python\"", ToolCallState::Success);
    let child = child_call(
        &parent.call_id,
        0,
        Some("github"),
        Some(false),
        "invoke",
        "create_issue",
        serde_json::json!({
            "server": "github",
            "tool": "create_issue",
            "args": { "title": "Bug" }
        }),
        "{\"number\":1234}",
        ToolCallState::Success,
    );

    let lines = rendered_text(&render_toolbox(
        &[parent, child],
        0,
        true,
        100,
        false,
        &no_elided(),
    ));

    assert!(
        lines
            .iter()
            .any(|line| line.contains("mcp: github.create_issue")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line == "│   title=\"Bug\""),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("create_issue:")),
        "{lines:?}"
    );
}

#[test]
fn builtin_functions_have_glyph_and_label_entries() {
    let presentations = cockpit_core::mcp::builtin::builtin_presentations();
    for name in ["rename_session", "request_compact", "context_usage"] {
        let Some((_name, presentation)) = presentations
            .iter()
            .find(|(candidate, _)| *candidate == name)
        else {
            panic!("{name} missing from builtin presentation registry");
        };
        assert!(!presentation.glyph.is_empty(), "{name} missing glyph");
        assert_eq!(presentation.label, name);
    }
}

#[test]
fn mcp_call_without_children_renders_as_today() {
    let call = mk_call(
        "mcp",
        "script=\"mcp.invoke(\"cockpit\", \"rename_session\", {\"name\": \"Test session\"})\"",
        ToolCallState::Success,
    );

    let lines = rendered_text(&render_toolbox(&[call], 0, true, 120, false, &no_elided()));

    assert_eq!(
        lines,
        vec![
            "│ mcp: script=\"mcp.invoke(\"cockpit\", \"rename_session\", {\"name\": \"Test session\"})\""
                .to_string()
        ]
    );
}

#[test]
fn search_and_describe_children_collapse_by_default() {
    let parent = mk_call("mcp", "script=\"mcp work\"", ToolCallState::Success);
    let search = child_call(
        &parent.call_id,
        0,
        None,
        None,
        "search",
        "mcp.search",
        serde_json::json!({ "query": "issues" }),
        "search output should be hidden",
        ToolCallState::Success,
    );
    let describe = child_call(
        &parent.call_id,
        1,
        Some("github"),
        Some(false),
        "describe",
        "create_issue",
        serde_json::json!({ "server": "github", "tool": "create_issue" }),
        "describe output should be hidden",
        ToolCallState::Success,
    );
    let invoke = child_call(
        &parent.call_id,
        2,
        Some("github"),
        Some(false),
        "invoke",
        "create_issue",
        serde_json::json!({ "server": "github", "tool": "create_issue", "args": {"title": "Bug"} }),
        "invoke output is visible",
        ToolCallState::Success,
    );

    assert!(!search.expanded);
    assert!(!describe.expanded);
    assert!(invoke.expanded);
    let lines = rendered_text(&render_toolbox(
        &[parent, search, describe, invoke],
        0,
        true,
        100,
        false,
        &no_elided(),
    ));

    assert!(
        lines
            .iter()
            .any(|line| line.contains("search query=\"issues\""))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("describe github.create_issue"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("invoke output is visible"))
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("search output should be hidden"))
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("describe output should be hidden"))
    );
}

#[test]
fn failed_child_shows_failure_and_reason() {
    let parent = mk_call("mcp", "script=\"mcp work\"", ToolCallState::Success);
    let mut failed = child_call(
        &parent.call_id,
        0,
        Some("cockpit"),
        Some(true),
        "invoke",
        "rename_session",
        serde_json::json!({
            "server": "cockpit",
            "tool": "rename_session",
            "args": { "name": "Blocked" }
        }),
        "builtin MCP tool `cockpit.rename_session` is not available",
        ToolCallState::BadCall,
    );
    failed.expanded = true;
    let success = child_call(
        &parent.call_id,
        1,
        Some("cockpit"),
        Some(true),
        "invoke",
        "context_usage",
        serde_json::json!({ "server": "cockpit", "tool": "context_usage", "args": {} }),
        "{\"snapshot\":\"turn_start\"}",
        ToolCallState::Success,
    );

    let rendered = render_toolbox(
        &[parent, failed, success],
        0,
        true,
        100,
        false,
        &no_elided(),
    );
    let lines = rendered_text(&rendered);

    assert!(
        lines
            .iter()
            .any(|line| line.contains("rename_session: name=\"Blocked\""))
    );
    assert!(lines.iter().any(|line| line.contains("not available")));
    assert!(lines.iter().any(|line| line.contains("context_usage:")));
    let failed_header = rendered
        .lines
        .iter()
        .find(|line| line_text(line).contains("rename_session:"))
        .expect("failed child header");
    assert!(
        failed_header
            .spans
            .iter()
            .any(|span| span.style.add_modifier.contains(Modifier::BOLD)),
        "{failed_header:?}"
    );
}

#[test]
fn sidebar_glyphs_correct_with_children() {
    let parent = mk_call("mcp", "script=\"mcp work\"", ToolCallState::Success);
    let child = child_call(
        &parent.call_id,
        0,
        Some("cockpit"),
        Some(true),
        "invoke",
        "context_usage",
        serde_json::json!({ "server": "cockpit", "tool": "context_usage", "args": {} }),
        "{}",
        ToolCallState::Success,
    );
    let lines = rendered_text(&render_toolbox(
        &[parent, child],
        0,
        true,
        100,
        false,
        &no_elided(),
    ));

    assert!(lines.first().unwrap().starts_with('╭'), "{lines:?}");
    assert!(lines.last().unwrap().starts_with('╰'), "{lines:?}");
    for line in lines.iter().skip(1).take(lines.len().saturating_sub(2)) {
        assert!(line.starts_with('│'), "{lines:?}");
    }

    let single = rendered_text(&render_toolbox(
        &[mk_call("bash", "ls", ToolCallState::Success)],
        0,
        true,
        80,
        false,
        &no_elided(),
    ));
    assert!(single[0].starts_with('│'), "{single:?}");
}

#[test]
fn child_summary_budget_uses_child_prefix_width() {
    let parent = mk_call("mcp", "script=\"mcp work\"", ToolCallState::Success);
    let child = child_call(
        &parent.call_id,
        0,
        Some("github"),
        Some(false),
        "invoke",
        "create_issue",
        serde_json::json!({ "server": "github", "tool": "create_issue", "args": {"title": "A very long issue title"} }),
        "{}",
        ToolCallState::Success,
    );

    let parent_budget = tool_call_summary_budget(&parent, 40, 2, false);
    let child_budget = tool_call_summary_budget(&child, 40, 4, false);

    assert!(child_budget < parent_budget);
}

#[test]
fn truncated_children_are_announced() {
    let parent = mk_call("mcp", "script=\"mcp work\"", ToolCallState::Success);
    let cap = child_call(
        &parent.call_id,
        50,
        None,
        None,
        "cap",
        "mcp.child_events_truncated",
        serde_json::json!({ "unrecorded_dispatches": 7 }),
        "{\"message\":\"7 further MCP dispatches were not recorded\"}",
        ToolCallState::Success,
    );

    let lines = rendered_text(&render_toolbox(
        &[parent, cap],
        0,
        true,
        100,
        false,
        &no_elided(),
    ));

    assert!(
        lines
            .iter()
            .any(|line| line.contains("7 unrecorded MCP dispatches")),
        "{lines:?}"
    );
}

#[test]
fn no_closed_match_on_tool_name_decides_presentation() {
    let history_source = include_str!("mod.rs");
    let events_source = include_str!("../app/events.rs");

    assert!(!history_source.contains("match tool {"));
    assert!(!events_source.contains("match tool {"));
    let (glyph, label) = tool_glyph_label("unknown_tool", true);
    assert!(glyph.is_empty());
    assert_eq!(label, "unknown_tool");
}

#[test]
fn builtin_and_tool_presentation_resolve_through_one_interface() {
    let builtin_meta = mcp_child_meta("parent", 0, Some("cockpit"), Some(true), "invoke");
    let builtin = resolve_tool_presentation(
        "rename_session",
        &serde_json::json!({
            "server": "cockpit",
            "tool": "rename_session",
            "args": { "name": "Test session" }
        }),
        Some(&builtin_meta),
    );
    let native = resolve_tool_presentation(
        "bash",
        &serde_json::json!({ "command": "cargo test" }),
        None,
    );
    let not_tool = cockpit_core::engine::tool::known_tool_presentation(
        "rename_session",
        &serde_json::json!({ "name": "Test session" }),
    );

    assert_eq!(builtin.label, "rename_session");
    assert!(builtin.glyph.is_some());
    assert_eq!(native.label, "bash");
    assert_eq!(native.glyph, Some("🔧"));
    assert_eq!(not_tool.glyph, None);
}

/// `pinned-messages`: the relocated controls ride an agent reply's
/// first content line, immediately left of the right-aligned timestamp
/// — `[fork] [pin] HH:MM` (grey) / `[fork] [unpin] HH:MM` (yellow for
/// unpin). The returned region records separate fork and pin ranges.
#[test]
fn agent_inline_controls_sit_left_of_timestamp_for_both_states() {
    let width: u16 = 60;
    let ctrl = |pinned: bool| PinControl {
        seq: 42,
        pinned,
        show_control: true,
        is_pick: false,
    };

    for (pinned, label, pin_w) in [(false, "[pin]", 5u16), (true, "[unpin]", 7u16)] {
        let r = render_agent(
            "Auto",
            "ok",
            "",
            fixed_ts(),
            false,
            0,
            None,
            width,
            false,
            Some(ctrl(pinned)),
        );
        let first = line_text(&r.lines[0]);
        let ts: String = first.chars().rev().take(TIMESTAMP_WIDTH).collect();
        assert!(
            ts.chars().rev().collect::<String>().contains(':'),
            "row ends with the HH:MM timestamp: {first:?}"
        );
        let fork_at = first.find("[fork] ").expect("fork control left of pin");
        let pin_at = first
            .find(&format!("{label} "))
            .expect("pin control left of ts");
        assert_eq!(pin_at, fork_at + "[fork] ".chars().count());
        let pin_end = pin_at + label.chars().count();
        assert_eq!(
            pin_end,
            width as usize - TIMESTAMP_RIGHT_MARGIN - TIMESTAMP_WIDTH - 1,
            "pin control ends just left of the ts gap: {first:?}"
        );

        let region = r.pin_region.expect("clickable control region recorded");
        assert_eq!(region.seq, 42);
        assert_eq!(region.row, 0, "controls ride the first content line");
        assert_eq!(region.fork_col_start, Some(fork_at as u16));
        assert_eq!(region.fork_col_end, Some((fork_at + 6) as u16));
        assert_eq!(region.col_end - region.col_start, pin_w, "{label} width");
        assert_eq!(
            region.col_end,
            width - TIMESTAMP_RIGHT_MARGIN as u16 - TIMESTAMP_WIDTH as u16 - 1,
            "pin region ends just left of the ts gap"
        );
        assert_eq!(
            region.col_start as usize, pin_at,
            "pin region starts at glyphs"
        );
        assert!(line_width(&r.lines[0]) <= width as usize);
    }
}

#[test]
fn agent_inline_controls_drop_fork_before_pin_on_narrow_width() {
    let ctrl = PinControl {
        seq: 42,
        pinned: false,
        show_control: true,
        is_pick: false,
    };

    let pin_only = render_agent(
        "Auto",
        "ok",
        "",
        fixed_ts(),
        false,
        0,
        None,
        20,
        false,
        Some(ctrl),
    );
    let first = line_text(&pin_only.lines[0]);
    assert!(!first.contains("[fork]"));
    assert!(first.contains("[pin]"));
    let region = pin_only.pin_region.expect("pin survives narrow fallback");
    assert_eq!(region.fork_col_start, None);
    assert_eq!(region.fork_col_end, None);
    assert_eq!(region.col_end - region.col_start, 5);

    let too_narrow = render_agent(
        "Auto",
        "ok",
        "",
        fixed_ts(),
        false,
        0,
        None,
        12,
        false,
        Some(ctrl),
    );
    let first = line_text(&too_narrow.lines[0]);
    assert!(!first.contains("[fork]") && !first.contains("[pin]"));
    assert!(too_narrow.pin_region.is_none());
}

/// `pinned-messages`: visibility is preserved — with the control hidden
/// (mouse mode off) and no pick selection, the agent's first line is
/// just `… HH:MM`, reserving no pin columns and recording no region.
#[test]
fn agent_no_pin_when_control_hidden() {
    let width: u16 = 60;
    let r = render_agent(
        "Auto",
        "ok",
        "",
        fixed_ts(),
        false,
        0,
        None,
        width,
        false,
        None,
    );
    assert!(r.pin_region.is_none(), "no region when not shown");
    let first = line_text(&r.lines[0]);
    assert!(!first.contains("[pin]") && !first.contains("[unpin]"));
}

#[test]
fn glyph_label_collapses_lock_variants_only_with_emoji() {
    // Emoji on: the lock/unlock emoji carries the lock state, so the
    // label collapses to the base verb.
    assert_eq!(tool_glyph_label("readlock", true).1, "read");
    assert_eq!(tool_glyph_label("writeunlock", true).1, "write");
    assert_eq!(tool_glyph_label("unlock", true).1, "unlock");
    // Emoji off: keep the full tool name so the lock state is legible.
    assert_eq!(tool_glyph_label("readlock", false).1, "readlock");
    assert_eq!(tool_glyph_label("writeunlock", false).1, "writeunlock");
    // A glyph only appears when emojis are enabled.
    assert!(tool_glyph_label("bash", false).0.is_empty());
    assert!(!tool_glyph_label("bash", true).0.is_empty());
}

/// Every emoji glyph in the tool-glyph path must be a reliably-wide,
/// single-codepoint emoji: no VS16 (U+FE0F) variation selector and a
/// `unicode_width` display width of exactly 2. A future glyph that
/// reintroduces the VS16 / width-mismatch bug fails here.
#[test]
fn tool_glyphs_are_vs16_free_and_width_two() {
    // Every tool whose row carries an emoji glyph.
    for tool in [
        "bash",
        "read",
        "readlock",
        "unlock",
        "write",
        "writeunlock",
        "edit",
        "editunlock",
    ] {
        let (glyph, _label) = tool_glyph_label(tool, /* emojis */ true);
        // The glyph is emitted with a trailing space; the emoji itself
        // is everything before it.
        let emoji = glyph.trim_end_matches(' ');
        assert!(!emoji.is_empty(), "{tool}: expected a glyph with emojis on");
        assert!(
            !emoji.contains('\u{FE0F}'),
            "{tool}: glyph {emoji:?} contains a VS16 variation selector"
        );
        assert_eq!(
            emoji.width(),
            2,
            "{tool}: glyph {emoji:?} display width must be 2, got {}",
            emoji.width()
        );
        // Reliably-wide single-codepoint emoji: exactly one scalar.
        assert_eq!(
            emoji.chars().count(),
            1,
            "{tool}: glyph {emoji:?} must be a single codepoint"
        );
    }
}

/// The collapsed tool-summary line (glyph + label + `": "` + truncated
/// summary), built exactly as `render_toolbox` builds it, must never
/// exceed the pane width — measured in display COLUMNS, not chars — for
/// any tool. Catches an off-by-one when a wide glyph's display width is
/// mis-counted.
#[test]
fn collapsed_tool_summary_fits_pane_for_every_tool() {
    // A long mixed-width summary so truncation is always exercised.
    let summary = "src/some/very/long/path/with/wide/字符/segments/that/overflow.rs".repeat(4);
    for width in [24usize, 40, 80, 120] {
        for tool in [
            "bash",
            "read",
            "readlock",
            "unlock",
            "write",
            "writeunlock",
            "edit",
            "editunlock",
        ] {
            let call = mk_call(tool, &summary, ToolCallState::Success);
            // Mirror render_toolbox's collapsed row: indent 2 (sidebar
            // glyph + space), then glyph + bold label + ": " + summary.
            let budget = tool_call_summary_budget(&call, width, 2, /* emojis */ true);
            let spans = tool_call_spans(&call, &truncate(&summary, budget), /* emojis */ true);
            // The leading sidebar glyph (1) + its space (1) = 2 columns.
            let line_cols: usize = 2 + spans.iter().map(|s| s.content.width()).sum::<usize>();
            assert!(
                line_cols <= width,
                "{tool}@{width}: collapsed line is {line_cols} cols, exceeds pane width"
            );
        }
    }
}

#[test]
fn toolbox_top_follows_and_clamps() {
    // <= visible: always pinned to the start.
    assert_eq!(toolbox_top(3, 0, true), 0);
    assert_eq!(toolbox_top(3, 5, false), 0);
    // Following pins to the last window.
    assert_eq!(toolbox_top(10, 0, true), 10 - TOOLBOX_VISIBLE);
    // Not following: the stored offset wins, clamped to the max.
    assert_eq!(toolbox_top(10, 2, false), 2);
    assert_eq!(toolbox_top(10, 99, false), 10 - TOOLBOX_VISIBLE);
}

#[test]
fn toolbox_collapsed_caps_at_visible_with_rounded_caps() {
    let calls: Vec<ToolCall> = (0..9)
        .map(|i| mk_call("bash", &format!("cmd{i}"), ToolCallState::Success))
        .collect();
    let r = render_toolbox(&calls, 0, true, 80, false, &no_elided());
    assert_eq!(r.lines.len(), TOOLBOX_VISIBLE);
    // Rounded caps top and bottom; in between the newest calls show.
    assert!(line_text(&r.lines[0]).starts_with('╭'));
    assert!(line_text(&r.lines[TOOLBOX_VISIBLE - 1]).starts_with('╰'));
    assert!(line_text(&r.lines[0]).contains("cmd3")); // 9 - 6
    assert!(line_text(&r.lines[TOOLBOX_VISIBLE - 1]).contains("cmd8"));
}

#[test]
fn toolbox_processing_call_is_yellow() {
    let calls = vec![mk_call("bash", "build", ToolCallState::Processing)];
    let r = render_toolbox(&calls, 0, true, 80, false, &no_elided());
    assert!(
        r.lines[0]
            .spans
            .iter()
            .any(|s| s.style.fg == Some(WARNING_TEXT))
    );
}

#[test]
fn toolbox_expanded_shows_read_and_readlock_output_but_not_unlock_output() {
    let mut bash = mk_call("bash", "ls", ToolCallState::Success);
    bash.expanded = true;
    bash.output = "file_a\nfile_b".into();
    let mut read = mk_call("read", "f.rs", ToolCallState::Success);
    read.expanded = true;
    read.output = "1|fn main() {}".into();
    let mut readlock = mk_call("readlock", "g.ts", ToolCallState::Success);
    readlock.expanded = true;
    readlock.output = "1|const value = 1;".into();
    let mut unlock = mk_call("unlock", "f.rs", ToolCallState::Success);
    unlock.expanded = true;
    unlock.output = "SHOULD_NOT_SHOW".into();

    let r = render_toolbox(
        &[bash, read, readlock, unlock],
        0,
        true,
        80,
        false,
        &no_elided(),
    );
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

    assert!(joined.contains("file_a") && joined.contains("file_b"));
    assert!(joined.contains("1|fn main() {}"));
    assert!(joined.contains("1|const value = 1;"));
    assert!(!joined.contains("SHOULD_NOT_SHOW"));
}

#[test]
fn toolbox_read_output_styles_line_numbers_without_rewriting_text() {
    let mut call = mk_call("read", "src/main.rs", ToolCallState::Success);
    call.expanded = true;
    call.output = "1|fn main() {\n2|}".into();

    let r = render_toolbox(&[call], 0, true, 80, false, &no_elided());
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

    assert!(joined.contains("1|fn main() {"));
    assert!(joined.contains("2|}"));
    let line = r
        .lines
        .iter()
        .find(|line| line_text(line).contains("1|fn main()"))
        .expect("rendered read output line");
    assert!(
        line.spans
            .iter()
            .any(|span| span.content.as_ref() == "1|" && span.style.fg == Some(METADATA_TEXT))
    );
    assert!(
        line.spans
            .iter()
            .any(|span| span.content.as_ref() == "fn" && span.style.fg == Some(PLAN_YELLOW))
    );
}

#[test]
fn inner_scroll_window_clamps_and_reports_more_counts() {
    let top = inner_scroll_window(25, TOOLCALL_RESULT_VISIBLE, 0);
    assert_eq!(top.offset, 0);
    assert_eq!(top.max_offset, 5);
    assert_eq!(top.more_above, 0);
    assert_eq!(top.more_below, 5);

    let middle = inner_scroll_window(25, TOOLCALL_RESULT_VISIBLE, 3);
    assert_eq!(middle.offset, 3);
    assert_eq!(middle.more_above, 3);
    assert_eq!(middle.more_below, 2);

    let clamped = inner_scroll_window(25, TOOLCALL_RESULT_VISIBLE, 99);
    assert_eq!(clamped.offset, 5);
    assert_eq!(clamped.more_above, 5);
    assert_eq!(clamped.more_below, 0);
}

#[test]
fn toolbox_expands_only_the_selected_call() {
    let mut expanded = mk_call("bash", "cmd1", ToolCallState::Success);
    expanded.expanded = true;
    expanded.full_input = "cmd1\ncontinued".into();
    expanded.output = "selected output".into();
    let mut collapsed = mk_call("bash", "cmd2", ToolCallState::Success);
    collapsed.full_input = "cmd2\nSHOULD_NOT_SHOW".into();
    collapsed.output = "neighbor output".into();

    let r = render_toolbox(&[expanded, collapsed], 0, true, 80, false, &no_elided());
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

    assert!(joined.contains("continued"));
    assert!(joined.contains("selected output"));
    assert!(joined.contains("bash: cmd2"));
    assert!(!joined.contains("SHOULD_NOT_SHOW"));
    assert!(!joined.contains("neighbor output"));
    assert_eq!(
        r.tool_call_rows
            .iter()
            .filter(|row| **row == Some(0))
            .count(),
        3
    );
    assert_eq!(
        r.tool_call_rows
            .iter()
            .filter(|row| **row == Some(1))
            .count(),
        1
    );
}

#[test]
fn toolbox_wraps_long_expanded_input_with_hanging_indent() {
    let width = 32u16;
    let mut call = mk_call(
        "bash",
        "printf alpha beta gamma delta epsilon zeta eta theta iota kappa lambda",
        ToolCallState::Success,
    );
    call.expanded = true;
    call.full_input = call.summary.clone();

    let r = render_toolbox(&[call], 0, true, width, false, &no_elided());

    assert!(r.lines.len() > 1, "long input should wrap");
    assert!(
        r.lines
            .iter()
            .all(|line| line_width(line) <= width as usize),
        "wrapped rows must fit within width: {:?}",
        r.lines.iter().map(line_text).collect::<Vec<_>>()
    );
    assert!(r.lines[0].spans[0].content.as_ref() == "╭");
    assert!(
        r.lines[1..]
            .iter()
            .all(|line| matches!(line.spans[0].content.as_ref(), "│" | "╰")),
        "every continuation keeps a sidebar glyph"
    );
    assert!(
        r.tool_call_rows.iter().all(|row| *row == Some(0)),
        "wrapped input rows stay mapped to the owning call"
    );

    let continuation = line_text(&r.lines[1]);
    assert!(
        continuation.starts_with("│       "),
        "continuation should have sidebar, spacer, and six-column bash label indent: {continuation:?}"
    );
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("lambda"));
    assert!(!joined.contains('…'));
}

#[test]
fn toolbox_result_window_caps_and_records_scroll_region() {
    let mut call = mk_call("bash", "long", ToolCallState::Success);
    call.expanded = true;
    call.output = (0..25)
        .map(|idx| format!("out-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");

    let r = render_toolbox(&[call], 0, true, 80, false, &no_elided());
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("out-0"));
    assert!(joined.contains("out-19"));
    assert!(!joined.contains("out-20"));
    assert!(joined.contains("5 more below"));
    assert_eq!(r.tool_result_scroll_regions.len(), 1);
    assert_eq!(r.tool_result_scroll_regions[0].call_index, 0);
    assert_eq!(r.tool_result_scroll_regions[0].offset, 0);
    assert_eq!(r.tool_result_scroll_regions[0].max_offset, 5);

    let mut scrolled = mk_call("bash", "long", ToolCallState::Success);
    scrolled.expanded = true;
    scrolled.result_offset = 3;
    scrolled.output = (0..25)
        .map(|idx| format!("out-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let r = render_toolbox(&[scrolled], 0, true, 80, false, &no_elided());
    let joined = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("3 more above"));
    assert!(joined.contains("out-3"));
    assert!(joined.contains("out-22"));
    assert!(joined.contains("2 more below"));
}

#[test]
#[rustfmt::skip]
fn toolbox_renders_readable_websearch_and_custom_args() {
    let websearch = mk_call(
        "websearch",
        "OpenAI model release news",
        ToolCallState::Success,
    );
    let mut custom = mk_call(
        "custom_audit",
        "prompt=\"Describe the deployment risk for the west region\"",
        ToolCallState::Success,
    );
    custom.full_input =
        "prompt=\"Describe the deployment risk for the west region\"\ndry_run=true".to_string();

    let collapsed = render_toolbox(
        &[websearch.clone(), custom.clone()],
        0,
        true,
        100,
        false,
        &no_elided(),
    );
    let collapsed_text = collapsed
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(collapsed_text.contains("websearch: OpenAI model release news"));
    assert!(collapsed_text.contains("custom_audit: prompt=\"Describe"));
    assert!(!collapsed_text.contains("<25c>"));
    assert!(!collapsed_text.contains("<52c>"));

    let mut expanded_websearch = websearch;
    expanded_websearch.expanded = true;
    let mut expanded_custom = custom;
    expanded_custom.expanded = true;
    let expanded = render_toolbox(
        &[expanded_websearch, expanded_custom],
        0,
        true,
        100,
        false,
        &no_elided(),
    );
    let expanded_text = expanded
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(expanded_text.contains("websearch: OpenAI model release news"));
    assert!(
        expanded_text.contains("prompt=\"Describe the deployment risk for the west region\"")
    );
    assert!(expanded_text.contains("dry_run=true"));
    assert!(!expanded_text.contains("<25c>"));
    assert!(!expanded_text.contains("<52c>"));
}

#[test]
#[rustfmt::skip]
fn toolbox_honors_emoji_setting() {
    let calls = vec![mk_call("read", "f.txt", ToolCallState::Success)];
    assert!(
        !line_text(&render_toolbox(&calls, 0, true, 80, false, &no_elided()).lines[0])
            .contains('📖')
    );
    assert!(
        line_text(&render_toolbox(&calls, 0, true, 80, true, &no_elided()).lines[0])
            .contains('📖')
    );
}

// ── prune dimming ──────────────────────────────────────────────────

const MUTED: Color = Color::Indexed(MUTED_COLOR_INDEX);

/// True when any span on `line` carries the theme muted foreground.
fn any_muted(line: &Line<'static>) -> bool {
    line.spans.iter().any(|s| s.style.fg == Some(MUTED))
}

/// A boxed snapshot tool whose `call_id` is in the elided set renders
/// its expanded body dimmed (muted) with a `(pruned …)` tag, while the
/// kept (non-elided) call of the same kind renders normally. Drives the
/// renderer with a SYNTHETIC elided set.
#[test]
fn elided_body_is_dimmed_kept_body_is_not() {
    // Two `search` calls (output-bearing snapshot tool): the older is
    // elided, the newer kept.
    let mut older = mk_call("search", "TODO", ToolCallState::Success);
    older.call_id = "c1".into();
    older.expanded = true;
    older.output = "OLDER RESULTS BODY".into();
    let mut newer = mk_call("search", "TODO", ToolCallState::Success);
    newer.call_id = "c2".into();
    newer.expanded = true;
    newer.output = "NEWER RESULTS BODY".into();

    let elided: HashSet<String> = ["c1".to_string()].into_iter().collect();
    let r = render_toolbox(&[older, newer], 0, true, 80, false, &elided);

    // Locate the body rows (indented output) for each call.
    let older_body = r
        .lines
        .iter()
        .find(|l| line_text(l).contains("OLDER RESULTS BODY"))
        .expect("older body present (full-fidelity, still visible)");
    let newer_body = r
        .lines
        .iter()
        .find(|l| line_text(l).contains("NEWER RESULTS BODY"))
        .expect("newer body present");

    // Elided body is muted; kept body is not.
    assert!(any_muted(older_body), "elided body must be dimmed");
    assert!(
        !any_muted(newer_body),
        "kept most-recent body must NOT be dimmed"
    );
    // The optional `(pruned …)` tag is emitted on the elided call's
    // summary line, in the muted style.
    let joined: String = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(joined.contains("(pruned"), "elided call gets a pruned tag");
}

/// Empty elided set → zero visual change: no body is muted and no tag.
#[test]
fn no_elisions_means_no_dimming() {
    let mut call = mk_call("search", "TODO", ToolCallState::Success);
    call.call_id = "c1".into();
    call.expanded = true;
    call.output = "RESULTS".into();
    let r = render_toolbox(&[call], 0, true, 80, false, &no_elided());
    let joined: String = r.lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(!joined.contains("(pruned"));
    assert!(
        r.lines.iter().all(|l| !any_muted(l)),
        "no elisions → nothing muted"
    );
}

fn compact_entry(source: &str, expanded: bool) -> HistoryEntry {
    HistoryEntry::CompactBoundary {
        predecessor_short_id: "deadbe".into(),
        seed_tool_count: 2,
        seed_tool_tokens: 12,
        source: source.into(),
        trigger_ctx_pct: Some(61.5),
        tokens_before: 6_000,
        tokens_after: 2_000,
        turns_summarized: 8,
        tail_kept: 4,
        tail_trimmed: 1,
        handoff: Some("## Decisions\nkeep the exact handoff".into()),
        expanded,
        result_offset: 0,
    }
}

#[test]
fn compaction_renders_as_tool_call() {
    for source in ["auto", "manual", "agent_requested"] {
        let rendered = render_entry(
            &compact_entry(source, false),
            80,
            ThinkingDisplay::Condensed,
            MarkdownOpts::default(),
            cockpit_config::extended::DiffStyle::default(),
            false,
            &no_elided(),
            0,
            None,
        );
        let text = rendered.lines.iter().map(line_text).collect::<String>();
        assert!(text.contains("compact:"), "{text}");
        assert!(text.contains(&format!("source={source}")), "{text}");
        assert_eq!(rendered.tool_call_rows, vec![Some(0)]);
    }
}

#[test]
fn compaction_expand_shows_handoff() {
    let rendered = render_entry(
        &compact_entry("manual", true),
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    let text = rendered
        .lines
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("tokens=6000→2000"), "{text}");
    assert!(text.contains("tail kept=4, trimmed=1"), "{text}");
    assert!(text.contains("keep the exact handoff"), "{text}");
    assert!(rendered.tool_call_rows.iter().all(|row| *row == Some(0)));
}

/// The backup-fallback notice (implementation note)
/// renders as a YELLOW display-only line.
#[test]
fn backup_warning_renders_yellow() {
    let entry = HistoryEntry::BackupWarning {
        line: "primary `q` failed (timeout) — answered with backup `c`.".into(),
    };
    let r = render_entry(
        &entry,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert!(
        r.lines[0]
            .spans
            .iter()
            .any(|s| s.style.fg == Some(WARNING_TEXT)),
        "backup banner must be yellow"
    );
}

#[test]
fn command_error_renders_red() {
    let entry = HistoryEntry::CommandError {
        line: "/fork: could not fork: daemon unavailable".into(),
    };
    let r = render_entry(
        &entry,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert!(
        r.lines[0]
            .spans
            .iter()
            .any(|s| s.style.fg == Some(ERROR_TEXT)),
        "command errors must be red"
    );
}

#[test]
#[rustfmt::skip]
fn inference_warning_renders_yellow() {
    let entry = HistoryEntry::InferenceWarning {
        line: "local/slow has not produced another token after 1s. Press Ctrl+C to cancel."
            .into(),
    };
    let r = render_entry(
        &entry,
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert!(
        r.lines[0]
            .spans
            .iter()
            .any(|s| s.style.fg == Some(WARNING_TEXT)),
        "inference warning must be yellow"
    );
}

#[test]
fn compact_duration_compact_under_and_over_a_minute() {
    assert_eq!(format_compact_duration(Duration::from_secs(0)), "0s");
    assert_eq!(format_compact_duration(Duration::from_secs(45)), "45s");
    assert_eq!(format_compact_duration(Duration::from_secs(59)), "59s");
    assert_eq!(format_compact_duration(Duration::from_secs(60)), "1m 0s");
    assert_eq!(format_compact_duration(Duration::from_secs(130)), "2m 10s");
    // Sub-second is floored.
    assert_eq!(format_compact_duration(Duration::from_millis(1900)), "1s");
}

/// Whether any span on the line carries the orange child-name color.
fn any_orange(line: &Line<'static>) -> bool {
    line.spans
        .iter()
        .any(|s| s.style.fg == Some(SUBAGENT_NAME_FG))
}

fn render_sub(
    parent: &str,
    child: &str,
    spawned_at: std::time::Instant,
    outcome: Option<SubagentOutcome>,
    expanded: bool,
) -> Rendered {
    render_entry(
        &HistoryEntry::Subagent {
            parent: parent.into(),
            child: child.into(),
            task_call_id: "task".into(),
            label: "default".into(),
            trusted_only: true,
            model_trusted: true,
            routing: SubagentRoutingChips {
                model: Some("claude-sonnet-4-6".into()),
                location: Some("private_remote".into()),
                fallback: None,
            },
            spawned_at,
            outcome,
            expanded,
        },
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    )
}

#[test]
#[rustfmt::skip]
fn subagent_routing_chips_condense_model_and_trust() {
    fn chip_text(
        trusted_only: bool,
        model_trusted: bool,
        routing: SubagentRoutingChips,
    ) -> String {
        let mut spans = Vec::new();
        append_subagent_routing_chips(&mut spans, trusted_only, model_trusted, &routing);
        spans_text(&spans)
    }

    assert_eq!(
        chip_text(
            true,
            true,
            SubagentRoutingChips {
                model: Some("gpt-5".into()),
                location: Some("private_remote".into()),
                fallback: Some("backup".into()),
            },
        ),
        " [gpt-5 · t] [private_remote] [fallback:backup] [trusted-only]"
    );
    assert_eq!(
        chip_text(
            false,
            false,
            SubagentRoutingChips {
                model: Some("gpt-5".into()),
                location: None,
                fallback: None,
            },
        ),
        " [gpt-5 · u]"
    );
    assert_eq!(
        chip_text(false, true, SubagentRoutingChips::default()),
        " [t]"
    );
    assert_eq!(
        chip_text(false, false, SubagentRoutingChips::default()),
        " [u]"
    );
}

#[test]
fn fallback_chip_renders_for_non_none_decision() {
    let mut spans = Vec::new();
    append_subagent_routing_chips(
        &mut spans,
        false,
        true,
        &SubagentRoutingChips {
            model: Some("gpt-5".into()),
            location: None,
            fallback: Some("backup".into()),
        },
    );
    assert!(spans_text(&spans).contains("[fallback:backup]"));

    let mut none_spans = Vec::new();
    append_subagent_routing_chips(
        &mut none_spans,
        false,
        true,
        &SubagentRoutingChips {
            model: Some("gpt-5".into()),
            location: None,
            fallback: Some("none".into()),
        },
    );
    assert!(!spans_text(&none_spans).contains("[fallback:"));
}

/// Running: one live line `{parent} delegated to {child}…
/// (elapsed)`, child name orange, no expand chip.
#[test]
fn subagent_running_is_one_orange_live_line() {
    let r = render_sub("Build", "explore", std::time::Instant::now(), None, false);
    assert_eq!(r.lines.len(), 1);
    let text = line_text(&r.lines[0]);
    assert!(text.contains("Build delegated to explore"), "{text}");
    assert!(text.contains("[claude-sonnet-4-6 · t]"), "{text}");
    assert!(!text.contains("[trusted]"), "{text}");
    assert!(text.contains("[private_remote]"), "{text}");
    assert!(text.contains("[trusted-only]"), "{text}");
    // Verbatim casing: parent capitalized, child lowercase.
    assert!(!text.contains("Explore"));
    // Elapsed clock rendered (the `(…s)` readout).
    assert!(text.contains("s)"), "{text}");
    assert!(any_orange(&r.lines[0]));
    assert!(r.chip_row.is_none());
}

/// Settled (normal): `{child} worked for {duration}` header (orange
/// child) + left-bar-quoted body, truncated with an expand chip.
#[test]
fn subagent_report_renders_header_and_quoted_body() {
    // Blank-line-separated so each paragraph renders as its own row
    // (markdown reflows single-newline runs into one paragraph).
    let report = (0..10)
        .map(|i| format!("para {i}"))
        .collect::<Vec<_>>()
        .join("\n\n");
    let r = render_sub(
        "Build",
        "explore",
        std::time::Instant::now(),
        Some(SubagentOutcome {
            report,
            failed: false,
            duration: Duration::from_secs(130),
            status: None,
        }),
        false,
    );
    let header = line_text(&r.lines[0]);
    assert!(header.contains("explore worked for 2m 10s"), "{header}");
    assert!(header.contains("[claude-sonnet-4-6 · t]"), "{header}");
    assert!(!header.contains("[trusted]"), "{header}");
    assert!(header.contains("[private_remote]"), "{header}");
    assert!(header.contains("[trusted-only]"), "{header}");
    assert!(any_orange(&r.lines[0]));
    // Body rows carry the left `│` bar.
    assert!(r.lines[1..].iter().any(|l| line_text(l).contains("│")));
    // Truncated: an expand chip exists and is the clickable row.
    assert!(r.chip_row.is_some());
    let chip = line_text(&r.lines[r.chip_row.unwrap()]);
    assert!(chip.contains("expand"), "{chip}");
    // Collapsed body shows only the preview lines.
    let body_rows = r.lines.len() - 1 /* header */ - 1 /* chip */;
    assert_eq!(body_rows, SUBAGENT_PREVIEW_LINES);
}

/// Expanding reveals the full body and offers a collapse affordance.
#[test]
fn subagent_expanded_reveals_full_body() {
    let report = (0..10)
        .map(|i| format!("para {i}"))
        .collect::<Vec<_>>()
        .join("\n\n");
    let r = render_sub(
        "Build",
        "explore",
        std::time::Instant::now(),
        Some(SubagentOutcome {
            report,
            failed: false,
            duration: Duration::from_secs(5),
            status: None,
        }),
        true,
    );
    // All ten body paragraphs present (plus header + collapse chip).
    let joined: String = r.lines.iter().map(line_text).collect();
    assert!(joined.contains("para 9"));
    assert!(r.chip_row.is_some());
}

/// Failure: `{child} failed after {duration}` header, child orange,
/// no dangling running line.
#[test]
fn subagent_failure_renders_failed_header() {
    let r = render_sub(
        "Build",
        "explore",
        std::time::Instant::now(),
        Some(SubagentOutcome {
            report: "Error: it broke".into(),
            failed: true,
            duration: Duration::from_secs(7),
            status: Some("explore stopped with an error".into()),
        }),
        false,
    );
    let header = line_text(&r.lines[0]);
    assert!(header.contains("explore failed after 7s"), "{header}");
    assert!(!header.contains("delegated to"));
    assert!(any_orange(&r.lines[0]));
    let joined: String = r.lines.iter().map(line_text).collect();
    assert!(joined.contains("explore stopped with an error"), "{joined}");
}

/// Empty report: bare `{child} worked for {duration}` header, no
/// quoted block, no expand chip.
#[test]
fn subagent_empty_report_is_header_only() {
    let r = render_sub(
        "Build",
        "explore",
        std::time::Instant::now(),
        Some(SubagentOutcome {
            report: "   \n  ".into(),
            failed: false,
            duration: Duration::from_secs(3),
            status: None,
        }),
        false,
    );
    assert_eq!(r.lines.len(), 1);
    assert!(line_text(&r.lines[0]).contains("explore worked for 3s"));
    assert!(r.chip_row.is_none());
}

#[test]
fn subagent_status_renders_between_header_and_body() {
    let r = render_sub(
        "Build",
        "builder",
        std::time::Instant::now(),
        Some(SubagentOutcome {
            report: "Edited src/lib.rs. Validation not run yet.".into(),
            failed: false,
            duration: Duration::from_secs(9),
            status: Some("builder stopped after writing files; validation not run yet".into()),
        }),
        true,
    );
    let joined: String = r.lines.iter().map(line_text).collect();
    assert!(
        joined.contains("builder stopped after writing files; validation not run yet"),
        "{joined}"
    );
}

#[test]
fn subagent_batch_label_shows_running_and_done_state() {
    let running = render_entry(
        &HistoryEntry::Subagent {
            parent: "Build".into(),
            child: "explore".into(),
            task_call_id: "task".into(),
            label: "auth".into(),
            trusted_only: true,
            model_trusted: true,
            routing: SubagentRoutingChips {
                model: Some("reasoning-model".into()),
                location: Some("local".into()),
                fallback: Some("backup".into()),
            },
            spawned_at: std::time::Instant::now(),
            outcome: None,
            expanded: false,
        },
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert!(line_text(&running.lines[0]).contains("auth Build delegated to explore"));

    let done = render_entry(
        &HistoryEntry::Subagent {
            parent: "Build".into(),
            child: "explore".into(),
            task_call_id: "task".into(),
            label: "auth".into(),
            trusted_only: true,
            model_trusted: true,
            routing: SubagentRoutingChips {
                model: Some("reasoning-model".into()),
                location: Some("local".into()),
                fallback: Some("backup".into()),
            },
            spawned_at: std::time::Instant::now(),
            outcome: Some(SubagentOutcome {
                report: "done".into(),
                failed: false,
                duration: Duration::from_secs(1),
                status: None,
            }),
            expanded: false,
        },
        80,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        cockpit_config::extended::DiffStyle::default(),
        false,
        &no_elided(),
        0,
        None,
    );
    assert!(line_text(&done.lines[0]).contains("auth ✓ explore worked for 1s"));
}

#[test]
fn classifies_partial_builder_report() {
    let status = classify_subagent_status(
        "builder",
        "Modified src/lib.rs and tests were not run.",
        false,
    );
    assert_eq!(
        status.as_deref(),
        Some("builder stopped after writing files; validation not run yet")
    );
    assert!(classify_subagent_status("explore", "all done", false).is_none());
}
