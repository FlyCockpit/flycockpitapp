use super::{
    App, CopyCommand, CopyFormat, parse_copy_command, parse_copy_format, select_agent_text,
};
use crate::tui::history::HistoryEntry;

fn agent(text: &str) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "builder".to_string(),
        text: text.to_string(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: None,
        performance: None,
        performance_expanded: false,
    }
}

#[test]
fn bare_and_markdown_default_to_markdown() {
    assert_eq!(parse_copy_format(""), Some(CopyFormat::Markdown));
    assert_eq!(parse_copy_format("markdown"), Some(CopyFormat::Markdown));
    // Whitespace-only / mixed case still resolve.
    assert_eq!(parse_copy_format("  "), Some(CopyFormat::Markdown));
    assert_eq!(parse_copy_format("MarkDown"), Some(CopyFormat::Markdown));
}

#[test]
fn plain_and_rich_aliases_parse() {
    assert_eq!(parse_copy_format("plain"), Some(CopyFormat::Plain));
    assert_eq!(parse_copy_format("plaintext"), Some(CopyFormat::Plain));
    assert_eq!(parse_copy_format("rich"), Some(CopyFormat::Rich));
    assert_eq!(parse_copy_format("richtext"), Some(CopyFormat::Rich));
}

#[test]
fn unknown_format_is_none() {
    assert_eq!(parse_copy_format("html"), None);
    assert_eq!(parse_copy_format("md"), None);
}

#[test]
fn select_agent_text_bare_skips_non_agent_and_empty() {
    // No agent messages → None (the no-response path). `select_agent_text`
    // with `n: None` is the bare-`/copy` case ("the last response").
    assert_eq!(select_agent_text(&[], None), None);
    assert_eq!(
        select_agent_text(
            &[HistoryEntry::Plain {
                line: "tool chrome".to_string(),
            }],
            None
        ),
        None
    );

    // Tool chrome after the agent message must not shadow it, and a
    // trailing empty agent turn is ignored.
    let history = vec![
        agent("first response"),
        HistoryEntry::Plain {
            line: "a tool ran".to_string(),
        },
        agent("**last** response"),
        agent("   "),
    ];
    assert_eq!(
        select_agent_text(&history, None).as_deref(),
        Some("**last** response")
    );
}

// ---------------------------------------------------------------------
// AC1 (tui-copy-command-file-output): copy_command_parser_and_selection —
// grammar, spaces, N/format errors, legacy forms, exact payloads.
// ---------------------------------------------------------------------

fn cmd(n: Option<usize>, format: CopyFormat, file: Option<&str>) -> CopyCommand {
    CopyCommand {
        n,
        format,
        file: file.map(str::to_string),
    }
}

#[test]
fn legacy_forms_parse_exactly_as_before() {
    assert_eq!(
        parse_copy_command(""),
        Ok(cmd(None, CopyFormat::Markdown, None))
    );
    assert_eq!(
        parse_copy_command("markdown"),
        Ok(cmd(None, CopyFormat::Markdown, None))
    );
    assert_eq!(
        parse_copy_command("plain"),
        Ok(cmd(None, CopyFormat::Plain, None))
    );
    assert_eq!(
        parse_copy_command("rich"),
        Ok(cmd(None, CopyFormat::Rich, None))
    );
}

#[test]
fn n_alone_defaults_format_and_has_no_file() {
    assert_eq!(
        parse_copy_command("2"),
        Ok(cmd(Some(2), CopyFormat::Markdown, None))
    );
    assert_eq!(
        parse_copy_command("10"),
        Ok(cmd(Some(10), CopyFormat::Markdown, None))
    );
}

#[test]
fn n_zero_is_rejected_at_parse_time_not_left_to_selection() {
    // Positions are 1-indexed; `0` must fail to parse, not silently
    // succeed and only later report "no response at position 0".
    assert!(parse_copy_command("0").is_err());
    assert!(parse_copy_command("0 plain").is_err());
    assert!(parse_copy_command("0 file /tmp/out.md").is_err());
}

#[test]
fn n_and_format_combine_in_grammar_order() {
    assert_eq!(
        parse_copy_command("3 plain"),
        Ok(cmd(Some(3), CopyFormat::Plain, None))
    );
    assert_eq!(
        parse_copy_command("1 rich"),
        Ok(cmd(Some(1), CopyFormat::Rich, None))
    );
}

#[test]
fn file_form_captures_raw_remainder_including_spaces() {
    assert_eq!(
        parse_copy_command("file /tmp/out.md"),
        Ok(cmd(None, CopyFormat::Markdown, Some("/tmp/out.md")))
    );
    assert_eq!(
        parse_copy_command("file /tmp/My Documents/out.md"),
        Ok(cmd(
            None,
            CopyFormat::Markdown,
            Some("/tmp/My Documents/out.md")
        ))
    );
    assert_eq!(
        parse_copy_command("2 plain file /tmp/out.md"),
        Ok(cmd(Some(2), CopyFormat::Plain, Some("/tmp/out.md")))
    );
    assert_eq!(
        parse_copy_command("  3   rich   file   /tmp/spaced out.md  "),
        Ok(cmd(Some(3), CopyFormat::Rich, Some("/tmp/spaced out.md")))
    );
}

#[test]
fn file_without_a_path_is_an_error() {
    assert!(parse_copy_command("file").is_err());
    assert!(parse_copy_command("plain file").is_err());
    assert!(parse_copy_command("file   ").is_err());
}

#[test]
fn unknown_format_token_is_an_error() {
    assert!(parse_copy_command("html").is_err());
    assert!(parse_copy_command("md").is_err());
    assert!(parse_copy_command("2 html").is_err());
}

#[test]
fn trailing_garbage_after_a_complete_command_is_an_error() {
    assert!(parse_copy_command("plain extra").is_err());
    // NOT a trailing-garbage case: `file` intentionally consumes the raw
    // remainder of the line as its path (grammar: "raw remainder path"),
    // so "extra" here is part of the path, not garbage after it — a path
    // containing a literal space is exactly what this constructs.
    assert_eq!(
        parse_copy_command("1 plain file /tmp/out.md extra"),
        Ok(cmd(Some(1), CopyFormat::Plain, Some("/tmp/out.md extra")))
    );
    // A real trailing-garbage case *after* a complete non-file command.
    assert!(parse_copy_command("2 rich extra").is_err());
}

#[test]
fn select_agent_text_is_newest_first_one_indexed() {
    let history = vec![agent("oldest"), agent("middle"), agent("newest")];
    assert_eq!(select_agent_text(&history, None).as_deref(), Some("newest"));
    assert_eq!(
        select_agent_text(&history, Some(1)).as_deref(),
        Some("newest")
    );
    assert_eq!(
        select_agent_text(&history, Some(2)).as_deref(),
        Some("middle")
    );
    assert_eq!(
        select_agent_text(&history, Some(3)).as_deref(),
        Some("oldest")
    );
    assert_eq!(select_agent_text(&history, Some(4)), None);
    assert_eq!(select_agent_text(&history, Some(0)), None);
}

#[test]
fn select_agent_text_skips_empty_assistant_turns() {
    let history = vec![agent("first"), agent("   "), agent("second")];
    assert_eq!(
        select_agent_text(&history, Some(1)).as_deref(),
        Some("second")
    );
    assert_eq!(
        select_agent_text(&history, Some(2)).as_deref(),
        Some("first")
    );
}

#[test]
fn render_copy_file_payload_exact_bytes_per_format() {
    let markdown = "# Title\n\n**bold** text";
    assert_eq!(
        App::render_copy_file_payload(CopyFormat::Markdown, markdown),
        markdown.as_bytes()
    );
    let plain = App::render_copy_file_payload(CopyFormat::Plain, markdown);
    assert_eq!(
        String::from_utf8(plain).unwrap(),
        crate::clipboard::markdown_to_plain(markdown)
    );
    let rich = App::render_copy_file_payload(CopyFormat::Rich, markdown);
    assert_eq!(
        String::from_utf8(rich).unwrap(),
        crate::clipboard::markdown_to_html(markdown)
    );
}
