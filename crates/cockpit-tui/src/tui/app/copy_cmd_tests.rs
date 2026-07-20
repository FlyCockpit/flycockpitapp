use super::{CopyFormat, last_agent_text, parse_copy_format};
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
fn last_agent_text_skips_non_agent_and_empty() {
    // No agent messages → None (the no-response path).
    assert_eq!(last_agent_text(&[]), None);
    assert_eq!(
        last_agent_text(&[HistoryEntry::Plain {
            line: "tool chrome".to_string(),
        }]),
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
        last_agent_text(&history).as_deref(),
        Some("**last** response")
    );
}
