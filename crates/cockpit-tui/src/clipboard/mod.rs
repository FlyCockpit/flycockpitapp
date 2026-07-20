//! System-clipboard helpers (plan.md T8.e).
//!
//! Two entry points:
//!
//! - [`copy_plain`] — plain-text only. Prefers OSC52 (works through SSH)
//!   and falls back to the local OS clipboard via `arboard` if the OSC52
//!   write fails (e.g. terminal doesn't honor the escape).
//! - [`copy_rich`] — multi-format (HTML + plain alt). Uses `arboard`
//!   only, because OSC52 is single-format. Returns `Err(Unsupported)`
//!   when the session is over SSH so the caller can show a toast and
//!   fall back to `copy_plain`.
//!
//! SSH detection is `$SSH_CONNECTION` / `$SSH_TTY` — OpenSSH sets these
//! on the remote side. Inside tmux on a local machine they're unset
//! so we still pick the local-clipboard path.

use std::io::{Write, stdout};

use base64::Engine;

/// Why a copy attempt didn't reach the system clipboard.
#[derive(Debug)]
pub enum CopyError {
    /// Rich-text copy was attempted over SSH, where no protocol can
    /// forward multi-format clipboard data. Caller should fall back to
    /// plain text and surface a toast.
    UnsupportedOverSsh,
    /// Underlying clipboard backend failed (no clipboard service,
    /// permission denied, etc.).
    Backend(String),
    /// Base64 payload exceeds the OSC52 size ceiling; nothing was
    /// written (no partial escape). Carries the max allowed base64 len.
    TooLarge { max: usize },
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOverSsh => write!(f, "rich-text copy unavailable over SSH"),
            Self::Backend(s) => write!(f, "clipboard backend error: {s}"),
            Self::TooLarge { max } => {
                write!(f, "selection too large for OSC52 (max {max} base64 bytes)")
            }
        }
    }
}

impl std::error::Error for CopyError {}

/// Observable result of a plain-text copy attempt.
///
/// OSC52 is fire-and-forget: writing the escape means Cockpit accepted the
/// attempt locally, but terminals do not acknowledge whether they placed the
/// text on the user's clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOutcome {
    pub osc52_written: bool,
    pub local_clipboard_written: bool,
}

impl CopyOutcome {
    pub fn accepted(self) -> bool {
        self.osc52_written || self.local_clipboard_written
    }
}

/// Copy plain text to the system clipboard.
///
/// Tries OSC52 first (terminal escape, works through SSH and tmux with
/// `set-clipboard on`). Falls back to the local OS clipboard via
/// `arboard` if OSC52 isn't acknowledged by the terminal (we can't
/// actually detect that — we just attempt OSC52 and additionally try
/// arboard locally so at least one path lands).
pub fn copy_plain(text: &str) -> Result<CopyOutcome, CopyError> {
    copy_plain_with(text, is_ssh(), osc52_set_clipboard, arboard_set_text)
}

fn copy_plain_with(
    text: &str,
    ssh: bool,
    mut osc52: impl FnMut(&str) -> Result<(), CopyError>,
    mut local: impl FnMut(&str) -> Result<(), CopyError>,
) -> Result<CopyOutcome, CopyError> {
    let mut outcome = CopyOutcome {
        osc52_written: false,
        local_clipboard_written: false,
    };
    let mut first_err = None;

    match osc52(text) {
        Ok(()) => outcome.osc52_written = true,
        Err(e) => first_err = Some(e),
    }

    if !ssh {
        match local(text) {
            Ok(()) => outcome.local_clipboard_written = true,
            Err(e) if first_err.is_none() => first_err = Some(e),
            Err(_) => {}
        }
    }

    if outcome.accepted() {
        Ok(outcome)
    } else {
        Err(first_err.unwrap_or_else(|| CopyError::Backend("no clipboard backend".to_string())))
    }
}

/// Copy rich text (HTML + plain alt) to the system clipboard.
///
/// Goes through `arboard` only — OSC52 cannot carry multi-format. Over
/// SSH there's no clipboard pathway, so this returns
/// [`CopyError::UnsupportedOverSsh`] and the caller falls back to
/// [`copy_plain`].
pub fn copy_rich(plain: &str, html: &str) -> Result<(), CopyError> {
    if is_ssh() {
        return Err(CopyError::UnsupportedOverSsh);
    }
    arboard_set_html(html, plain)
}

/// True when the current process appears to be running over SSH —
/// `$SSH_CONNECTION` or `$SSH_TTY` is set. Used by the rich-text
/// copy path to fall back to OSC52 plain, and by the context-menu
/// builder to drop "Copy as rich text" from the offered list (it
/// can't reach the local clipboard over SSH anyway).
pub fn is_ssh() -> bool {
    std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some()
}

/// xterm's documented OSC-string parse ceiling for the base64 payload;
/// past it terminals drop the escape, so we hard-fail rather than emit a
/// truncated clipboard.
const OSC52_MAX_B64: usize = 74_994;

/// Build the OSC52 clipboard-set escape(s) for `encoded_b64`. Inside
/// tmux, returns the raw BEL-terminated escape immediately followed by
/// the DCS-passthrough-wrapped form (double-emit, covering both
/// `set-clipboard` and `allow-passthrough` tmux configs); outside tmux,
/// the raw escape alone.
fn osc52_sequence(encoded_b64: &str, in_tmux: bool) -> String {
    let raw = format!("\x1b]52;c;{encoded_b64}\x07");
    if !in_tmux {
        return raw;
    }
    // tmux DCS passthrough: prefix `ESC P tmux ;`, double every inner
    // ESC (the BEL-terminated form has only the leading ESC), terminate
    // with ST (`ESC \`). Inner BEL is never doubled.
    let inner = raw.replace('\x1b', "\x1b\x1b");
    format!("{raw}\x1bPtmux;{inner}\x1b\\")
}

fn osc52_set_clipboard(text: &str) -> Result<(), CopyError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    // Hard-fail before writing anything — a partial escape would corrupt
    // the terminal stream and leave a half-set clipboard.
    if encoded.len() > OSC52_MAX_B64 {
        return Err(CopyError::TooLarge { max: OSC52_MAX_B64 });
    }
    // `c` selects the system clipboard buffer (vs `p` primary or numeric
    // cut-buffers). Inside tmux we double-emit the raw + passthrough form.
    let seq = osc52_sequence(&encoded, std::env::var_os("TMUX").is_some());
    let mut out = stdout();
    write!(out, "{seq}").map_err(|e| CopyError::Backend(e.to_string()))?;
    out.flush().map_err(|e| CopyError::Backend(e.to_string()))?;
    Ok(())
}

/// Read an image from the system clipboard and encode it to PNG bytes.
///
/// Returns `Ok(Some(png))` when the clipboard holds a bitmap image,
/// `Ok(None)` when it holds no image (the caller falls back to treating
/// the paste as text), and `Err` only when the clipboard backend itself
/// is unavailable. arboard hands us raw RGBA (`width`/`height`/`bytes`);
/// we wrap it in an `image::RgbaImage` and re-encode as PNG so every
/// provider gets a normalized, self-describing payload. Mirrors codex's
/// `clipboard_paste::paste_image_as_png`, minus the file-list fallback
/// (we only care about a real bitmap on the clipboard, not file paths).
///
/// Local clipboard only — SSH image paste is out of scope, and arboard
/// has no remote pathway anyway.
pub fn read_image_as_png() -> Result<Option<Vec<u8>>, CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|e| CopyError::Backend(e.to_string()))?;
    let img = match cb.get_image() {
        Ok(img) => img,
        // No image on the clipboard is the common case (the user pasted
        // text); surface it as `None`, not an error.
        Err(_) => return Ok(None),
    };
    let w = img.width as u32;
    let h = img.height as u32;
    let Some(rgba) = image::RgbaImage::from_raw(w, h, img.bytes.into_owned()) else {
        return Err(CopyError::Backend(
            "clipboard image had an invalid RGBA buffer".to_string(),
        ));
    };
    let dynimg = image::DynamicImage::ImageRgba8(rgba);
    let mut png = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut png);
    dynimg
        .write_to(&mut cursor, image::ImageFormat::Png)
        .map_err(|e| CopyError::Backend(format!("PNG encode failed: {e}")))?;
    Ok(Some(png))
}

/// Read plain text from the system clipboard.
///
/// Returns `Ok(Some(text))` when the clipboard holds text, `Ok(None)`
/// when it holds no text (e.g. an image or an empty clipboard), and
/// `Err` only when the clipboard backend itself is unavailable. Used by
/// the composer vim register mirror so an OS copy is pasteable with
/// `p`/`P`. Local clipboard only (arboard) — OSC52 is write-only and
/// SSH has no read pathway.
pub fn read_text() -> Result<Option<String>, CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|e| CopyError::Backend(e.to_string()))?;
    match cb.get_text() {
        Ok(text) => Ok(Some(text)),
        // No text on the clipboard is the common case (image, empty);
        // surface it as `None`, not an error.
        Err(_) => Ok(None),
    }
}

fn arboard_set_text(text: &str) -> Result<(), CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|e| CopyError::Backend(e.to_string()))?;
    cb.set_text(text.to_string())
        .map_err(|e| CopyError::Backend(e.to_string()))?;
    Ok(())
}

fn arboard_set_html(html: &str, plain: &str) -> Result<(), CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|e| CopyError::Backend(e.to_string()))?;
    cb.set_html(html.to_string(), Some(plain.to_string()))
        .map_err(|e| CopyError::Backend(e.to_string()))?;
    Ok(())
}

/// Convert a markdown source string to a self-contained HTML fragment
/// suitable for the system clipboard's HTML slot. Used by the
/// rich-text copy keybind (plan.md T8.g).
pub fn markdown_to_html(markdown: &str) -> String {
    use pulldown_cmark::{Options, Parser, html};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_SMART_PUNCTUATION);
    let parser = Parser::new_ext(markdown, opts);
    let mut buf = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut buf, parser);
    buf
}

/// Render a markdown source string to plain text — drops the
/// formatting markers (`**`, `_`, backticks, ATX `#`, etc.) and
/// keeps readable structure (paragraph breaks, list items as
/// "- item", code block contents on their own lines). Used by the
/// "Copy as plain text" context-menu action.
pub fn markdown_to_plain(markdown: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(markdown, opts);
    let mut out = String::with_capacity(markdown.len());
    // Track list nesting to render bullets/numbered prefixes.
    let mut list_stack: Vec<Option<u64>> = Vec::new();
    let mut at_block_start = true;
    let mut in_code_block = false;
    for event in parser {
        match event {
            Event::Start(Tag::Paragraph) => {
                ensure_paragraph_break(&mut out);
                at_block_start = true;
            }
            Event::End(TagEnd::Paragraph) => {
                out.push('\n');
                at_block_start = true;
            }
            Event::Start(Tag::Heading { .. }) => {
                ensure_paragraph_break(&mut out);
                // No `#` prefix; the next text + a trailing blank
                // line gives the heading enough visual weight on its
                // own in a plain-text paste.
            }
            Event::End(TagEnd::Heading(_)) => {
                out.push_str("\n\n");
                at_block_start = true;
            }
            Event::Start(Tag::BlockQuote(_)) => {
                ensure_paragraph_break(&mut out);
                out.push_str("> ");
                at_block_start = false;
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                out.push('\n');
                at_block_start = true;
            }
            Event::Start(Tag::CodeBlock(_)) => {
                ensure_paragraph_break(&mut out);
                in_code_block = true;
                at_block_start = true;
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code_block = false;
                out.push('\n');
                at_block_start = true;
            }
            Event::Start(Tag::List(start)) => {
                ensure_paragraph_break(&mut out);
                list_stack.push(start);
                at_block_start = true;
            }
            Event::End(TagEnd::List(_)) => {
                list_stack.pop();
                if list_stack.is_empty() {
                    out.push('\n');
                }
                at_block_start = true;
            }
            Event::Start(Tag::Item) => {
                if !at_block_start {
                    out.push('\n');
                }
                let depth = list_stack.len().saturating_sub(1);
                for _ in 0..depth {
                    out.push_str("  ");
                }
                if let Some(top) = list_stack.last_mut() {
                    match top {
                        Some(n) => {
                            out.push_str(&format!("{n}. "));
                            *n += 1;
                        }
                        None => out.push_str("- "),
                    }
                }
                at_block_start = false;
            }
            Event::End(TagEnd::Item) => {
                at_block_start = true;
            }
            Event::Start(Tag::Emphasis | Tag::Strong | Tag::Strikethrough) => {}
            Event::End(TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough) => {}
            Event::Start(Tag::Link { .. }) => {}
            Event::End(TagEnd::Link) => {}
            Event::Start(Tag::Image { .. }) => {}
            Event::End(TagEnd::Image) => {}
            Event::Text(s) => {
                out.push_str(&s);
                at_block_start = false;
            }
            Event::Code(s) => {
                // Inline code stays as the bare text — no backticks.
                out.push_str(&s);
                at_block_start = false;
            }
            Event::SoftBreak => {
                if in_code_block {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                at_block_start = false;
            }
            Event::HardBreak => {
                out.push('\n');
                at_block_start = false;
            }
            Event::Rule => {
                ensure_paragraph_break(&mut out);
                out.push_str("---\n\n");
                at_block_start = true;
            }
            Event::Html(s) | Event::InlineHtml(s) => {
                out.push_str(&s);
                at_block_start = false;
            }
            _ => {}
        }
    }
    // Collapse trailing whitespace + newlines so the pasted result
    // doesn't end with a sea of blank lines.
    while out.ends_with(['\n', ' ']) {
        out.pop();
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock {
    pub lang: Option<String>,
    pub body: String,
}

pub fn extract_code_blocks(markdown: &str) -> Vec<CodeBlock> {
    use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
    let mut blocks = Vec::new();
    let mut current: Option<CodeBlock> = None;
    let parser = Parser::new_ext(markdown, Options::empty());
    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match kind {
                    CodeBlockKind::Fenced(info) => {
                        let lang = info.split_whitespace().next().unwrap_or("").trim();
                        (!lang.is_empty()).then(|| lang.to_string())
                    }
                    CodeBlockKind::Indented => None,
                };
                current = Some(CodeBlock {
                    lang,
                    body: String::new(),
                });
            }
            Event::End(TagEnd::CodeBlock) => {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
            }
            Event::Text(text) | Event::Code(text) if current.is_some() => {
                if let Some(block) = current.as_mut() {
                    block.body.push_str(&text);
                }
            }
            Event::SoftBreak | Event::HardBreak if current.is_some() => {
                if let Some(block) = current.as_mut() {
                    block.body.push('\n');
                }
            }
            _ => {}
        }
    }
    blocks
}

/// Ensure the buffer ends with a paragraph break (`\n\n`) before
/// appending a new block. No-op when the buffer is empty or already
/// terminates that way.
fn ensure_paragraph_break(out: &mut String) {
    if out.is_empty() {
        return;
    }
    while out.ends_with(' ') {
        out.pop();
    }
    if !out.ends_with("\n\n") {
        if out.ends_with('\n') {
            out.push('\n');
        } else {
            out.push_str("\n\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_sequence_outside_tmux_is_raw_only() {
        let seq = osc52_sequence("QUJD", false);
        assert_eq!(seq, "\x1b]52;c;QUJD\x07");
    }

    #[test]
    fn osc52_sequence_inside_tmux_double_emits_wrapped() {
        let seq = osc52_sequence("QUJD", true);
        // Raw form, then the DCS-passthrough-wrapped form: leading ESC
        // doubled, inner BEL untouched, terminated with ST (`ESC \`).
        assert_eq!(
            seq,
            "\x1b]52;c;QUJD\x07\x1bPtmux;\x1b\x1b]52;c;QUJD\x07\x1b\\"
        );
        // The inner BEL must not be doubled.
        assert!(!seq.contains("\x07\x07"));
    }

    #[test]
    fn osc52_size_guard_rejects_oversized_payload() {
        // One raw byte yields ~1.34 base64 chars, so this comfortably
        // exceeds the base64 ceiling.
        let big = "x".repeat(OSC52_MAX_B64);
        match osc52_set_clipboard(&big) {
            Err(CopyError::TooLarge { max }) => assert_eq!(max, OSC52_MAX_B64),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn osc52_size_guard_allows_just_under_ceiling() {
        // Pick a raw length whose base64 length is at or just under the
        // ceiling: base64 len = 4 * ceil(n / 3).
        let n = (OSC52_MAX_B64 / 4) * 3;
        let payload = "y".repeat(n);
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        assert!(encoded.len() <= OSC52_MAX_B64);
        assert!(osc52_set_clipboard(&payload).is_ok());
    }

    #[test]
    fn copy_plain_osc52_too_large_local_success_is_accepted() {
        let outcome = copy_plain_with(
            "hello",
            false,
            |_| Err(CopyError::TooLarge { max: OSC52_MAX_B64 }),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            outcome,
            CopyOutcome {
                osc52_written: false,
                local_clipboard_written: true
            }
        );
    }

    #[test]
    fn copy_plain_osc52_too_large_over_ssh_errors() {
        let err = copy_plain_with(
            "hello",
            true,
            |_| Err(CopyError::TooLarge { max: OSC52_MAX_B64 }),
            |_| panic!("local clipboard must not run over SSH"),
        )
        .expect_err("no observable backend accepted");
        assert!(matches!(err, CopyError::TooLarge { .. }));
    }

    #[test]
    fn copy_plain_local_failure_outside_ssh_keeps_osc52_acceptance() {
        let outcome = copy_plain_with(
            "hello",
            false,
            |_| Ok(()),
            |_| Err(CopyError::Backend("local unavailable".to_string())),
        )
        .unwrap();
        assert_eq!(
            outcome,
            CopyOutcome {
                osc52_written: true,
                local_clipboard_written: false
            }
        );
    }

    #[test]
    fn copy_plain_all_observable_backends_fail_errors() {
        let err = copy_plain_with(
            "hello",
            false,
            |_| Err(CopyError::Backend("osc failed".to_string())),
            |_| Err(CopyError::Backend("local failed".to_string())),
        )
        .expect_err("all backends failed");
        assert!(matches!(err, CopyError::Backend(_)));
    }

    #[test]
    fn extract_code_blocks_fenced_returns_body_and_lang() {
        let blocks = extract_code_blocks("```rust\nlet x=1;\n```");
        assert_eq!(
            blocks,
            vec![CodeBlock {
                lang: Some("rust".to_string()),
                body: "let x=1;\n".to_string()
            }]
        );
    }

    #[test]
    fn extract_code_blocks_multiple_in_document_order() {
        let blocks = extract_code_blocks("```sh\necho one\n```\ntext\n```\ntwo\n```");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].lang.as_deref(), Some("sh"));
        assert_eq!(blocks[0].body, "echo one\n");
        assert_eq!(blocks[1].lang, None);
        assert_eq!(blocks[1].body, "two\n");
    }

    #[test]
    fn extract_code_blocks_indented_block() {
        let blocks = extract_code_blocks("prose\n\n    indented\n    block\n");
        assert_eq!(
            blocks,
            vec![CodeBlock {
                lang: None,
                body: "indented\nblock\n".to_string()
            }]
        );
    }

    #[test]
    fn extract_code_blocks_none_for_prose() {
        assert!(extract_code_blocks("plain prose only").is_empty());
    }
}
