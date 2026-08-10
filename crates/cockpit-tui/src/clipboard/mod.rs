//! Trusted ordered clipboard delivery (native → OSC52 → executable).
//!
//! One service evaluates routes in order, stops at first Confirmed, continues
//! after unacknowledged OSC52 (Unverified), and never writes plaintext to disk.
//! OSC52 size uses the sole
//! [`cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES`] contract.

mod display;
mod executable;
pub mod feedback;
pub mod file_publish;
mod native;
mod osc52;
pub mod recovery;
mod service;
mod types;

#[cfg(test)]
mod tests;

pub use recovery::ClipboardRecovery;
pub use service::{ClipboardService, attached_client_route_exists};
pub use types::{
    AttemptOutcome, AttemptRecord, Confidence, CopyError, CopyRequest, DeliveryResult, Downgrade,
    Eligibility, OscTransport, PlatformKind, Representation, RichPolicy, Route, SafeErrorKind,
    SessionContext, SkipReason,
};

/// Copy plain text through the shared delivery service.
///
/// Returns `Ok(result)` when confidence is Confirmed or Unverified, and
/// `Err` only for Failed (including empty/over-limit pre-route failures).
/// `recovery` is `tui.clipboard_recovery`: when
/// [`ClipboardRecovery::PrivateFile`], a failed/unverified delivery also
/// writes one private bounded recovery artifact (never on a Confirmed
/// delivery, and never any filesystem operation at all when `Off`).
pub fn copy_plain(text: &str, recovery: ClipboardRecovery) -> Result<DeliveryResult, CopyError> {
    let mut svc = ClipboardService::system();
    let result = svc.deliver_plain(text);
    self::recovery::observe_delivery(recovery, result.confidence, text);
    if result.delivered() {
        Ok(result)
    } else if text.is_empty() {
        Err(CopyError::Empty)
    } else {
        Err(result.failure_error())
    }
}

/// Copy rich text (HTML + plain) with [`RichPolicy::AllowPlainDowngrade`].
///
/// Preferred entry for UI actions that should visibly fall back to plain.
/// See [`copy_plain`] for the `recovery` parameter.
pub fn copy_rich(
    plain: &str,
    html: &str,
    recovery: ClipboardRecovery,
) -> Result<DeliveryResult, CopyError> {
    copy_rich_with_policy(plain, html, RichPolicy::AllowPlainDowngrade, recovery)
}

/// Copy rich text with an explicit policy. See [`copy_plain`] for the
/// `recovery` parameter — the recovery artifact always holds the plain
/// text alternative, never the HTML.
pub fn copy_rich_with_policy(
    plain: &str,
    html: &str,
    policy: RichPolicy,
    recovery: ClipboardRecovery,
) -> Result<DeliveryResult, CopyError> {
    let mut svc = ClipboardService::system();
    let result = svc.deliver_rich(plain, html, policy);
    self::recovery::observe_delivery(recovery, result.confidence, plain);
    if result.delivered() {
        Ok(result)
    } else {
        Err(result.failure_error())
    }
}

/// Read an image from the system clipboard and encode it to PNG bytes.
///
/// Paste path only — not part of the copy routing service. Local clipboard
/// only; SSH image paste is out of scope.
pub fn read_image_as_png() -> Result<Option<Vec<u8>>, CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|_| CopyError::Backend)?;
    let img = match cb.get_image() {
        Ok(img) => img,
        Err(_) => return Ok(None),
    };
    const MAX_DIMENSION: usize = 8_192;
    const MAX_PIXELS: usize = 40_000_000;
    const MAX_RGBA_BYTES: usize = 160_000_000;
    if img.width > MAX_DIMENSION
        || img.height > MAX_DIMENSION
        || img
            .width
            .checked_mul(img.height)
            .is_none_or(|pixels| pixels > MAX_PIXELS)
        || img.bytes.len() > MAX_RGBA_BYTES
    {
        return Err(CopyError::Backend);
    }
    let w = u32::try_from(img.width).map_err(|_| CopyError::Backend)?;
    let h = u32::try_from(img.height).map_err(|_| CopyError::Backend)?;
    let Some(rgba) = image::RgbaImage::from_raw(w, h, img.bytes.into_owned()) else {
        return Err(CopyError::Backend);
    };
    let dynimg = image::DynamicImage::ImageRgba8(rgba);
    let mut png = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut png);
    dynimg
        .write_to(&mut cursor, image::ImageFormat::Png)
        .map_err(|_| CopyError::Backend)?;
    Ok(Some(png))
}

/// Read plain text from the system clipboard (paste path).
pub fn read_text() -> Result<Option<String>, CopyError> {
    let mut cb = arboard::Clipboard::new().map_err(|_| CopyError::Backend)?;
    match cb.get_text() {
        Ok(text) => Ok(Some(text)),
        Err(_) => Ok(None),
    }
}

/// Convert markdown to a self-contained HTML fragment for the rich slot.
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

/// Render markdown to plain text (drop markers, keep structure).
pub fn markdown_to_plain(markdown: &str) -> String {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(markdown, opts);
    let mut out = String::with_capacity(markdown.len());
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
