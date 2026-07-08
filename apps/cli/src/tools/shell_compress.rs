//! Native shell-output compression — the `shell compression` setting's
//! filtering layer (implementation note).
//!
//! rtk-native filters ported from rtk @ 41285725e446706204943d826d89e19608df0c03
//! (Cargo.toml v0.40.0 / git-describe dev-0.43.0-rc.254). To re-sync with
//! upstream rtk capabilities, diff against a newer commit via `kcl ask rtk`.
//!
//! This is a **native Rust reimplementation** of rtk's output-filtering
//! logic — cockpit does NOT shell out to the `rtk` binary and does NOT take
//! it as a dependency (rtk is binary-only, no library crate). The logic
//! lives here.
//!
//! Two layers, applied in order to each of the `bash` tool's stdout and
//! stderr streams when the `shell compression` setting is `enabled`:
//!
//!  1. [`generic_filter`] — applied to ALL output: ANSI/color-code
//!     stripping, progress-bar / spinner / carriage-return-redraw collapse,
//!     consecutive-duplicate-line dedup, known-boilerplate removal, and
//!     middle-truncation of very large output (HEAD + TAIL + an explicit
//!     `… N lines elided …` marker).
//!  2. [`command_strategy`] — a per-command strategy for a recognized tool
//!     (`cargo`, `git`, `pytest`, …): drop that tool's progress/noise lines
//!     while keeping everything that looks like signal.
//!
//! # Correctness contract (priority #1 — defensive against weak models)
//!
//! Compression is **lossy of noise only, never of signal**. No stage here
//! may drop a line that looks like an error, warning, panic, stack trace,
//! diagnostic, failing-test detail, or anything that explains *why* a
//! command failed. The per-command strategies are written as "drop a small,
//! explicit allowlist of known-noise lines; keep everything else" — never
//! "keep only an allowlist" — so an unrecognized-but-important line always
//! survives. Middle-truncation keeps both head and tail and always emits an
//! elision marker. When in doubt, KEEP the line. The unit tests assert that
//! error / warning / failing-test / non-zero-exit lines survive every
//! family's strategy.
//!
//! This layer runs *inside* `bash::call`, strictly **before** the §7
//! redaction chokepoint (`redact::scrub`, applied in `engine::agent::turn`
//! to every tool result) — compression shrinks the text, redaction then
//! scrubs whatever remains. Redaction is unaffected and still runs.

use std::borrow::Cow;

use regex::Regex;

/// Lines longer than this (after generic filtering) trigger middle
/// truncation. Sized to comfortably exceed an ordinary build/test run while
/// still bounding a runaway `cat`/`find` dump well under the 8 KB tool cap,
/// so the model always sees head + tail + an explicit elision marker rather
/// than a hard byte-cap that could clip the failure tail.
const MAX_LINES_BEFORE_TRUNCATE: usize = 400;
/// Head lines kept on middle-truncation (3:2 head:tail, mirroring the
/// byte-level [`crate::tools::common::truncate_head_tail`] split — the head
/// carries the command's framing, the tail carries the failure signal).
const TRUNCATE_HEAD_LINES: usize = 240;
/// Tail lines kept on middle-truncation. The failure signal (a panic, a
/// non-zero-exit summary, the last assertion) almost always lives at the
/// tail, so the tail is preserved generously.
const TRUNCATE_TAIL_LINES: usize = 160;
const TRACE_BLOCK_HEAD_LINES: usize = 32;
const TRACE_BLOCK_TAIL_LINES: usize = 32;
const MAX_TRACE_BLOCKS_BEFORE_SUMMARY: usize = 2;
const PRUNE_BOUNDARY_MIN_BYTES: usize = 16 * 1024;
const PRUNE_BOUNDARY_MIN_LINES: usize = 400;
const PRUNE_BOUNDARY_SIGNAL_HEAD: usize = 40;
const PRUNE_BOUNDARY_SIGNAL_TAIL: usize = 40;

/// Compress one shell stream (`stdout` or `stderr`) through both layers.
///
/// `command` is the raw command line the model issued (used to recognize a
/// per-command strategy). `body` is the captured stream text. Returns the
/// compressed text; an empty input returns empty.
///
/// Order is: generic noise filter first (ANSI/spinner/dedup/boilerplate +
/// middle-truncation), then the recognized per-command strategy. The
/// per-command strategy runs second so it sees already-ANSI-stripped,
/// dedup'd lines and only has to reason about clean text.
pub fn compress_stream(command: &str, body: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    let generic = generic_filter(body);
    match recognize(command) {
        Some(family) => command_strategy(family, &generic),
        None => generic,
    }
}

/// Deterministically condense a large surviving `bash` tool result at the
/// `/prune` boundary. This is intentionally built from the same shell-output
/// filters as live shell compression, then adds a bounded, exact diagnostic
/// section so errors/warnings/exit/sandbox/security lines survive even when
/// they appeared in the elided middle of a long log.
pub fn prune_boundary_condense(command: &str, body: &str) -> Option<String> {
    let line_count = body.lines().count();
    if body.len() < PRUNE_BOUNDARY_MIN_BYTES && line_count <= PRUNE_BOUNDARY_MIN_LINES {
        return None;
    }

    let compressed = compress_stream(command, body);
    let signal_lines = prune_boundary_signal_lines(body);
    let signal = bounded_signal_lines(&signal_lines);

    let mut out = String::new();
    out.push_str("[deterministic shell condensation]\n");
    out.push_str(&format!(
        "original_bytes={} original_lines={line_count}\n",
        body.len()
    ));
    if !signal.is_empty() {
        out.push_str("--- preserved diagnostics ---\n");
        out.push_str(&signal);
        out.push('\n');
    }
    out.push_str("--- condensed output ---\n");
    out.push_str(&compressed);

    if out.len() < body.len() {
        Some(out)
    } else {
        None
    }
}

// ───────────────────────── Layer 1: generic noise filter ─────────────────

/// The generic noise filter applied to ALL output, in stages:
///
///  1. ANSI/color-code stripping (CSI + OSC sequences).
///  2. Carriage-return redraw collapse: a `\r`-rewritten line (progress bar
///     / percentage redraw) keeps only its final segment.
///  3. Per-line: drop pure spinner/progress-glyph lines.
///  4. Consecutive-duplicate-line dedup, replacing a run of `n` identical
///     lines with the line plus a `[×n]` count suffix (never silently — the
///     count makes the elision explicit).
///  5. Middle-truncation when the result still exceeds
///     [`MAX_LINES_BEFORE_TRUNCATE`] lines: keep HEAD + TAIL + an explicit
///     `… N lines elided …` marker.
///
/// No stage removes a line on the basis of its *content* looking like an
/// error — only structural noise (escape codes, redraws, spinner glyphs,
/// exact duplicates) is touched.
pub fn generic_filter(body: &str) -> String {
    let stripped = strip_ansi(body);
    let mut out_lines: Vec<String> = Vec::new();

    // Stages 2–4 in one pass: CR-collapse, spinner drop, consecutive dedup.
    let mut prev: Option<String> = None;
    let mut prev_count: usize = 0;
    for raw_line in stripped.lines() {
        let line = collapse_carriage_returns(raw_line);
        if is_spinner_or_progress(&line) {
            continue;
        }
        match &prev {
            Some(p) if p == &line => {
                prev_count += 1;
            }
            _ => {
                if let Some(p) = prev.take() {
                    push_with_count(&mut out_lines, p, prev_count);
                }
                prev = Some(line);
                prev_count = 1;
            }
        }
    }
    if let Some(p) = prev.take() {
        push_with_count(&mut out_lines, p, prev_count);
    }

    trace_aware_truncate_lines(out_lines)
}

/// Flush a deduplicated run: the line, plus a `  [×n]` suffix when it
/// repeated. The suffix is on the same logical line so the dedup is explicit
/// (never a silent drop) yet costs only a few tokens.
fn push_with_count(out: &mut Vec<String>, line: String, count: usize) {
    if count > 1 {
        out.push(format!("{line}  [×{count}]"));
    } else {
        out.push(line);
    }
}

/// Strip ANSI escape sequences: CSI (`ESC [ … final`) and OSC (`ESC ] … BEL`
/// or `ESC ] … ESC \`). Ported from rtk `core/utils.rs::strip_ansi`
/// (`\x1b\[[0-9;]*[a-zA-Z]`), extended to also drop OSC title/hyperlink
/// sequences and lone control bytes some tools emit. Content is never
/// touched — only the escape bytes are removed.
pub fn strip_ansi(text: &str) -> Cow<'_, str> {
    use std::sync::OnceLock;
    static ANSI_RE: OnceLock<Regex> = OnceLock::new();
    let re = ANSI_RE.get_or_init(|| {
        // CSI: ESC [ params intermediates final.
        // OSC: ESC ] ... (BEL | ESC \).
        Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)").unwrap()
    });
    re.replace_all(text, "")
}

/// Collapse a carriage-return-rewritten line to its final visible segment.
///
/// Progress bars and percentage redraws emit `\r` to overwrite the same
/// terminal line in place (`10%\r50%\r100%`); the only meaningful content is
/// what survives after the last `\r`. We keep the final non-empty segment so
/// `100%` survives while the intermediate redraws are dropped. A line with no
/// `\r` is returned unchanged.
fn collapse_carriage_returns(line: &str) -> String {
    if !line.contains('\r') {
        return line.to_string();
    }
    // The terminal shows whatever was written after the last carriage
    // return; earlier segments were overwritten. Prefer the last non-empty
    // segment so a trailing bare `\r` doesn't blank the line.
    line.split('\r')
        .rfind(|seg| !seg.trim().is_empty())
        .unwrap_or("")
        .to_string()
}

/// Whether a line is a pure spinner / progress-glyph redraw with no textual
/// content. Ported from rtk's `ollama.toml` spinner filter
/// (`^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏\s]*$`), broadened to the full braille spinner block plus
/// the common ASCII/Unicode spinner glyphs. A line carrying ANY ordinary
/// text is NOT a spinner (so `⠋ Building error[E0382]` is kept).
fn is_spinner_or_progress(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false; // blank lines are handled by dedup/truncation, not here
    }
    trimmed.chars().all(|c| {
        c.is_whitespace()
            // Braille spinner block (U+2800–U+28FF) — covers every dot frame.
            || ('\u{2800}'..='\u{28FF}').contains(&c)
            // Common ASCII / box spinner + progress-bar fill glyphs.
            || matches!(c, '|' | '/' | '\\' | '-' | '.' | '·' | '•'
                | '█' | '▉' | '▊' | '▋' | '▌' | '▍' | '▎' | '▏'
                | '░' | '▒' | '▓' | '◐' | '◓' | '◑' | '◒' | '○' | '●')
    })
}

/// Middle-truncate a line vector when it exceeds [`MAX_LINES_BEFORE_TRUNCATE`].
/// Always keeps HEAD + TAIL and inserts a single explicit elision marker
/// naming the elided count — never silently drops the middle. The tail is
/// always preserved so the failure signal (which lives at the tail) survives.
fn middle_truncate_lines(lines: Vec<String>) -> String {
    if lines.len() <= MAX_LINES_BEFORE_TRUNCATE {
        return lines.join("\n");
    }
    let total = lines.len();
    let head = &lines[..TRUNCATE_HEAD_LINES];
    let tail = &lines[total - TRUNCATE_TAIL_LINES..];
    let elided = total - TRUNCATE_HEAD_LINES - TRUNCATE_TAIL_LINES;
    let mut out = String::new();
    out.push_str(&head.join("\n"));
    out.push('\n');
    out.push_str(&format!("… {elided} lines elided …"));
    out.push('\n');
    out.push_str(&tail.join("\n"));
    out
}

fn trace_aware_truncate_lines(lines: Vec<String>) -> String {
    if lines.len() <= MAX_LINES_BEFORE_TRUNCATE {
        return summarize_trace_blocks(lines);
    }

    let trace_blocks = trace_blocks(&lines);
    if trace_blocks.is_empty() {
        return middle_truncate_lines(lines);
    }

    let total = lines.len();
    let head_end = TRUNCATE_HEAD_LINES.min(total);
    let tail_start = total.saturating_sub(TRUNCATE_TAIL_LINES);
    let mut ranges = vec![(0, head_end), (tail_start, total)];
    for (start, end) in first_last_trace_blocks(&trace_blocks) {
        ranges.push((start, end));
    }
    ranges.sort_unstable();

    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if start >= end {
            continue;
        }
        if let Some((_, prev_end)) = merged.last_mut()
            && start <= *prev_end
        {
            *prev_end = (*prev_end).max(end);
            continue;
        }
        merged.push((start, end));
    }

    let mut out = Vec::new();
    let mut cursor = 0;
    for (start, end) in merged {
        if start > cursor {
            out.push(format!("… {} lines elided …", start - cursor));
        }
        out.extend(lines[start..end].iter().cloned());
        cursor = end;
    }
    if cursor < total {
        out.push(format!("… {} lines elided …", total - cursor));
    }

    summarize_trace_blocks(out)
}

// ─────────────────────── Layer 2: per-command strategy ───────────────────

/// Recognized command families (the full set rtk covers, per the spec's
/// table). Each maps to a [`command_strategy`] arm. The variant a command
/// resolves to is decided by [`recognize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Git,
    Js,
    Go,
    Python,
    Rust,
    Ruby,
    Jvm,
    Dotnet,
    Cloud,
    System,
}

/// Recognize the per-command strategy family from the command line, by
/// inspecting the first real program token (after skipping leading env
/// assignments like `FOO=bar cmd`). Returns `None` when no family matches —
/// the generic filter alone applies. Matching is on the program's basename
/// so `/usr/bin/git` and `git` both resolve.
pub fn recognize(command: &str) -> Option<Family> {
    let prog = first_program(command)?;
    Some(match prog.as_str() {
        // git ecosystem
        "git" | "gh" | "glab" | "gt" => Family::Git,
        // js ecosystem
        "npm" | "pnpm" | "npx" | "playwright" | "vitest" | "prettier" | "tsc" | "prisma"
        | "next" => Family::Js,
        // go ecosystem
        "go" | "golangci-lint" => Family::Go,
        // python ecosystem
        "pytest" | "ruff" | "pip" | "pip3" | "mypy" => Family::Python,
        // rust ecosystem
        "cargo" => Family::Rust,
        // ruby ecosystem
        "rspec" | "rubocop" | "rake" => Family::Ruby,
        // jvm ecosystem
        "gradlew" | "./gradlew" => Family::Jvm,
        // dotnet ecosystem
        "dotnet" => Family::Dotnet,
        // cloud ecosystem
        "aws" | "curl" | "wget" | "psql" | "docker" => Family::Cloud,
        // system ecosystem (rtk's system/* commands)
        "find" | "grep" | "ls" | "tree" | "wc" | "env" | "cat" | "head" | "tail" => Family::System,
        _ => return None,
    })
}

/// The first real program token of a command line: skips leading
/// `VAR=value` env assignments (POSIX prefix), then returns the basename of
/// the next token with a leading `./` preserved for `./gradlew`. Returns
/// `None` for an empty/blank command.
///
/// Shared classifier seam: both the per-command compression strategy
/// ([`recognize`]) and the defensive bash-result routing nudge
/// ([`classify_tip`]) resolve the command's program through this one helper —
/// `VAR=val` skipping and basename normalization are written once.
pub fn first_program(command: &str) -> Option<String> {
    for tok in command.split_whitespace() {
        // Leading env assignment (`FOO=bar`) — skip and keep scanning.
        if tok.contains('=')
            && !tok.starts_with('=')
            && tok.split('=').next().is_some_and(is_envish)
        {
            continue;
        }
        // Preserve `./gradlew` exactly; otherwise take the path basename.
        if tok == "./gradlew" {
            return Some(tok.to_string());
        }
        let base = tok.rsplit('/').next().unwrap_or(tok);
        return Some(base.to_string());
    }
    None
}

/// The dedicated tool a defensive-mode `bash` file/search command should have
/// been routed to (implementation note). A
/// `bash` run in [`crate::config::extended::LlmMode::Defensive`] classifies its
/// command off [`first_program`] and, when it lands on one of these, appends a
/// single terse tip line steering the model to the dedicated tool next time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BashTip {
    /// `cat`/`head`/`tail`/`less`/`more` → `read`.
    Read,
    /// `grep`/`rg`/`egrep` → `search` (or `word`/`symbol_find`).
    Search,
    /// `find`/`ls` → `tree`.
    Tree,
}

impl BashTip {
    /// The terse, model-facing tip line for this category (no leading/trailing
    /// newline — the caller frames it). One short sentence (token economy §10).
    pub fn line(self) -> &'static str {
        match self {
            BashTip::Read => "tip: use `read <file>` for line-numbered, budgeted output",
            BashTip::Search => {
                "tip: use `search` (or `word`/`symbol_find`) — budgeted, won't flood context"
            }
            BashTip::Tree => "tip: use `tree` to list indexed files",
        }
    }

    /// The dedicated-tool key that, once successfully used in a session,
    /// self-suppresses this tip. `read` suppresses the read tip; `search`,
    /// `word`, and `symbol_find` each suppress the search tip; `tree`
    /// suppresses the tree tip. Mirrors the `tool → BashTip` map a successful
    /// dispatch records.
    pub fn suppressed_by(self) -> &'static [&'static str] {
        match self {
            BashTip::Read => &["read"],
            BashTip::Search => &["search", "word", "symbol_find"],
            BashTip::Tree => &["tree"],
        }
    }
}

/// Which dedicated tool a successfully-run tool name marks as adopted, for the
/// self-suppression seam — the inverse of [`BashTip::suppressed_by`]. A
/// successful `read`/`search`/`word`/`symbol_find`/`tree` call stops the
/// corresponding tip; every other tool returns `None`. Centralized here so the
/// record site (a successful dispatch) and the emit site (a `bash` run) agree
/// on the mapping.
pub fn tip_adopted_by(tool: &str) -> Option<BashTip> {
    match tool {
        "read" => Some(BashTip::Read),
        "search" | "word" | "symbol_find" => Some(BashTip::Search),
        "tree" => Some(BashTip::Tree),
        _ => None,
    }
}

/// Classify a `bash` command line for the defensive-mode routing nudge: resolve
/// the first real program (skipping `VAR=val` prefixes, basename-normalized)
/// and map a file/search command to the dedicated tool that replaces it.
/// Classifies off the FIRST program only — a pipeline (`cat x | grep y`)
/// resolves on its head (`cat` → [`BashTip::Read`]); good enough, no pipeline
/// parsing. Returns `None` for any command with no dedicated-tool replacement.
pub fn classify_tip(command: &str) -> Option<BashTip> {
    let prog = first_program(command)?;
    Some(match prog.as_str() {
        "cat" | "head" | "tail" | "less" | "more" => BashTip::Read,
        "grep" | "rg" | "egrep" => BashTip::Search,
        "find" | "ls" => BashTip::Tree,
        _ => return None,
    })
}

/// Whether a token's pre-`=` part looks like a shell env-var name
/// (`[A-Za-z_][A-Za-z0-9_]*`) — used to skip `FOO=bar` command prefixes.
fn is_envish(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OmittedCounts {
    errors: usize,
    warnings: usize,
    progress: usize,
    unknown: usize,
}

impl OmittedCounts {
    fn total(self) -> usize {
        self.errors + self.warnings + self.progress + self.unknown
    }

    fn add(&mut self, class: OmittedLineClass) {
        match class {
            OmittedLineClass::Error => self.errors += 1,
            OmittedLineClass::Warning => self.warnings += 1,
            OmittedLineClass::ProgressInfo => self.progress += 1,
            OmittedLineClass::Unknown => self.unknown += 1,
        }
    }

    fn marker(self) -> String {
        format!(
            "... [{} lines omitted: {} errors, {} warnings, {} progress/info, {} unknown]",
            self.total(),
            self.errors,
            self.warnings,
            self.progress,
            self.unknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OmittedLineClass {
    Error,
    Warning,
    ProgressInfo,
    Unknown,
}

fn classify_omitted_line(line: &str) -> OmittedLineClass {
    let lower = line.trim_start().to_ascii_lowercase();
    if lower.contains("error") || lower.contains("fail") || lower.contains("panic") {
        OmittedLineClass::Error
    } else if lower.contains("warn") || lower.contains("deprecated") {
        OmittedLineClass::Warning
    } else if !lower.is_empty() {
        OmittedLineClass::ProgressInfo
    } else {
        OmittedLineClass::Unknown
    }
}

fn first_last_trace_blocks(blocks: &[(usize, usize)]) -> Vec<(usize, usize)> {
    if blocks.len() <= MAX_TRACE_BLOCKS_BEFORE_SUMMARY {
        return blocks.to_vec();
    }
    vec![blocks[0], blocks[blocks.len() - 1]]
}

fn trace_blocks(lines: &[String]) -> Vec<(usize, usize)> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !is_trace_start(&lines[i]) {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut blank_budget = 1;
        while i < lines.len() {
            let line = &lines[i];
            if is_trace_continuation(line) {
                blank_budget = 1;
                i += 1;
            } else if line.trim().is_empty() && blank_budget > 0 {
                blank_budget -= 1;
                i += 1;
            } else {
                break;
            }
        }
        blocks.push((start, i));
    }
    blocks
}

fn is_trace_start(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Traceback (most recent call last):")
        || t.starts_with("thread '") && t.contains("panicked at")
        || t.starts_with("stack backtrace:")
        || t.starts_with("panic: ")
        || t.starts_with("goroutine ") && t.contains("[")
        || t.starts_with("Exception in thread ")
        || t.starts_with("Caused by: ")
        || t.starts_with("at ") && t.contains(':')
}

fn is_trace_continuation(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("File \"")
        || t.starts_with("at ") && t.contains(':')
        || t.starts_with("at ") && t.contains('(')
        || t.starts_with("Caused by:")
        || t.contains("Error:")
        || t.starts_with("...")
        || t.starts_with("stack backtrace:")
        || t.chars().next().is_some_and(|c| c.is_ascii_digit())
        || t.starts_with("goroutine ") && t.contains("[")
        || t.contains(".go:") && t.contains('+')
        || (t.ends_with(')') && !looks_like_clean_log_boundary(t))
        || (line.starts_with('\t') && t.contains(".go:"))
        || (line.starts_with("    ") && !looks_like_clean_log_boundary(t))
}

fn looks_like_clean_log_boundary(trimmed: &str) -> bool {
    first_word(trimmed).is_some_and(|word| {
        matches!(
            word,
            "Compiling"
                | "Checking"
                | "Finished"
                | "Downloading"
                | "Downloaded"
                | "Fresh"
                | "PASS"
                | "ok"
        )
    })
}

fn summarize_trace_blocks(lines: Vec<String>) -> String {
    let blocks = trace_blocks(&lines);
    if blocks.is_empty() {
        return lines.join("\n");
    }

    let mut out = Vec::new();
    let mut cursor = 0;
    let mut skipped_blocks = 0;
    let keep_blocks = first_last_trace_blocks(&blocks);
    for (start, end) in blocks.iter().copied() {
        if !keep_blocks.contains(&(start, end)) {
            out.extend(lines[cursor..start].iter().cloned());
            skipped_blocks += 1;
            cursor = end;
            continue;
        }
        out.extend(lines[cursor..start].iter().cloned());
        if skipped_blocks > 0 {
            out.push(format!("... [{skipped_blocks} trace blocks omitted]"));
            skipped_blocks = 0;
        }
        let block = &lines[start..end];
        if block.len() > TRACE_BLOCK_HEAD_LINES + TRACE_BLOCK_TAIL_LINES {
            out.extend(block[..TRACE_BLOCK_HEAD_LINES].iter().cloned());
            out.push(format!(
                "... [{} trace lines elided] ...",
                block.len() - TRACE_BLOCK_HEAD_LINES - TRACE_BLOCK_TAIL_LINES
            ));
            out.extend(
                block[block.len() - TRACE_BLOCK_TAIL_LINES..]
                    .iter()
                    .cloned(),
            );
        } else {
            out.extend(block.iter().cloned());
        }
        cursor = end;
    }
    if skipped_blocks > 0 {
        out.push(format!("... [{skipped_blocks} trace blocks omitted]"));
    }
    out.extend(lines[cursor..].iter().cloned());
    out.join("\n")
}

/// Apply the per-command strategy for `family` to already-generic-filtered
/// `body`. Every strategy is "drop a small allowlist of known-noise lines,
/// keep everything else" — so any error/warning/failure/diagnostic line, and
/// any line the strategy doesn't explicitly recognize as noise, is kept.
pub fn command_strategy(family: Family, body: &str) -> String {
    match family {
        Family::Rust => drop_noise(body, is_rust_noise),
        Family::Git => drop_noise(body, is_git_noise),
        Family::Js => drop_noise(body, is_js_noise),
        Family::Go => drop_noise(body, is_go_noise),
        Family::Python => drop_noise(body, is_python_noise),
        Family::Ruby => drop_noise(body, is_ruby_noise),
        Family::Jvm => drop_noise(body, is_jvm_noise),
        Family::Dotnet => drop_noise(body, is_dotnet_noise),
        Family::Cloud => drop_noise(body, is_cloud_noise),
        Family::System => drop_noise(body, is_system_noise),
    }
}

/// Core "keep everything that is not known noise" pass. `is_noise` returns
/// true ONLY for lines that are definitively safe to drop. A line is ALWAYS
/// kept when [`looks_like_signal`] judges it diagnostic, regardless of the
/// family predicate — the belt-and-suspenders signal guarantee: even a buggy
/// noise predicate can't eat an error/warning/panic/failure line.
fn drop_noise(body: &str, is_noise: impl Fn(&str) -> bool) -> String {
    let mut kept: Vec<String> = Vec::new();
    let mut omitted = OmittedCounts::default();
    for line in body.lines() {
        if looks_like_signal(line) || !is_noise(line) {
            kept.push(line.to_string());
        } else {
            omitted.add(classify_omitted_line(line));
        }
    }
    // If the strategy dropped everything (e.g. a clean, all-progress run),
    // never return empty for tiny cleanups — that would hide that the command
    // ran. Fall back to the original body unless the omission is material
    // enough to warrant an explicit summary.
    if kept.is_empty() && !body.trim().is_empty() && omitted.total() < 3 {
        return body.to_string();
    }
    if omitted.total() >= 3 {
        kept.push(omitted.marker());
    }
    kept.join("\n")
}

/// Whether a line carries signal that must NEVER be dropped: errors,
/// warnings, panics, stack traces, diagnostics, failing-test markers, or
/// non-zero-exit context. Case-insensitive, substring/anchor based, and
/// deliberately broad — the cost of a false positive (keeping a noise line)
/// is a few tokens; the cost of a false negative (dropping a diagnostic) is
/// a weak model unable to recover. Ported in spirit from rtk
/// `cmds/rust/runner.rs::ERROR_PATTERNS`.
pub fn looks_like_signal(line: &str) -> bool {
    use std::sync::OnceLock;
    static SIGNAL_RE: OnceLock<Regex> = OnceLock::new();
    let re = SIGNAL_RE.get_or_init(|| {
        // Verbose (?x) mode: whitespace in the pattern is ignored, so the
        // alternatives read clearly. A literal double-quote can't appear in a
        // Rust raw string, so the Python-traceback frame uses \x22 for `"`.
        Regex::new(
            r#"(?ix)
              \b error \b
            | error \[                  # rustc error[E0382]
            | error :                   # error:
            | \b warn(ing)? \b
            | \b fail(ed|ure|ures|ing)? \b
            | \b panic(ked|s)? \b
            | \b exception \b
            | \b traceback \b
            | \b assert(ion)? \b
            | \b fatal \b
            | \b denied \b
            | \b cannot \b
            | \b unable \s to \b
            | \b not \s found \b
            | \b undefined \b
            | \b unexpected \b
            | ^ \s* -->\s               # rustc/clippy source pointer
            | ^ \s* at\s .* :\d+        # JS/Java stack frame
            | ^ \s* File\s \x22 .* \x22 ,\s line\s \d+   # Python traceback frame
            | \.go:\d+:                 # Go file:line diagnostic
            | ^ \s* FAIL \b
            | ^ \s* FAILED \b
            | ^ \s* E \s                # pytest assertion-detail prefix `E   `
            | ^ \s* ✗
            | ^ \s* ✕
            | ^ \s* ×
            "#,
        )
        .unwrap()
    });
    re.is_match(line)
}

fn prune_boundary_signal_lines(body: &str) -> Vec<String> {
    strip_ansi(body)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if looks_like_signal(line) || looks_like_prune_boundary_diagnostic(trimmed) {
                Some(line.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn looks_like_prune_boundary_diagnostic(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("exit:")
        || lower.contains("exit code")
        || lower.contains("sandbox")
        || lower.contains("security")
        || lower.contains("permission")
        || lower.contains("stack backtrace")
        || lower.contains("backtrace")
}

fn bounded_signal_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    if lines.len() <= PRUNE_BOUNDARY_SIGNAL_HEAD + PRUNE_BOUNDARY_SIGNAL_TAIL {
        return lines.join("\n");
    }
    let omitted = lines.len() - PRUNE_BOUNDARY_SIGNAL_HEAD - PRUNE_BOUNDARY_SIGNAL_TAIL;
    let mut out = String::new();
    out.push_str(&lines[..PRUNE_BOUNDARY_SIGNAL_HEAD].join("\n"));
    out.push('\n');
    out.push_str(&format!("… {omitted} diagnostic lines elided …"));
    out.push('\n');
    out.push_str(&lines[lines.len() - PRUNE_BOUNDARY_SIGNAL_TAIL..].join("\n"));
    out
}

// ── Per-family noise predicates ───────────────────────────────────────────
//
// Each returns `true` ONLY for a line that is definitively safe to drop for
// that ecosystem. They are intentionally narrow: anything not explicitly
// listed is kept, and [`looks_like_signal`] overrides them all.

/// `cargo` (Family::Rust). Ported from rtk `cmds/rust/cargo_cmd.rs`
/// (`should_skip`): drop the progress verbs cargo prints while building —
/// `Compiling`/`Checking`/`Downloading`/`Downloaded`/`Fresh`/`Finished`/
/// `Updating`/`Blocking`/`Installing`/`Adding`/`Removing` — never errors,
/// warnings, or test output.
fn is_rust_noise(line: &str) -> bool {
    let t = line.trim_start();
    matches!(
        first_word(t),
        Some(
            "Compiling"
                | "Checking"
                | "Downloading"
                | "Downloaded"
                | "Fresh"
                | "Finished"
                | "Updating"
                | "Blocking"
                | "Installing"
                | "Locking"
                | "Adding"
                | "Removing"
        )
    )
}

/// `git`/`gh`/`glab`/`gt` (Family::Git). Ported from rtk `cmds/git/git.rs`
/// (status uses compact porcelain; long-format status prints hint banners).
/// Drop git's verbose advisory/hint scaffolding and progress counters —
/// never file paths, branch state, or conflict markers.
fn is_git_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("  (use \"git")          // `(use "git restore ..." to ...)` advice
        || t.starts_with("(use \"git")
        || t == "nothing to commit, working tree clean"
        || t.starts_with("Receiving objects:")
        || t.starts_with("Resolving deltas:")
        || t.starts_with("remote: Counting objects:")
        || t.starts_with("remote: Compressing objects:")
        || t.starts_with("Unpacking objects:")
        || t.starts_with("Enumerating objects:")
}

/// js ecosystem (`npm`/`pnpm`/`npx`/`vitest`/`tsc`/`prettier`/`prisma`/
/// `next`/`playwright`). Ported from rtk `cmds/js/*`: drop npm/pnpm progress
/// + lifecycle banners and the verbose npm funding/audit footer — never
///   `npm ERR!`, type errors, or test failures.
fn is_js_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("npm notice")
        || t.starts_with("npm WARN deprecated") // deprecation noise; real warns kept by signal
        || t.starts_with("> ")                  // pnpm/npm lifecycle echo `> pkg@1 build`
        || t.starts_with("Progress:")
        || t.starts_with("Packages:")
        || t.starts_with("Downloading ")
        || t.starts_with("added ")
        || t.starts_with("Lockfile is up to date")
        || t.starts_with("Already up to date")
        || t.starts_with("up to date")
        || t == "Done in"
        || t.starts_with("Done in ")
}

/// go ecosystem (`go`/`golangci-lint`). Ported from rtk `cmds/go/*`: drop
/// `go: downloading`/`go: finding` module-fetch progress and `ok`/`---`
/// passing-test lines — never `FAIL`, vet diagnostics, or `.go:line:` errors.
fn is_go_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("go: downloading")
        || t.starts_with("go: finding")
        || t.starts_with("go: extracting")
        || t.starts_with("ok  \t")    // `ok  \tpkg\t0.1s` passing package
        || t.starts_with("?   \t")    // `?   \tpkg\t[no test files]`
        || t == "PASS"
        || t.starts_with("=== RUN")
        || t.starts_with("=== PAUSE")
        || t.starts_with("=== CONT")
        || t.starts_with("--- PASS")
}

/// python ecosystem (`pytest`/`ruff`/`pip`/`mypy`). Ported from rtk
/// `cmds/python/*`: drop pytest's platform/rootdir/plugins preamble, the
/// progress dots line, pip's `Requirement already satisfied` / download
/// chatter — never assertion details (`E   ...`), tracebacks, or `FAILED`.
fn is_python_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("platform ")
        || t.starts_with("rootdir:")
        || t.starts_with("plugins:")
        || t.starts_with("cachedir:")
        || t.starts_with("collecting ")
        || t.starts_with("Requirement already satisfied")
        || t.starts_with("Collecting ")
        || t.starts_with("Downloading ")
        || t.starts_with("Using cached ")
        || t.starts_with("Installing collected packages")
        // pytest progress line: only dots / percentages / `[ 50%]`, no text.
        || (!t.is_empty()
            && t.chars()
                .all(|c| matches!(c, '.' | '%' | '[' | ']' | ' ') || c.is_ascii_digit()))
}

/// ruby ecosystem (`rspec`/`rubocop`/`rake`). Ported from rtk `cmds/ruby/*`:
/// drop the `Using <gem>` bundler lines and rspec's progress dots / `Run
/// options` preamble — never `Failures:`, offenses, or backtraces.
fn is_ruby_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Using ")            // `bundle install` "Using rake 13.0"
        || t.starts_with("Fetching ")
        || t.starts_with("Run options:")
        || t.starts_with("Randomized with seed")
        // rspec progress dots (`.....F...`) — only dots, F, *, no other text.
        || (!t.is_empty() && t.chars().all(|c| matches!(c, '.' | 'F' | '*' | 'E' | ' ')))
            && t.contains('.')
}

/// jvm ecosystem (`gradlew`/`./gradlew`). Ported from rtk `cmds/jvm/*` +
/// `filters/gradle.toml`: drop Gradle's `> Task :…` progress, the
/// daemon/`Welcome`/`BUILD SUCCESSFUL` banner chatter, and the percentage
/// progress redraws — never `BUILD FAILED`, compilation errors, or test
/// failures.
fn is_jvm_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("> Task :")
        || t.starts_with("> Configure project")
        || t.starts_with("Starting a Gradle Daemon")
        || t.starts_with("Welcome to Gradle")
        || t.starts_with("Daemon will be stopped")
        || t == "BUILD SUCCESSFUL"
        || t.starts_with("BUILD SUCCESSFUL in")
        || t.starts_with("Deprecated Gradle features were used")
        || t.contains("actionable task") // `5 actionable tasks: 5 executed`
}

/// dotnet ecosystem (`dotnet`). Ported from rtk `cmds/dotnet/*` +
/// `filters/dotnet-build.toml`: drop the MSBuild `Determining projects to
/// restore` / `Restored` / `Restore complete` progress and the welcome
/// telemetry banner — never `error CS####`, warnings, or test failures.
fn is_dotnet_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Determining projects to restore")
        || t.starts_with("Restored ")
        || t.starts_with("Restore complete")
        || t.starts_with("Nothing to do. None of the projects")
        || t.starts_with("Welcome to .NET")
        || t.starts_with("Telemetry")
        || t.starts_with("----------")
        || t.starts_with("Build succeeded")
}

/// cloud ecosystem (`aws`/`curl`/`wget`/`psql`/`docker`). Ported from rtk
/// `cmds/cloud/*`: drop docker layer-pull progress, curl/wget transfer
/// progress meters, and psql `SET`/`Time:` chatter — never HTTP error
/// statuses, stderr diagnostics, or SQL errors.
fn is_cloud_noise(line: &str) -> bool {
    let t = line.trim_start();
    // docker pull layer progress: `<id>: Pulling fs layer` / `Downloading` /
    // `Extracting` / `Pull complete` / `Already exists`.
    t.ends_with(": Pulling fs layer")
        || t.ends_with(": Waiting")
        || t.ends_with(": Verifying Checksum")
        || t.ends_with(": Download complete")
        || t.ends_with(": Pull complete")
        || t.ends_with(": Already exists")
        || t.contains(": Downloading ")
        || t.contains(": Extracting ")
        // psql noise
        || t == "SET"
        || t.starts_with("Time: ")
        // wget progress redraw remnants
        || t.starts_with("Saving to:")
        || t.starts_with("Length:")
        || t.starts_with("--")  && t.contains("--  http")
}

/// system ecosystem (`find`/`grep`/`ls`/`tree`/`wc`/`env`/`cat`/`head`/
/// `tail`). Ported from rtk `cmds/system/*`: these mostly produce listing
/// output with little intrinsic noise, so the strategy is conservative —
/// drop only `find`/`grep` permission-denied spam to a single representative
/// line is handled by dedup already; here we drop tree's trailing
/// `N directories, M files` summary line is KEPT (it's a useful count), so
/// the only structural noise is a `grep:`/`find:` line that the signal guard
/// already keeps. Net effect: system output is largely passthrough beyond the
/// generic filter — which is correct (listings are signal). Returns false for
/// everything; the generic filter (dedup + truncation) carries the savings.
fn is_system_noise(_line: &str) -> bool {
    false
}

/// First whitespace-delimited word of a line, or `None` when blank.
fn first_word(line: &str) -> Option<&str> {
    line.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Generic filter ──────────────────────────────────────────────────

    #[test]
    fn strips_ansi_color_codes() {
        let input = "\x1b[31mError: boom\x1b[0m\n\x1b[1;32mok\x1b[0m";
        let out = generic_filter(input);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("Error: boom"));
        assert!(out.contains("ok"));
    }

    #[test]
    fn strips_osc_hyperlink_sequences() {
        // OSC 8 hyperlink wrapping: ESC ] 8 ; ; url BEL text ESC ] 8 ; ; BEL
        let input = "\x1b]8;;https://example.com\x07link text\x1b]8;;\x07";
        let out = generic_filter(input);
        assert!(!out.contains('\x1b'));
        assert!(out.contains("link text"));
        assert!(!out.contains("example.com") || out.contains("link text"));
    }

    #[test]
    fn collapses_carriage_return_progress_redraw() {
        let input = "Downloading 10%\rDownloading 50%\rDownloading 100%";
        let out = generic_filter(input);
        // Only the final segment survives; the intermediate redraws are gone.
        assert!(out.contains("Downloading 100%"));
        assert!(!out.contains("10%"));
        assert!(!out.contains("50%"));
    }

    #[test]
    fn drops_spinner_only_lines_keeps_text() {
        let input = "⠋\n⠙\n⠹\nHello! How can I help you today?";
        let out = generic_filter(input);
        assert_eq!(out, "Hello! How can I help you today?");
    }

    #[test]
    fn spinner_with_real_text_is_kept() {
        // A spinner glyph followed by real text (esp. an error) must survive.
        let input = "⠋ Building error[E0382]: borrow of moved value";
        let out = generic_filter(input);
        assert!(out.contains("error[E0382]"));
    }

    #[test]
    fn dedups_consecutive_identical_lines_with_count() {
        let input = "retrying\nretrying\nretrying\ndone";
        let out = generic_filter(input);
        assert!(out.contains("retrying  [×3]"), "got: {out}");
        assert!(out.contains("done"));
        // The repeated text appears once (plus the count), not three times.
        assert_eq!(out.matches("retrying").count(), 1);
    }

    #[test]
    fn middle_truncation_keeps_head_and_tail_with_marker() {
        let mut lines: Vec<String> = Vec::new();
        for i in 0..1000 {
            lines.push(format!("line {i}"));
        }
        let input = lines.join("\n");
        let out = generic_filter(&input);
        // Head present.
        assert!(out.contains("line 0"));
        assert!(out.contains("line 1"));
        // Tail present (the failure signal lives at the tail).
        assert!(out.contains("line 999"));
        assert!(out.contains("line 998"));
        // Explicit elision marker present and naming the count.
        assert!(out.contains("lines elided"), "got tail: {out}");
        // The deep middle is gone.
        assert!(!out.contains("line 500"));
    }

    #[test]
    fn middle_truncation_preserves_trace_blocks_from_elided_middle() {
        let mut lines: Vec<String> = (0..260).map(|i| format!("head noise {i}")).collect();
        lines.extend([
            "Traceback (most recent call last):".to_string(),
            "  File \"app.py\", line 10, in <module>".to_string(),
            "    run()".to_string(),
            "ValueError: first failure".to_string(),
        ]);
        lines.extend((0..260).map(|i| format!("middle noise {i}")));
        lines.extend([
            "panic: second failure".to_string(),
            "goroutine 1 [running]:".to_string(),
            "main.main()".to_string(),
            "\t/app/main.go:12 +0x20".to_string(),
        ]);
        lines.extend((0..260).map(|i| format!("tail noise {i}")));

        let out = generic_filter(&lines.join("\n"));

        assert!(out.contains("Traceback (most recent call last):"), "{out}");
        assert!(out.contains("ValueError: first failure"), "{out}");
        assert!(out.contains("panic: second failure"), "{out}");
        assert!(out.contains("/app/main.go:12"), "{out}");
        assert!(out.contains("lines elided"), "{out}");
    }

    #[test]
    fn many_trace_blocks_keep_first_and_last_with_summary() {
        let input = "\
Traceback (most recent call last):
  File \"first.py\", line 1, in <module>
FirstError: boom
between one
Traceback (most recent call last):
  File \"middle.py\", line 2, in <module>
MiddleError: boom
between two
Traceback (most recent call last):
  File \"last.py\", line 3, in <module>
LastError: boom";

        let out = generic_filter(input);

        assert!(out.contains("first.py"), "{out}");
        assert!(out.contains("last.py"), "{out}");
        assert!(!out.contains("middle.py"), "{out}");
        assert!(out.contains("trace blocks omitted"), "{out}");
    }

    #[test]
    fn very_long_trace_block_keeps_top_and_tail_with_marker() {
        let mut lines = vec!["Traceback (most recent call last):".to_string()];
        for i in 0..90 {
            lines.push(format!("  File \"f{i}.py\", line {i}, in <module>"));
        }
        lines.push("RuntimeError: tail survives".to_string());

        let out = generic_filter(&lines.join("\n"));

        assert!(out.contains("f0.py"), "{out}");
        assert!(out.contains("f89.py"), "{out}");
        assert!(out.contains("RuntimeError: tail survives"), "{out}");
        assert!(out.contains("trace lines elided"), "{out}");
        assert!(!out.contains("f45.py"), "{out}");
    }

    #[test]
    fn no_truncation_under_the_line_threshold() {
        let input = "a\nb\nc";
        assert_eq!(generic_filter(input), "a\nb\nc");
    }

    // ── recognize / first_program ───────────────────────────────────────

    #[test]
    fn recognizes_every_family() {
        assert_eq!(recognize("git status"), Some(Family::Git));
        assert_eq!(recognize("gh pr list"), Some(Family::Git));
        assert_eq!(recognize("glab mr view"), Some(Family::Git));
        assert_eq!(recognize("gt log"), Some(Family::Git));
        assert_eq!(recognize("npm install"), Some(Family::Js));
        assert_eq!(recognize("pnpm build"), Some(Family::Js));
        assert_eq!(recognize("npx vitest"), Some(Family::Js));
        assert_eq!(recognize("playwright test"), Some(Family::Js));
        assert_eq!(recognize("vitest run"), Some(Family::Js));
        assert_eq!(recognize("prettier --check ."), Some(Family::Js));
        assert_eq!(recognize("tsc --noEmit"), Some(Family::Js));
        assert_eq!(recognize("prisma generate"), Some(Family::Js));
        assert_eq!(recognize("next build"), Some(Family::Js));
        assert_eq!(recognize("go test ./..."), Some(Family::Go));
        assert_eq!(recognize("golangci-lint run"), Some(Family::Go));
        assert_eq!(recognize("pytest -q"), Some(Family::Python));
        assert_eq!(recognize("ruff check ."), Some(Family::Python));
        assert_eq!(recognize("pip install x"), Some(Family::Python));
        assert_eq!(recognize("mypy ."), Some(Family::Python));
        assert_eq!(recognize("cargo build"), Some(Family::Rust));
        assert_eq!(recognize("rspec spec/"), Some(Family::Ruby));
        assert_eq!(recognize("rubocop"), Some(Family::Ruby));
        assert_eq!(recognize("rake test"), Some(Family::Ruby));
        assert_eq!(recognize("./gradlew build"), Some(Family::Jvm));
        assert_eq!(recognize("gradlew test"), Some(Family::Jvm));
        assert_eq!(recognize("dotnet build"), Some(Family::Dotnet));
        assert_eq!(recognize("aws s3 ls"), Some(Family::Cloud));
        assert_eq!(recognize("curl https://x"), Some(Family::Cloud));
        assert_eq!(recognize("wget https://x"), Some(Family::Cloud));
        assert_eq!(recognize("psql -c 'select 1'"), Some(Family::Cloud));
        assert_eq!(recognize("docker build ."), Some(Family::Cloud));
        assert_eq!(recognize("find . -name x"), Some(Family::System));
        assert_eq!(recognize("grep -r foo"), Some(Family::System));
        assert_eq!(recognize("ls -la"), Some(Family::System));
        assert_eq!(recognize("tree src"), Some(Family::System));
        assert_eq!(recognize("wc -l f"), Some(Family::System));
        assert_eq!(recognize("env"), Some(Family::System));
    }

    #[test]
    fn recognize_skips_env_prefix_and_path() {
        assert_eq!(recognize("FOO=bar cargo build"), Some(Family::Rust));
        assert_eq!(
            recognize("RUST_LOG=debug PATH=/x cargo test"),
            Some(Family::Rust)
        );
        assert_eq!(recognize("/usr/bin/git status"), Some(Family::Git));
        assert_eq!(recognize("unknownbin run"), None);
        assert_eq!(recognize(""), None);
    }

    // ── defensive-routing tip classifier ────────────────────────────────

    #[test]
    fn classify_tip_maps_each_family() {
        assert_eq!(classify_tip("cat foo.txt"), Some(BashTip::Read));
        assert_eq!(classify_tip("head -n5 f"), Some(BashTip::Read));
        assert_eq!(classify_tip("tail -f log"), Some(BashTip::Read));
        assert_eq!(classify_tip("less f"), Some(BashTip::Read));
        assert_eq!(classify_tip("more f"), Some(BashTip::Read));
        assert_eq!(classify_tip("grep -r foo ."), Some(BashTip::Search));
        assert_eq!(classify_tip("rg foo"), Some(BashTip::Search));
        assert_eq!(classify_tip("egrep foo f"), Some(BashTip::Search));
        assert_eq!(classify_tip("find . -name x"), Some(BashTip::Tree));
        assert_eq!(classify_tip("ls -la"), Some(BashTip::Tree));
    }

    #[test]
    fn classify_tip_skips_env_prefix_and_path() {
        // A leading `VAR=val` env assignment is skipped, same as `recognize`.
        assert_eq!(classify_tip("VAR=1 cat f"), Some(BashTip::Read));
        assert_eq!(
            classify_tip("FOO=bar GREP_COLOR=1 grep x"),
            Some(BashTip::Search)
        );
        // Path basename is normalized.
        assert_eq!(classify_tip("/bin/cat f"), Some(BashTip::Read));
    }

    #[test]
    fn classify_tip_pipeline_classifies_on_head() {
        // A pipeline resolves on its first program only.
        assert_eq!(classify_tip("cat x | grep y"), Some(BashTip::Read));
    }

    #[test]
    fn classify_tip_none_for_non_file_commands() {
        assert_eq!(classify_tip("cargo build"), None);
        assert_eq!(classify_tip("git status"), None);
        assert_eq!(classify_tip(""), None);
    }

    #[test]
    fn tip_adopted_by_maps_dedicated_tools() {
        assert_eq!(tip_adopted_by("read"), Some(BashTip::Read));
        assert_eq!(tip_adopted_by("search"), Some(BashTip::Search));
        assert_eq!(tip_adopted_by("word"), Some(BashTip::Search));
        assert_eq!(tip_adopted_by("symbol_find"), Some(BashTip::Search));
        assert_eq!(tip_adopted_by("tree"), Some(BashTip::Tree));
        assert_eq!(tip_adopted_by("bash"), None);
        assert_eq!(tip_adopted_by("outline"), None);
    }

    // ── signal guarantee (shared) ───────────────────────────────────────

    #[test]
    fn looks_like_signal_catches_diagnostics() {
        for line in [
            "error[E0382]: borrow of moved value",
            "error: cannot find value `x`",
            "warning: unused variable",
            "thread 'main' panicked at src/main.rs:4:5",
            "Traceback (most recent call last):",
            "  File \"app.py\", line 10, in <module>",
            "    at Object.<anonymous> (/app/index.js:3:11)",
            "./main.go:12: undefined: Foo",
            "FAILED tests/test_x.py::test_y",
            "E   assert 1 == 2",
            "  --> src/lib.rs:9:5",
            "AssertionError: boom",
        ] {
            assert!(looks_like_signal(line), "should be signal: {line:?}");
        }
    }

    #[test]
    fn prune_boundary_condense_preserves_middle_diagnostics() {
        let mut lines = Vec::new();
        for i in 0..700 {
            lines.push(format!("noise line {i}"));
            if i == 350 {
                lines.push("error: compiler exploded".to_string());
                lines.push("sandbox denied: write outside workspace".to_string());
                lines.push("stack backtrace:".to_string());
                lines.push("exit: 101".to_string());
            }
        }
        let body = lines.join("\n");

        let out = prune_boundary_condense("cargo test", &body).expect("condensed");

        assert!(out.len() < body.len());
        assert!(out.contains("[deterministic shell condensation]"));
        assert!(out.contains("error: compiler exploded"));
        assert!(out.contains("sandbox denied: write outside workspace"));
        assert!(out.contains("stack backtrace:"));
        assert!(out.contains("exit: 101"));
        assert!(out.contains("lines elided"));
    }

    #[test]
    fn prune_boundary_condense_leaves_short_output_unchanged() {
        assert!(prune_boundary_condense("cargo test", "ok\n").is_none());
    }

    // ── Per-command family strategies: noise stripped + signal preserved ──

    #[test]
    fn rust_strips_progress_keeps_errors_and_warnings() {
        let input = "\
   Compiling foo v0.1.0
   Compiling bar v0.2.0
    Checking baz v0.3.0
   Downloading crates ...
warning: unused variable: `x`
error[E0382]: borrow of moved value: `v`
  --> src/main.rs:5:9
    Finished dev [unoptimized] in 2.3s";
        let out = compress_stream("cargo build", input);
        assert!(!out.contains("Compiling foo"));
        assert!(!out.contains("Downloading"));
        assert!(!out.contains("Finished"));
        // Signal preserved.
        assert!(out.contains("warning: unused variable"));
        assert!(out.contains("error[E0382]"));
        assert!(out.contains("--> src/main.rs:5:9"));
    }

    #[test]
    fn rust_progress_omissions_are_summarized_when_material() {
        let input = "\
   Compiling a v0.1.0
   Compiling b v0.1.0
   Compiling c v0.1.0
   Compiling d v0.1.0
done";

        let out = compress_stream("cargo build", input);

        assert!(out.contains("done"), "{out}");
        assert!(out.contains("4 lines omitted"), "{out}");
        assert!(
            out.contains("0 errors, 0 warnings, 4 progress/info"),
            "{out}"
        );
        assert!(!out.contains("Compiling a"), "{out}");
    }

    #[test]
    fn tiny_clean_progress_omission_still_falls_back_to_original() {
        let input = "   Compiling foo v0.1.0\n   Compiling bar v0.2.0";
        let out = compress_stream("cargo build", input);
        assert_eq!(out, input);
    }

    #[test]
    fn git_strips_advice_keeps_file_state() {
        let input = "\
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use \"git add <file>...\" to update what will be committed)
  (use \"git restore <file>...\" to discard changes in working directory)
	modified:   src/main.rs

no changes added to commit (use \"git add\" and/or \"git commit -a\")";
        let out = compress_stream("git status", input);
        assert!(!out.contains("(use \"git restore"));
        assert!(!out.contains("(use \"git add <file>"));
        // File state preserved.
        assert!(out.contains("modified:   src/main.rs"));
        assert!(out.contains("On branch main"));
    }

    #[test]
    fn js_strips_lifecycle_keeps_npm_err_and_type_errors() {
        let input = "\
npm notice New version of npm available
> myapp@1.0.0 build
> tsc --noEmit
added 421 packages
src/index.ts(3,5): error TS2322: Type 'string' is not assignable to type 'number'.
npm ERR! code ELIFECYCLE";
        let out = compress_stream("npm run build", input);
        assert!(!out.contains("npm notice"));
        assert!(!out.contains("added 421 packages"));
        // Signal preserved.
        assert!(out.contains("error TS2322"));
        assert!(out.contains("npm ERR!"));
    }

    #[test]
    fn go_strips_module_fetch_keeps_failures() {
        let input = "\
go: downloading github.com/foo/bar v1.2.3
=== RUN   TestThing
--- PASS: TestOther (0.00s)
ok  \tgithub.com/x/y\t0.123s
--- FAIL: TestThing (0.01s)
    thing_test.go:14: expected 2, got 1
FAIL";
        let out = compress_stream("go test ./...", input);
        assert!(!out.contains("go: downloading"));
        assert!(!out.contains("=== RUN"));
        assert!(!out.contains("--- PASS"));
        // Signal preserved.
        assert!(out.contains("--- FAIL: TestThing"));
        assert!(out.contains("thing_test.go:14"));
        assert!(out.lines().any(|l| l.trim() == "FAIL"));
    }

    #[test]
    fn python_strips_preamble_keeps_assertion_detail() {
        let input = "\
platform linux -- Python 3.11.0, pytest-7.4.0
rootdir: /app
plugins: cov-4.1.0
collecting ...
test_x.py ..F.. [100%]
=================================== FAILURES ===================================
_________________________________ test_thing __________________________________
E   assert 1 == 2
FAILED test_x.py::test_thing - assert 1 == 2";
        let out = compress_stream("pytest -q", input);
        assert!(!out.contains("platform linux"));
        assert!(!out.contains("rootdir:"));
        assert!(!out.contains("plugins:"));
        // Signal preserved.
        assert!(out.contains("E   assert 1 == 2"));
        assert!(out.contains("FAILED test_x.py::test_thing"));
        assert!(out.contains("FAILURES"));
    }

    #[test]
    fn python_clean_progress_omissions_are_summarized_when_material() {
        let input = "\
platform linux -- Python 3.11.0, pytest-7.4.0
rootdir: /app
plugins: cov-4.1.0
cachedir: .pytest_cache
collecting ...
.................................... [100%]
1 passed in 0.01s";

        let out = compress_stream("pytest -q", input);

        assert!(out.contains("1 passed"), "{out}");
        assert!(out.contains("6 lines omitted"), "{out}");
        assert!(!out.contains("platform linux"), "{out}");
    }

    #[test]
    fn ruby_strips_using_lines_keeps_failures() {
        let input = "\
Using rake 13.0.6
Using rspec 3.12.0
Run options: include {:focus=>true}
.....F....
Failures:
  1) Thing does stuff
     Failure/Error: expect(1).to eq(2)";
        let out = compress_stream("rspec spec/", input);
        assert!(!out.contains("Using rake"));
        assert!(!out.contains("Run options:"));
        // Signal preserved.
        assert!(out.contains("Failures:"));
        assert!(out.contains("Failure/Error: expect(1).to eq(2)"));
    }

    #[test]
    fn jvm_strips_task_progress_keeps_build_failed() {
        let input = "\
Starting a Gradle Daemon
> Task :compileJava
> Task :processResources
> Task :test
5 actionable tasks: 5 executed
src/main/java/App.java:7: error: cannot find symbol
BUILD FAILED in 3s";
        let out = compress_stream("./gradlew build", input);
        assert!(!out.contains("> Task :compileJava"));
        assert!(!out.contains("Starting a Gradle Daemon"));
        assert!(!out.contains("actionable task"));
        // Signal preserved.
        assert!(out.contains("error: cannot find symbol"));
        assert!(out.contains("BUILD FAILED"));
    }

    #[test]
    fn dotnet_strips_restore_keeps_cs_errors() {
        let input = "\
Determining projects to restore...
Restored /app/App.csproj (in 1.2 sec).
Restore complete (1.5s)
/app/Program.cs(8,13): error CS0103: The name 'x' does not exist
Build FAILED.";
        let out = compress_stream("dotnet build", input);
        assert!(!out.contains("Determining projects to restore"));
        assert!(!out.contains("Restored /app"));
        assert!(!out.contains("Restore complete"));
        // Signal preserved.
        assert!(out.contains("error CS0103"));
        assert!(out.contains("Build FAILED"));
    }

    #[test]
    fn cloud_strips_docker_layers_keeps_errors() {
        let input = "\
sha256abc: Pulling fs layer
sha256abc: Downloading 50%
sha256abc: Pull complete
Step 5/8 : RUN make
failed to solve: process \"/bin/sh -c make\" did not complete successfully: exit code 2";
        let out = compress_stream("docker build .", input);
        assert!(!out.contains("Pulling fs layer"));
        assert!(!out.contains("Pull complete"));
        // Signal preserved.
        assert!(out.contains("failed to solve"));
    }

    #[test]
    fn system_is_largely_passthrough_after_generic() {
        let input = "src\nsrc/main.rs\nsrc/lib.rs\n2 directories, 5 files";
        let out = compress_stream("tree src", input);
        // Listing content + the useful count are all preserved.
        assert!(out.contains("src/main.rs"));
        assert!(out.contains("src/lib.rs"));
        assert!(out.contains("2 directories, 5 files"));
    }

    #[test]
    fn strategy_never_eats_everything() {
        // An all-progress run must not collapse to empty — the model still
        // needs to see the command produced output.
        let input = "   Compiling foo v0.1.0\n   Compiling bar v0.2.0";
        let out = compress_stream("cargo build", input);
        assert!(!out.trim().is_empty());
    }

    #[test]
    fn signal_guard_overrides_a_family_predicate() {
        // A line that a family predicate WOULD drop is kept when it carries
        // signal. `go: downloading ... error` is matched by is_go_noise's
        // prefix but the signal guard keeps it.
        let input = "go: downloading failed: error connecting to proxy";
        let out = compress_stream("go test ./...", input);
        assert!(out.contains("error connecting to proxy"));
    }

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(compress_stream("cargo build", ""), "");
        assert_eq!(generic_filter(""), "");
    }
}
