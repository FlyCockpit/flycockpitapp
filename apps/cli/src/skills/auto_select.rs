//! Cheap-model skill auto-selection (GOALS §5).
//!
//! On each user turn the driver consults the configured `utility_model`
//! with the catalog of skill `(name, description)` pairs plus the last few
//! conversation turns (the same window `predict` uses); the model returns
//! the clearly-relevant skills in relevance order (or `NONE`). The
//! surviving selections — capped in count and token-budgeted — have their
//! bodies loaded (after `!`-processing — Claude/Codex mode per
//! [`crate::skills::render_body`]) and injected into context before the
//! main agent's turn, in relevance order.
//!
//! Token economy (GOALS §10): the cheap model sees only the catalog,
//! never a body. Bodies are the sole large payload and only materialize on
//! selection; combined injected bodies are bounded by a hard count cap
//! ([`MAX_SELECTED_SKILLS`]) and a total token budget
//! ([`SELECTED_BODY_TOKEN_BUDGET`], enforced via the cl100k_base counter
//! in [`crate::tokens`]).
//!
//! Graceful degradation mirrors [`crate::auto_title`]: when
//! `utility_model` is unset the pass is skipped (logged once via the
//! caller), never erroring and never falling back to the main model.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::engine::predict::{PredictionTurn, last_turns};

/// Timeout for the utility-model selection call. Selection is
/// best-effort; if the provider stalls we'd rather skip injection than
/// hold up the user's turn.
pub const SELECT_CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Hard cap on the number of skills activated in one turn. Conservative
/// for token economy (GOALS §10): even within the token budget we never
/// inject more than this many bodies. Selections beyond the cap are
/// dropped (logged) by relevance order.
pub const MAX_SELECTED_SKILLS: usize = 3;

/// Total cl100k_base token budget for the combined injected skill bodies
/// in one turn. When the cap-trimmed selections still exceed this, the
/// lowest-priority (last-ranked) bodies are dropped whole until the rest
/// fit — bodies are never truncated mid-stream.
pub const SELECTED_BODY_TOKEN_BUDGET: usize = 8_000;

/// Hard cap on the transcript reason sub-line's length (chars). The reason
/// is display-only (off-wire, GOALS §14), but it still shares the
/// transcript with the user's message, so we keep it terse (token economy,
/// GOALS §10): collapsed to a single line and truncated at a word boundary
/// with `…` when longer.
pub const SELECT_REASON_MAX_CHARS: usize = 120;

/// Number of matched content words the keyword-overlap fallback reason
/// lists (`matches: a, b, c`) when the model supplied no reason of its own.
const FALLBACK_KEYWORD_COUNT: usize = 3;

/// One injected skill: its name (for the header), rendered
/// (`!`-processed, scrubbed) body, and an optional short reason it was
/// selected — the utility model's clause when given, else a keyword-overlap
/// fallback synthesized from the relevance backstop. Display-only and
/// off-wire (GOALS §14): the reason never enters the model's context.
pub struct InjectedSkill {
    pub name: String,
    pub body: String,
    pub reason: Option<String>,
}

/// One selector-side drop reason for debug/export. It deliberately carries
/// no skill body or prompt text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RejectedCandidate {
    pub skill: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SelectionDiagnostics {
    pub rejections: Vec<RejectedCandidate>,
}

impl SelectionDiagnostics {
    fn reject_skill(&mut self, skill: &crate::skills::Skill, reason: &'static str) {
        self.rejections.push(RejectedCandidate {
            skill: Some(skill.frontmatter.name.clone()),
            reason: reason.to_string(),
        });
    }

    fn reject_turn(&mut self, reason: &'static str) {
        self.rejections.push(RejectedCandidate {
            skill: None,
            reason: reason.to_string(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.rejections.is_empty()
    }
}

/// Result of an auto-selection pass.
pub enum Selection {
    /// One or more skills were chosen; carries the rendered bodies in
    /// relevance order (highest-relevance first), already capped and
    /// token-budgeted. Never empty.
    Skills(Vec<InjectedSkill>),
    /// No skill was selected this turn (model declined, no skills, no
    /// utility model, or everything dropped by the budget). The driver
    /// injects nothing.
    None,
}

/// Run one auto-selection pass for the recent conversation `turns` (the
/// `predict`-shaped last-3-turns window, oldest-first) against the
/// configured skills + utility model. Best-effort: any error (unset
/// utility model, network blip, parse failure) resolves to
/// [`Selection::None`] via the caller's `?`-free wrapper. `cwd` scopes
/// both skill discovery and the layered config.
///
/// `already_injected` is the driver's per-session set of skill names already
/// auto-injected this session (once-per-session suppression). Those skills
/// are removed before the catalog is built so the utility model never sees
/// them as options — it can neither re-vote them nor have the backstop
/// re-pass them. The set is the auto-injection path's own state, separate
/// from the relevance backstop.
#[cfg(test)]
async fn select(
    cwd: &Path,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    turns: &[PredictionTurn],
    already_injected: &std::collections::HashSet<String>,
) -> Selection {
    select_with_diagnostics(
        cwd,
        extended,
        providers,
        redact,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        turns,
        already_injected,
    )
    .await
    .0
}

pub async fn select_with_diagnostics(
    cwd: &Path,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    turns: &[PredictionTurn],
    already_injected: &std::collections::HashSet<String>,
) -> (Selection, SelectionDiagnostics) {
    match select_inner(
        cwd,
        extended,
        providers,
        redact,
        trusted_only,
        turns,
        already_injected,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(error = %e, "skills auto-select: pass ended without a skill");
            (Selection::None, SelectionDiagnostics::default())
        }
    }
}

async fn select_inner(
    cwd: &Path,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    turns: &[PredictionTurn],
    already_injected: &std::collections::HashSet<String>,
) -> Result<(Selection, SelectionDiagnostics)> {
    let mut diagnostics = SelectionDiagnostics::default();

    // Unset utility model → skip gracefully. The caller logs the
    // skip-once notice; here we just bail cleanly.
    let Some(model_ref) = extended.skill_injection_model_ref() else {
        return Ok((Selection::None, diagnostics));
    };

    // Claude parity + token economy: the utility-model catalog includes a
    // skill iff `disable-model-invocation` is not true. User-only skills
    // never enter this prompt and are never auto-injected. Already
    // auto-injected skills (this session) are also dropped here — before the
    // catalog — so the model can't re-vote them and the backstop can't
    // re-pass them (once-per-session suppression). Empty after either filter
    // → skip, never an error.
    let skills: Vec<crate::skills::Skill> = crate::skills::discover(cwd, &extended.skills)?
        .into_iter()
        .filter(|s| !s.frontmatter.disable_model_invocation)
        .filter(|s| !already_injected.contains(&s.frontmatter.name))
        .collect();
    if skills.is_empty() {
        return Ok((Selection::None, diagnostics));
    }

    // Same window `predict` feeds the utility model: the last 3 turns,
    // reduced to user input + agent final response (no tool calls).
    let window = selector_window(turns, &mut diagnostics);
    if window.is_empty() {
        return Ok((Selection::None, diagnostics));
    }

    let model = crate::engine::model::Model::from_ref_trusted_only(
        providers,
        model_ref,
        redact.clone(),
        trusted_only,
    )?;
    let catalog = crate::skills::catalog_lines(&skills);
    let prompt = build_select_prompt(&catalog, &window);
    let response =
        tokio::time::timeout(SELECT_CALL_TIMEOUT, model.text_completion(&prompt)).await??;

    // Robustly parse the relevance-ordered name list (each name carries an
    // optional model reason), then apply the deterministic relevance
    // backstop (priority #1: never trust the weak utility model's vote
    // alone), then the count cap and body token budget. The backstop also
    // returns the matched content words per survivor — the keyword-overlap
    // fallback reason when the model gave none.
    let chosen = parse_choices(&response, &skills);
    if chosen.is_empty() {
        return Ok((Selection::None, diagnostics));
    }
    let chosen = relevance_filter_with_diagnostics(&chosen, &window, &mut diagnostics);
    if chosen.is_empty() {
        return Ok((Selection::None, diagnostics));
    }

    let injected = render_capped_and_budgeted(&chosen, cwd, extended, &redact);
    if injected.is_empty() {
        Ok((Selection::None, diagnostics))
    } else {
        Ok((Selection::Skills(injected), diagnostics))
    }
}

/// Apply the count cap and token budget to the relevance-ordered
/// selections, then render the survivors. Order is preserved
/// (highest-relevance first). The count cap is applied first (drops past
/// `MAX_SELECTED_SKILLS` are logged); bodies are then rendered and added
/// in order while the running cl100k_base token total stays within
/// [`SELECTED_BODY_TOKEN_BUDGET`] — a body that would overflow is dropped
/// whole (logged), never truncated, and lower-priority bodies are likewise
/// dropped (they can only push the total higher).
fn render_capped_and_budgeted(
    chosen: &[Survivor<'_>],
    cwd: &Path,
    extended: &ExtendedConfig,
    redact: &crate::redact::RedactionTable,
) -> Vec<InjectedSkill> {
    // Hard count cap (token economy). Log what the cap dropped so it never
    // reads as full coverage.
    let (kept, capped_off) = if chosen.len() > MAX_SELECTED_SKILLS {
        chosen.split_at(MAX_SELECTED_SKILLS)
    } else {
        (chosen, &[][..])
    };
    if !capped_off.is_empty() {
        let dropped: Vec<&str> = capped_off
            .iter()
            .map(|s| s.skill.frontmatter.name.as_str())
            .collect();
        tracing::info!(
            cap = MAX_SELECTED_SKILLS,
            dropped = ?dropped,
            "skills auto-select: more relevant skills than the cap; dropped lowest-priority"
        );
    }

    let mut injected: Vec<InjectedSkill> = Vec::new();
    let mut used_tokens = 0usize;
    for survivor in kept {
        let skill = survivor.skill;
        let body = match crate::skills::load_body(skill) {
            Ok(b) => b,
            Err(e) => {
                // A skill whose body fails to load is skipped (logged); the
                // rest of the selection still injects.
                tracing::warn!(
                    error = %e,
                    skill = %skill.frontmatter.name,
                    "skills auto-select: body load failed; skipping this skill"
                );
                continue;
            }
        };
        let rendered =
            crate::skills::render_body(&body, cwd, extended.skills.auto_bang_commands, redact);
        let cost = crate::tokens::count(&rendered);
        if used_tokens + cost > SELECTED_BODY_TOKEN_BUDGET {
            // Over budget → drop this whole body (never truncate). Keep
            // scanning lower-priority bodies in case a smaller one still
            // fits the remaining budget.
            tracing::info!(
                budget = SELECTED_BODY_TOKEN_BUDGET,
                used = used_tokens,
                cost,
                skill = %skill.frontmatter.name,
                "skills auto-select: skill body exceeds remaining token budget; dropped"
            );
            continue;
        }
        used_tokens += cost;
        // Reason (display-only, off-wire): the model's clause when it gave
        // one, else a terse keyword-overlap fallback from the backstop's
        // matched words. Genuinely no reason → None → plain row, unchanged.
        let reason = survivor
            .reason
            .clone()
            .or_else(|| fallback_reason(&survivor.matched));
        injected.push(InjectedSkill {
            name: skill.frontmatter.name.clone(),
            body: rendered,
            reason,
        });
    }
    injected
}

/// Synthesize the keyword-overlap fallback reason from the backstop's
/// matched content words, e.g. `matches: export, session, tool-call`.
/// Caps to the first [`FALLBACK_KEYWORD_COUNT`] words for terseness; an
/// empty match set yields `None` (no sub-line). The matched set is the
/// `request ∩ skill_keywords` intersection — non-empty for any kept skill,
/// so this is essentially always available when the model gave no reason.
fn fallback_reason(matched: &[String]) -> Option<String> {
    if matched.is_empty() {
        return None;
    }
    let words: Vec<&str> = matched
        .iter()
        .take(FALLBACK_KEYWORD_COUNT)
        .map(String::as_str)
        .collect();
    Some(format!("matches: {}", words.join(", ")))
}

/// Trim, single-line, and length-cap a raw model reason. Collapses internal
/// whitespace (newlines included — a multi-line model reason degrades to one
/// line, never breaks the row) to single spaces, then truncates at a word
/// boundary with `…` when longer than [`SELECT_REASON_MAX_CHARS`]. Empty
/// after trimming → `None` (falls back to the keyword reason). Defensive
/// against a weak model (priority #1): any malformed reason yields at worst
/// `None`, never an error.
fn clean_reason(raw: &str) -> Option<String> {
    let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    if collapsed.chars().count() <= SELECT_REASON_MAX_CHARS {
        return Some(collapsed);
    }
    // Truncate at a word boundary within the cap, then append the ellipsis.
    let mut truncated = String::new();
    for word in collapsed.split(' ') {
        // +1 for the joining space (none before the first word), +1 for `…`.
        let added = if truncated.is_empty() {
            word.chars().count()
        } else {
            truncated.chars().count() + 1 + word.chars().count()
        };
        if added + 1 > SELECT_REASON_MAX_CHARS {
            break;
        }
        if !truncated.is_empty() {
            truncated.push(' ');
        }
        truncated.push_str(word);
    }
    if truncated.is_empty() {
        // A single over-long word: hard-cut at the char cap (still terse).
        truncated = collapsed
            .chars()
            .take(SELECT_REASON_MAX_CHARS.saturating_sub(1))
            .collect();
    }
    truncated.push('…');
    Some(truncated)
}

/// One-shot prompt asking the utility model to pick the relevant skills.
/// Kept terse: catalog + the recent transcript + a one-line instruction.
/// The model sees only `(name, description)` pairs — never a body. The
/// transcript is the same last-3-turn window `predict` builds.
fn build_select_prompt(catalog: &str, turns: &[PredictionTurn]) -> String {
    let mut transcript = String::new();
    for turn in turns {
        transcript.push_str("USER: ");
        transcript.push_str(turn.user.trim());
        transcript.push('\n');
        if !turn.agent.trim().is_empty() {
            transcript.push_str("AGENT: ");
            transcript.push_str(turn.agent.trim());
            transcript.push('\n');
        }
    }
    format!(
        "Route a coding conversation to helper skills. Below is a catalog of \
         skills as `- name: description` lines, then the recent \
         conversation. Default to NONE. Name a skill ONLY when the request \
         clearly and directly matches that skill's stated purpose — not when \
         it is merely related or might help. When in doubt, answer NONE. \
         Most requests need no skill. Reply with the single word NONE, or \
         one clearly-matching skill per line, most-relevant first. On each \
         line: the skill name, then ` — `, then one short clause on why it \
         fits the request. Nothing else.\n\n\
         <skills>\n{catalog}</skills>\n\n\
         <conversation>\n{transcript}</conversation>\n"
    )
}

/// Build the selector/backstop window from stored turns without letting
/// previous auto-injected skill bodies look like fresh user intent.
fn selector_window(
    turns: &[PredictionTurn],
    diagnostics: &mut SelectionDiagnostics,
) -> Vec<PredictionTurn> {
    let sanitized: Vec<PredictionTurn> = turns
        .iter()
        .map(|turn| PredictionTurn {
            user: strip_leading_folded_auto_skills(&turn.user).to_string(),
            agent: turn.agent.clone(),
        })
        .collect();
    let window = last_turns(&sanitized);
    let Some(current) = window.last() else {
        return Vec::new();
    };
    if is_low_information_turn(&current.user) {
        diagnostics.reject_turn("current_turn_gate");
        return Vec::new();
    }
    if is_explicit_continuation(&current.user) {
        window
    } else {
        vec![PredictionTurn {
            user: current.user.clone(),
            agent: String::new(),
        }]
    }
}

/// Remove exactly the wire prefix produced by `Driver::fold_injected_skills`:
/// one or more leading `Skill `<name>` (auto-selected):` blocks separated
/// from the real user text by `\n\n---\n\n`.
fn strip_leading_folded_auto_skills(mut text: &str) -> &str {
    loop {
        let Some(rest) = text.strip_prefix("Skill `") else {
            return text;
        };
        let Some(after_name) = rest.split_once("` (auto-selected):\n\n") else {
            return text;
        };
        let Some((_body, after_block)) = after_name.1.split_once("\n\n---\n\n") else {
            return text;
        };
        text = after_block;
    }
}

fn is_explicit_continuation(text: &str) -> bool {
    let lower = normalize_phrase(text);
    if matches!(
        lower.as_str(),
        "continue" | "keep going" | "do that" | "yes proceed"
    ) {
        return true;
    }
    lower.starts_with("same for ") || lower.starts_with("now do the same for ")
}

fn is_low_information_turn(text: &str) -> bool {
    let lower = normalize_phrase(text);
    matches!(
        lower.as_str(),
        "" | "hi"
            | "hello"
            | "hey"
            | "ok"
            | "okay"
            | "thanks"
            | "thank you"
            | "uhh"
            | "umm"
            | "what now"
    ) || content_words(&lower).is_empty()
}

fn normalize_phrase(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || matches!(c, '.' | '?' | '!' | ','))
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

/// One model-named skill plus the optional reason clause it carried (the
/// remainder of the line after the first ` — `/`-`/`:` separator). The
/// reason is already cleaned (trimmed, single-lined, capped); `None` when
/// the line was a bare name or the clause was empty.
struct ParsedChoice<'a> {
    skill: &'a crate::skills::Skill,
    reason: Option<String>,
}

/// Parse the utility model's reply into the relevance-ordered, deduped
/// list of chosen skills, each with its optional reason clause. Defensive
/// against a weak model's formatting (priority #1): parses **line by
/// line** — the first catalog-name token on a line is the skill, and the
/// remainder after the first ` — `/`-`/`:` separator is the reason. A
/// bare-name line yields `reason = None`, never a parse failure or a
/// dropped skill. Matches names case-insensitively; a line whose first
/// token isn't a catalog name contributes nothing (unknown tokens
/// ignored); a standalone `NONE` line contributes nothing; dedupes while
/// preserving first-seen (relevance) order. The reason is trimmed,
/// collapsed to one line, and length-capped. Returned highest-relevance
/// first.
fn parse_choices<'a>(response: &str, skills: &'a [crate::skills::Skill]) -> Vec<ParsedChoice<'a>> {
    let mut chosen: Vec<ParsedChoice<'a>> = Vec::new();
    for line in response.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // The first catalog-name token on the line is the skill (names are
        // alphanumeric plus `-`/`_`); leading bullets/numbering/stray
        // non-name tokens fall away. A line whose first name-shaped token is
        // a standalone NONE contributes nothing, and the scan stops there so
        // a later in-line word can't masquerade as a pick.
        let mut name_match: Option<(&str, &crate::skills::Skill)> = None;
        for token in line.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
            if token.is_empty() {
                continue;
            }
            if token.eq_ignore_ascii_case("none") {
                break;
            }
            if let Some(skill) = skills
                .iter()
                .find(|s| s.frontmatter.name.eq_ignore_ascii_case(token))
            {
                name_match = Some((token, skill));
                break;
            }
        }
        let Some((name_tok, skill)) = name_match else {
            continue;
        };
        // Dedupe by name, preserving first-seen (relevance) order. A repeat
        // keeps the first line's reason (highest relevance).
        if chosen.iter().any(|c| {
            c.skill
                .frontmatter
                .name
                .eq_ignore_ascii_case(&skill.frontmatter.name)
        }) {
            continue;
        }
        // The reason is whatever follows the first separator after the name
        // token's occurrence on the line.
        let reason = line
            .find(name_tok)
            .map(|i| &line[i + name_tok.len()..])
            .and_then(reason_after_name);
        chosen.push(ParsedChoice { skill, reason });
    }
    chosen
}

/// Extract the reason clause from a line's text *after* the matched name
/// token: skip a leading ` — `/`-`/`:` separator (and surrounding
/// whitespace), then clean what remains. Returns `None` when there's no
/// separator or nothing meaningful follows (bare-name line).
fn reason_after_name(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    // Strip the first reason separator if present: em/en-dash, ASCII `-`,
    // or `:`. Without one, a trailing word is not treated as a reason.
    let after = rest
        .strip_prefix('—')
        .or_else(|| rest.strip_prefix('–'))
        .or_else(|| rest.strip_prefix('-'))
        .or_else(|| rest.strip_prefix(':'))?;
    clean_reason(after)
}

/// Generic English function words plus a few conversational fillers that
/// never signal a skill's domain. Stripped from both sides of the overlap
/// test so only *content* words can establish relevance — keeping the
/// backstop biased toward rejection (NONE) when nothing of substance is
/// shared. Deliberately small and domain-neutral; it must never contain a
/// word that could legitimately describe a skill's subject.
const STOPWORDS: &[&str] = &[
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "has", "her",
    "him", "his", "its", "our", "out", "she", "was", "who", "why", "how", "now", "get", "got",
    "use", "via", "that", "this", "with", "from", "into", "your", "they", "them", "then", "than",
    "what", "when", "where", "which", "will", "would", "should", "could", "have", "here", "there",
    "about", "just", "like", "sure", "yes", "okay", "want", "need", "please", "make", "made",
    "does", "did", "done", "let", "let's", "lets", "switched", "switch", "again", "still", "more",
    "most", "some",
];

/// Generic software/agent terms that show up in nearly every coding
/// request and so carry **no routing signal** — a skill keyword that is one
/// of these can never *distinguish* the skill from any other, so a match on
/// it would let the backstop pass on noise. Applied **only** to the
/// skill-keyword side ([`skill_keywords`]) so the backstop fires solely on a
/// word that actually discriminates the skill (`firecrawl`, `scrape`,
/// `crawl`, `rebrand`, `benchmark`, …). Deliberately scoped here — the
/// request side and every other tokenizer caller keep the smaller
/// [`STOPWORDS`] behavior the reason/other features rely on. Principle: a
/// word shared by most coding requests must not be a match.
const SKILL_KEYWORD_STOPWORDS: &[&str] = &[
    "code",
    "codebase",
    "file",
    "files",
    "project",
    "projects",
    "repo",
    "repos",
    "repository",
    "repositories",
    "analysis",
    "analyze",
    "analyse",
    "bug",
    "bugs",
    "change",
    "changes",
    "build",
    "builds",
    "run",
    "runs",
    "running",
    "test",
    "tests",
    "testing",
    "error",
    "errors",
    "issue",
    "issues",
    "function",
    "functions",
    "feature",
    "features",
    "review",
    "reviews",
    "check",
    "checks",
    "fix",
    "fixes",
    "app",
    "apps",
    "application",
    "applications",
    "data",
    "task",
    "tasks",
    "user",
    "users",
    "request",
    "requests",
    "implement",
    "implementation",
    "create",
    "update",
    "add",
    "remove",
    "delete",
    "write",
    "read",
    "skill",
    "skills",
    "agent",
    "agents",
    "tool",
    "tools",
    "work",
    "help",
    "thing",
    "things",
    "something",
    "anything",
    "everything",
    "context",
    "command",
    "commands",
    "line",
    "lines",
    "page",
    "pages",
    "content",
    "way",
    "ways",
];

/// Tokenize free text into lowercased content words: split on any
/// non-alphanumeric boundary, drop tokens shorter than 3 chars, drop
/// stopwords. The same tokenizer feeds the request word set and the
/// trigger-less description fallback so the overlap test is symmetric.
fn content_words(text: &str) -> std::collections::HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| !STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// Tokenizer for the **skill-keyword side** only: [`content_words`] plus the
/// expanded [`SKILL_KEYWORD_STOPWORDS`] prune. Keeps only *discriminating*
/// words on a skill's keyword set so the backstop never passes on a generic
/// term shared by most coding requests.
fn skill_content_words(text: &str) -> std::collections::HashSet<String> {
    content_words(text)
        .into_iter()
        .filter(|t| !SKILL_KEYWORD_STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// Build a skill's keyword set from the **curated trigger signal** — its
/// `name` (whole + hyphen/underscore parts) and the explicit
/// `when_to_use` / `when-to-use` / `triggers` frontmatter (the intentional
/// routing prose) — pruned of the expanded generic-term stoplist so only
/// *discriminating* words survive. The freeform `description` is **not** used
/// when a skill declares triggers (it is marketing prose full of generic
/// noise — `task`, `project`, `code`, … — that would re-weaken the backstop).
///
/// **Trigger-less fallback:** a skill with no `when_to_use`/`triggers`
/// frontmatter still needs *some* signal, so its `description` words are
/// folded in — but only after the same generic-term prune, so the description
/// contributes its discriminating words alone. Bodies never enter this path
/// (token economy, GOALS §10).
fn skill_keywords(skill: &crate::skills::Skill) -> std::collections::HashSet<String> {
    let mut kw = skill_content_words(&skill.frontmatter.name);
    let mut has_triggers = false;
    for key in ["when_to_use", "when-to-use", "triggers"] {
        if let Some(v) = skill.frontmatter.extra.get(key)
            && let Some(s) = trigger_text(v)
        {
            has_triggers = true;
            kw.extend(skill_content_words(&s));
        }
    }
    if !has_triggers {
        // No curated trigger signal → fall back to the description's
        // discriminating words (generic terms already pruned).
        kw.extend(skill_content_words(&skill.frontmatter.description));
    }
    kw
}

/// Flatten a `when_to_use`/`triggers` frontmatter value to a single string
/// of trigger prose (a scalar string, or a sequence of strings joined by
/// spaces); anything else contributes nothing.
fn trigger_text(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Sequence(items) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

/// Deterministic relevance backstop (priority #1). The utility model's vote
/// is advisory only: a model-named skill survives **iff** the user's recent
/// request shares at least one content word with the skill's keyword set
/// (name parts + declared triggers, or the pruned description for a
/// trigger-less skill — see [`skill_keywords`]). With stopwords and short
/// tokens stripped from both sides, an off-topic message (e.g. the v9h213
/// identity question "Are you sure? I switched you. What are you now?")
/// shares nothing with a web-scraping skill's keywords — `firecrawl`'s
/// description has no `sure`/`switched`/`now` and those are stopwords anyway
/// — so it is rejected and nothing injects. A real request ("scrape the
/// content from https://…") shares `scrape`/`content` with the same keyword
/// set and passes. Order (relevance) is preserved for the survivors.
///
/// This biases hard toward NONE: when nothing of substance is shared, the
/// skill is dropped (logged), never injected on the weak model's say-so.
///
/// Each survivor also carries the **matched content words** (the
/// `request ∩ skill_keywords` intersection it computes here) — the
/// keyword-overlap fallback reason when the model gave none. The matched
/// set is sorted for a deterministic `matches: a, b, c` fallback; it is
/// non-empty for any survivor (that's the survival condition).
#[cfg(test)]
fn relevance_filter<'a>(
    chosen: &[ParsedChoice<'a>],
    turns: &[PredictionTurn],
) -> Vec<Survivor<'a>> {
    let mut diagnostics = SelectionDiagnostics::default();
    relevance_filter_with_diagnostics(chosen, turns, &mut diagnostics)
}

fn relevance_filter_with_diagnostics<'a>(
    chosen: &[ParsedChoice<'a>],
    turns: &[PredictionTurn],
    diagnostics: &mut SelectionDiagnostics,
) -> Vec<Survivor<'a>> {
    // The request words come from the same recent window the model saw:
    // every user message plus agent reply in the last-turns window.
    let mut request = std::collections::HashSet::new();
    let mut request_text = String::new();
    for turn in turns {
        request.extend(content_words(&turn.user));
        request.extend(content_words(&turn.agent));
        request_text.push_str(&turn.user);
        request_text.push('\n');
        request_text.push_str(&turn.agent);
        request_text.push('\n');
    }
    let has_web_trigger = has_external_web_trigger(&request_text);

    let mut kept: Vec<Survivor<'a>> = Vec::new();
    for choice in chosen {
        if !strict_current_turn_triggers_match(choice.skill, &request_text) {
            diagnostics.reject_skill(choice.skill, "strict_current_turn_trigger_mismatch");
            tracing::info!(
                skill = %choice.skill.frontmatter.name,
                "skills auto-select: strict current-turn trigger rejected model pick"
            );
            continue;
        }
        let keywords = skill_keywords(choice.skill);
        let mut matched: Vec<String> = request.intersection(&keywords).cloned().collect();
        if matched.is_empty() {
            diagnostics.reject_skill(choice.skill, "relevance_backstop");
            tracing::info!(
                skill = %choice.skill.frontmatter.name,
                "skills auto-select: relevance backstop rejected an off-topic model pick"
            );
            continue;
        }
        if is_external_web_skill(choice.skill) && !has_web_trigger {
            diagnostics.reject_skill(choice.skill, "external_web_trigger_missing");
            tracing::info!(
                skill = %choice.skill.frontmatter.name,
                "skills auto-select: web-skill guard rejected model pick without an external-web trigger"
            );
            continue;
        }
        // Sort so the keyword-fallback reason is deterministic.
        matched.sort();
        kept.push(Survivor {
            skill: choice.skill,
            reason: choice.reason.clone(),
            matched,
        });
    }
    kept
}

fn strict_current_turn_triggers_match(skill: &crate::skills::Skill, request_text: &str) -> bool {
    let triggers = strict_trigger_phrases(skill);
    if triggers.is_empty() {
        return true;
    }
    let request = normalize_phrase(request_text);
    triggers
        .iter()
        .map(|trigger| normalize_phrase(trigger))
        .any(|trigger| !trigger.is_empty() && request.contains(&trigger))
}

fn strict_trigger_phrases(skill: &crate::skills::Skill) -> Vec<String> {
    for key in [
        "strict_current_turn_triggers",
        "strict-current-turn-triggers",
    ] {
        if let Some(v) = skill.frontmatter.extra.get(key) {
            let phrases: Vec<String> = match v {
                serde_yaml::Value::String(s) => s
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                serde_yaml::Value::Sequence(items) => items
                    .iter()
                    .filter_map(|i| i.as_str().map(str::trim))
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            if !phrases.is_empty() {
                return phrases;
            }
        }
    }
    Vec::new()
}

/// Classify skills whose domain is external web/search/scrape/crawl work.
/// These skills are high token-cost and easy for weak utility models to
/// over-select on generic investigation/research wording, so they must pass
/// both the normal keyword overlap and [`has_external_web_trigger`].
fn is_external_web_skill(skill: &crate::skills::Skill) -> bool {
    let text = skill_signal_text(skill).to_ascii_lowercase();
    [
        "firecrawl",
        "web search",
        "search the web",
        "scrape",
        "scraping",
        "crawler",
        "crawl",
        "webpage",
        "website",
        "web site",
        "url",
        "look up online",
        "fetch this page",
        "fetch this site",
        "download a site",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn skill_signal_text(skill: &crate::skills::Skill) -> String {
    let mut text = format!(
        "{}\n{}",
        skill.frontmatter.name, skill.frontmatter.description
    );
    for key in ["when_to_use", "when-to-use", "triggers"] {
        if let Some(v) = skill.frontmatter.extra.get(key)
            && let Some(s) = trigger_text(v)
        {
            text.push('\n');
            text.push_str(&s);
        }
    }
    text
}

/// Strong request-side triggers for external web data. Generic local-repo
/// words such as "investigate", "state", "repo", "test", "plan",
/// "harness", "tool", "agent", "model", and "token" deliberately do not
/// appear here.
fn has_external_web_trigger(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if contains_url_like(&lower) {
        return true;
    }
    [
        "search the web",
        "web search",
        "look up online",
        "lookup online",
        "online search",
        "scrape",
        "scraping",
        "crawl",
        "crawler",
        "fetch this page",
        "fetch this site",
        "fetch this url",
        "fetch the page",
        "fetch the site",
        "fetch the url",
        "download this site",
        "download the site",
        "latest",
        "news",
        "current price",
        "current docs",
        "current documentation",
        "recent docs",
        "recent documentation",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn contains_url_like(text: &str) -> bool {
    if text.contains("://") || text.contains("www.") {
        return true;
    }
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
            )
    })
    .map(|token| token.trim_matches(|c: char| matches!(c, '.' | ':' | '/' | '?' | '#' | '!')))
    .any(|token| {
        token.contains('.')
            && [
                ".com", ".org", ".net", ".dev", ".io", ".ai", ".app", ".docs",
            ]
            .iter()
            .any(|suffix| token.ends_with(suffix))
    })
}

/// A skill that passed the relevance backstop: the skill, the optional
/// model reason it was parsed with, and the matched content words (sorted,
/// non-empty) used to synthesize the keyword-overlap fallback reason.
struct Survivor<'a> {
    skill: &'a crate::skills::Skill,
    reason: Option<String>,
    matched: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{Skill, SkillFrontmatter};
    use std::path::PathBuf;

    fn skill(name: &str) -> Skill {
        Skill {
            frontmatter: SkillFrontmatter {
                name: name.into(),
                description: "d".into(),
                ..Default::default()
            },
            source: PathBuf::from(format!("/x/{name}/SKILL.md")),
        }
    }

    /// Write a skill on disk (frontmatter + `body`) and return a `Skill`
    /// pointing at it, so `load_body`/`render_body` can read a real file.
    fn write_skill(dir: &Path, name: &str, body: &str) -> Skill {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        let path = sub.join("SKILL.md");
        std::fs::write(
            &path,
            format!("---\nname: {name}\ndescription: d\n---\n{body}"),
        )
        .unwrap();
        Skill {
            frontmatter: SkillFrontmatter {
                name: name.into(),
                description: "d".into(),
                ..Default::default()
            },
            source: path,
        }
    }

    /// Build a `Skill` with a real description (and optional `when_to_use`
    /// trigger prose) so the relevance backstop has keywords to match
    /// against. No on-disk file is needed — the backstop reads frontmatter
    /// only.
    fn skill_desc(name: &str, description: &str) -> Skill {
        Skill {
            frontmatter: SkillFrontmatter {
                name: name.into(),
                description: description.into(),
                ..Default::default()
            },
            source: PathBuf::from(format!("/x/{name}/SKILL.md")),
        }
    }

    fn skill_strict(name: &str, description: &str, triggers: &[&str]) -> Skill {
        let mut skill = skill_desc(name, description);
        skill.frontmatter.extra.insert(
            "strict_current_turn_triggers".into(),
            serde_yaml::Value::Sequence(
                triggers
                    .iter()
                    .map(|trigger| serde_yaml::Value::String((*trigger).to_string()))
                    .collect(),
            ),
        );
        skill
    }

    fn folded_skill(name: &str, body: &str, user: &str) -> String {
        format!("Skill `{name}` (auto-selected):\n\n{body}\n\n---\n\n{user}")
    }

    /// The real `firecrawl` skill description (verbatim subject prose) — the
    /// catalog entry that was wrongly injected in session `v9h213`.
    const FIRECRAWL_DESC: &str = "Search, scrape, and interact with the web \
        via the Firecrawl CLI. Use this skill whenever the user wants to \
        search the web, find articles, research a topic, look something up \
        online, scrape a webpage, grab content from a URL, get data from a \
        website, crawl documentation, download a site, or interact with \
        pages that need clicks or logins.";

    fn no_redact(cwd: &Path) -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::build(&Default::default(), cwd).unwrap()
    }

    fn names(injected: &[InjectedSkill]) -> Vec<String> {
        injected.iter().map(|i| i.name.clone()).collect()
    }

    // ---- robust parser ----

    #[test]
    fn parse_choices_single_exact_match() {
        let skills = vec![skill("deploy"), skill("review")];
        let got = parse_choices("deploy", &skills);
        assert_eq!(choice_names(&got), vec!["deploy"]);
        // Bare name → no reason.
        assert_eq!(got[0].reason, None);
    }

    #[test]
    fn parse_choices_case_insensitive_and_trimmed() {
        let skills = vec![skill("Deploy")];
        let got = parse_choices("  deploy\n", &skills);
        assert_eq!(choice_names(&got), vec!["Deploy"]);
        assert_eq!(got[0].reason, None);
    }

    #[test]
    fn parse_choices_none_keyword_and_empty() {
        let skills = vec![skill("deploy")];
        assert!(parse_choices("NONE", &skills).is_empty());
        assert!(parse_choices("none", &skills).is_empty());
        assert!(parse_choices("", &skills).is_empty());
    }

    #[test]
    fn parse_choices_ignores_unknown_names() {
        let skills = vec![skill("deploy")];
        assert!(parse_choices("ship-it", &skills).is_empty());
        // Known + unknown interleaved: only the known survives.
        let got = parse_choices("ship-it deploy nope", &skills);
        assert_eq!(choice_names(&got), vec!["deploy"]);
        // `nope` is a trailing word, not a separator-introduced reason.
        assert_eq!(got[0].reason, None);
    }

    #[test]
    fn parse_choices_multiple_relevance_order_across_separators() {
        let skills = vec![skill("deploy"), skill("review"), skill("test")];
        // Mixed separators, bullets, numbering, casing, stray punctuation.
        let resp = "1. Review,\n- DEPLOY\n* test!";
        let got = parse_choices(resp, &skills);
        assert_eq!(choice_names(&got), vec!["review", "deploy", "test"]);
    }

    #[test]
    fn parse_choices_dedupes_preserving_first_seen_order() {
        let skills = vec![skill("deploy"), skill("review")];
        let got = parse_choices("review\ndeploy\nReview\nREVIEW\ndeploy", &skills);
        assert_eq!(choice_names(&got), vec!["review", "deploy"]);
    }

    // ---- reason parsing (name — reason) ----

    #[test]
    fn parse_choices_extracts_reason_after_em_dash() {
        let skills = vec![skill("firecrawl")];
        let got = parse_choices("firecrawl — because you asked to scrape a URL", &skills);
        assert_eq!(choice_names(&got), vec!["firecrawl"]);
        assert_eq!(
            got[0].reason.as_deref(),
            Some("because you asked to scrape a URL")
        );
    }

    #[test]
    fn parse_choices_reason_mixed_separators_and_bare() {
        let skills = vec![skill("deploy"), skill("review"), skill("test")];
        // ` - ` hyphen reason, `:` reason, and a bare name (no reason).
        let resp = "deploy - ship the release\nreview: look it over\ntest";
        let got = parse_choices(resp, &skills);
        assert_eq!(choice_names(&got), vec!["deploy", "review", "test"]);
        assert_eq!(got[0].reason.as_deref(), Some("ship the release"));
        assert_eq!(got[1].reason.as_deref(), Some("look it over"));
        assert_eq!(got[2].reason, None);
    }

    #[test]
    fn parse_choices_collapses_multiline_and_caps_reason() {
        let skills = vec![skill("deploy")];
        // A weak model that ran the reason long: it must collapse to one
        // line and cap at the char limit with a trailing `…`.
        let long = "word ".repeat(60);
        let got = parse_choices(&format!("deploy — {long}"), &skills);
        let reason = got[0].reason.as_ref().expect("a reason");
        assert!(
            reason.chars().count() <= SELECT_REASON_MAX_CHARS,
            "reason capped, got {} chars: {reason:?}",
            reason.chars().count()
        );
        assert!(
            reason.ends_with('…'),
            "over-long reason truncated: {reason:?}"
        );
        assert!(!reason.contains('\n'), "single-lined: {reason:?}");
    }

    #[test]
    fn parse_choices_bare_name_never_drops_or_fails() {
        // Bare-name list (old format / model omitted reasons) still parses,
        // each with reason = None.
        let skills = vec![skill("deploy"), skill("review")];
        let got = parse_choices("deploy\nreview", &skills);
        assert_eq!(choice_names(&got), vec!["deploy", "review"]);
        assert!(got.iter().all(|c| c.reason.is_none()));
    }

    fn choice_names(chosen: &[ParsedChoice<'_>]) -> Vec<String> {
        chosen
            .iter()
            .map(|c| c.skill.frontmatter.name.clone())
            .collect()
    }

    fn names_of(chosen: &[Survivor<'_>]) -> Vec<String> {
        chosen
            .iter()
            .map(|s| s.skill.frontmatter.name.clone())
            .collect()
    }

    // ---- deterministic relevance backstop ----

    /// Regression for the v9h213 defect: an agent-identity question must
    /// yield NONE even when the (stubbed) utility model names `firecrawl`.
    /// `parse_choices` accepts the model's pick; the backstop rejects it
    /// because the request shares no content word with the firecrawl
    /// keyword set.
    #[test]
    fn backstop_rejects_firecrawl_on_identity_question() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        // What the weak utility model returned in the export.
        let chosen = parse_choices("firecrawl", &skills);
        assert_eq!(
            choice_names(&chosen),
            vec!["firecrawl"],
            "model named firecrawl"
        );

        let turns = vec![PredictionTurn {
            user: "Are you sure? I switched you. What are you now?".into(),
            agent: String::new(),
        }];
        let kept = relevance_filter(&chosen, &turns);
        assert!(
            kept.is_empty(),
            "off-topic identity question must reject firecrawl, got {:?}",
            names_of(&kept)
        );
    }

    /// A clearly on-topic request must still pass the backstop: a scrape
    /// request shares `scrape`/`content` with the firecrawl keywords.
    #[test]
    fn backstop_passes_genuine_scrape_request() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        let chosen = parse_choices("firecrawl", &skills);
        let turns = vec![PredictionTurn {
            user: "Please scrape the content from https://example.com".into(),
            agent: String::new(),
        }];
        let kept = relevance_filter(&chosen, &turns);
        assert_eq!(
            names_of(&kept),
            vec!["firecrawl"],
            "a genuine scrape request must pass the backstop"
        );
    }

    /// Regression for session `ncs82d`: ordinary local-repo investigation
    /// work must not auto-inject web skills even when the utility model votes
    /// for `firecrawl`.
    #[test]
    fn backstop_rejects_firecrawl_on_ncs82d_local_repo_request() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        let chosen = parse_choices("firecrawl", &skills);
        assert_eq!(
            choice_names(&chosen),
            vec!["firecrawl"],
            "model named firecrawl"
        );

        let turns = vec![PredictionTurn {
            user: "Can you investigate the state of this repo, and then write a test-plan.md..."
                .into(),
            agent: String::new(),
        }];
        let kept = relevance_filter(&chosen, &turns);
        assert!(
            kept.is_empty(),
            "local repo investigation must inject nothing, got {:?}",
            names_of(&kept)
        );
    }

    /// Local codebase prompts contain many words that weak models associate
    /// with broad research/tooling skills. They are not external-web
    /// triggers.
    #[test]
    fn backstop_rejects_web_skills_on_local_repo_plan_request() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let search = skill_desc(
            "web-search",
            "Search the web for online articles and current documentation.",
        );
        let scrape = skill_desc("web-scrape", "Scrape webpages and URLs from websites.");
        let skills = vec![firecrawl, search, scrape];
        let chosen = parse_choices("firecrawl\nweb-search\nweb-scrape", &skills);
        let turns = vec![PredictionTurn {
            user: "investigate this repo and write a plan for the test harness, agent model, and token handling"
                .into(),
            agent: String::new(),
        }];
        assert!(
            relevance_filter(&chosen, &turns).is_empty(),
            "local repo plan prompt must not inject web/search/scrape skills"
        );
    }

    #[test]
    fn backstop_passes_web_skill_for_explicit_search_web_request() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        let chosen = parse_choices("firecrawl", &skills);
        let turns = vec![PredictionTurn {
            user: "search the web for recent OpenAI API docs".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["firecrawl"],
            "explicit web search with recent docs must pass"
        );
    }

    /// The backstop also matches on the skill *name* (and hyphen parts),
    /// not just the description.
    #[test]
    fn backstop_matches_on_skill_name_parts() {
        let s = skill_desc("docker-deploy", "ship containers");
        let skills = vec![s];
        let chosen = parse_choices("docker-deploy", &skills);
        let turns = vec![PredictionTurn {
            user: "help me deploy this".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["docker-deploy"]
        );
    }

    /// Multiple model-named skills are filtered independently: the relevant
    /// one survives, the off-topic one is dropped.
    #[test]
    fn backstop_filters_each_skill_independently() {
        let scrape = skill_desc("firecrawl", FIRECRAWL_DESC);
        let deploy = skill_desc("deploy", "deploy and release the application to production");
        let skills = vec![scrape, deploy];
        // One skill per line (the new parser takes the first catalog name
        // per line as the pick).
        let chosen = parse_choices("firecrawl\ndeploy", &skills);
        assert_eq!(choice_names(&chosen), vec!["firecrawl", "deploy"]);
        let turns = vec![PredictionTurn {
            user: "scrape the webpage content for me".into(),
            agent: String::new(),
        }];
        // Only firecrawl shares words ("scrape"/"webpage"/"content"); deploy
        // shares none and is rejected.
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["firecrawl"]
        );
    }

    /// Declared trigger prose in `when_to_use` frontmatter contributes to
    /// the keyword set even when the description itself is terse.
    #[test]
    fn backstop_uses_when_to_use_triggers() {
        let mut s = skill_desc("k8s", "cluster helper");
        s.frontmatter.extra.insert(
            "when_to_use".into(),
            serde_yaml::Value::String("use when deploying to kubernetes".into()),
        );
        let skills = vec![s];
        let chosen = parse_choices("k8s", &skills);
        let turns = vec![PredictionTurn {
            user: "get this onto kubernetes".into(),
            agent: String::new(),
        }];
        assert_eq!(names_of(&relevance_filter(&chosen, &turns)), vec!["k8s"]);
    }

    #[test]
    fn selector_window_strips_leading_folded_skill_blocks_only() {
        let folded = folded_skill(
            "generate-benchmark",
            "release notes deployment runbook body words",
            "actual user request",
        );
        assert_eq!(
            strip_leading_folded_auto_skills(&folded),
            "actual user request"
        );
        let mentioned_later =
            "please inspect this\n\nSkill `release-notes` (auto-selected):\n\nbody\n\n---\n\nx";
        assert_eq!(
            strip_leading_folded_auto_skills(mentioned_later),
            mentioned_later
        );
    }

    #[test]
    fn selector_window_low_information_current_turn_injects_nothing() {
        let turns = vec![
            PredictionTurn {
                user: folded_skill(
                    "generate-benchmark",
                    "release notes deployment workflow terms",
                    "draft release notes for benchmark generation",
                ),
                agent: "done".into(),
            },
            PredictionTurn {
                user: "Hi!".into(),
                agent: String::new(),
            },
        ];
        let mut diagnostics = SelectionDiagnostics::default();
        assert!(selector_window(&turns, &mut diagnostics).is_empty());
        assert_eq!(diagnostics.rejections[0].reason, "current_turn_gate");
    }

    #[test]
    fn selector_window_uhh_and_what_now_ignore_prior_skill_context() {
        for current in ["Uhh", "what now?"] {
            let turns = vec![
                PredictionTurn {
                    user: folded_skill(
                        "release-notes",
                        "release notes deployment runbook",
                        "draft release notes",
                    ),
                    agent: "done".into(),
                },
                PredictionTurn {
                    user: current.into(),
                    agent: String::new(),
                },
            ];
            let mut diagnostics = SelectionDiagnostics::default();
            assert!(
                selector_window(&turns, &mut diagnostics).is_empty(),
                "{current:?} must be a hard NONE gate"
            );
        }
    }

    #[test]
    fn strict_current_turn_triggers_gate_unrelated_skills() {
        let release = skill_strict(
            "release-notes",
            RELEASE_NOTES_DESC,
            &["draft release notes", "write changelog"],
        );
        let deploy = skill_strict(
            "deploy-runbook",
            DEPLOY_RUNBOOK_DESC,
            &["prepare deployment runbook", "deploy production"],
        );
        let skills = vec![release, deploy];

        let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
        let turns = vec![PredictionTurn {
            user: "workflow task helper skill".into(),
            agent: String::new(),
        }];
        let mut diagnostics = SelectionDiagnostics::default();
        assert!(relevance_filter_with_diagnostics(&chosen, &turns, &mut diagnostics).is_empty());
        assert!(
            diagnostics
                .rejections
                .iter()
                .all(|r| r.reason == "strict_current_turn_trigger_mismatch"),
            "strict mismatch reasons recorded: {:?}",
            diagnostics.rejections
        );

        let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
        let turns = vec![PredictionTurn {
            user: "draft release notes for the new OAuth flow".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["release-notes"]
        );
    }

    #[test]
    fn explicit_continuation_uses_sanitized_prior_context_not_folded_bodies() {
        let release = skill_strict(
            "release-notes",
            RELEASE_NOTES_DESC,
            &["draft release notes"],
        );
        let deploy = skill_strict(
            "deploy-runbook",
            DEPLOY_RUNBOOK_DESC,
            &["prepare deployment runbook"],
        );
        let skills = vec![release, deploy];
        let turns = vec![
            PredictionTurn {
                user: folded_skill(
                    "generate-benchmark",
                    "prepare deployment runbook and other body-only terms",
                    "draft release notes for benchmark generation",
                ),
                agent: "started".into(),
            },
            PredictionTurn {
                user: "continue".into(),
                agent: String::new(),
            },
        ];
        let mut diagnostics = SelectionDiagnostics::default();
        let window = selector_window(&turns, &mut diagnostics);
        assert_eq!(
            window.len(),
            2,
            "continuation keeps sanitized prior context"
        );
        assert!(!window[0].user.contains("body-only terms"));

        let chosen = parse_choices("release-notes\ndeploy-runbook", &skills);
        assert_eq!(
            names_of(&relevance_filter(&chosen, &window)),
            vec!["release-notes"],
            "prior user text can continue; stripped skill body cannot trigger deploy-runbook"
        );
    }

    // ---- hardened relevance backstop (curated keywords + stoplist) ----

    /// Real-ish release-notes description prose (no curated triggers): the
    /// trigger-less fallback path uses this, pruned of generic terms.
    const RELEASE_NOTES_DESC: &str = "Turn a rough change description into \
        clear release notes for users. Use when the user wants to draft, \
        clean up, or publish release notes.";

    /// Real-ish deploy-runbook description prose (no curated triggers).
    const DEPLOY_RUNBOOK_DESC: &str = "Prepare a production deployment \
        runbook: verify readiness, list commands, capture rollback steps, \
        and call out operator checks.";

    /// Negative: a plain bug-audit request must reject every off-topic skill
    /// the weak model nominated. The expanded generic-term stoplist strips
    /// `analysis`/`repo`/`bug`/`change`/`prompt`/… from the keyword side, so
    /// the incidental description overlap that used to pass the backstop no
    /// longer does — all three are rejected, nothing injects.
    #[test]
    fn backstop_rejects_all_on_bug_audit_request() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let release = skill_desc("release-notes", RELEASE_NOTES_DESC);
        let deploy = skill_desc("deploy-runbook", DEPLOY_RUNBOOK_DESC);
        let skills = vec![firecrawl, release, deploy];
        // What the over-nominating utility model returned.
        let chosen = parse_choices("release-notes\ndeploy-runbook\nfirecrawl", &skills);
        assert_eq!(
            choice_names(&chosen),
            vec!["release-notes", "deploy-runbook", "firecrawl"],
            "model nominated all three"
        );
        let turns = vec![PredictionTurn {
            user: "Can you do a deep dive analysis of this repo? I want to \
                   make sure there are no bugs before I ship it. Don't make \
                   any changes."
                .into(),
            agent: String::new(),
        }];
        assert!(
            relevance_filter(&chosen, &turns).is_empty(),
            "a plain bug-audit request must inject nothing, got {:?}",
            names_of(&relevance_filter(&chosen, &turns))
        );
    }

    /// Positive: the bar didn't over-prune — a genuine scrape request still
    /// keeps `firecrawl`, and a genuine release-notes request still keeps
    /// `release-notes`. The discriminating words (`scrape`, `release`) survive
    /// the stoplist.
    #[test]
    fn backstop_keeps_genuine_matches() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let release = skill_desc("release-notes", RELEASE_NOTES_DESC);

        // "scrape the pricing page" → firecrawl (shares `scrape`).
        let fc = [firecrawl];
        let chosen = parse_choices("firecrawl", &fc);
        let turns = vec![PredictionTurn {
            user: "scrape the pricing page".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["firecrawl"],
            "genuine scrape request keeps firecrawl"
        );

        // "draft release notes" -> release-notes (shares `release`,
        // a discriminating description word in the trigger-less fallback).
        let rn = [release];
        let chosen = parse_choices("release-notes", &rn);
        let turns = vec![PredictionTurn {
            user: "draft release notes for the new login flow".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["release-notes"],
            "genuine release-notes request keeps release-notes"
        );
    }

    /// Trigger-less fallback: a skill with only a `description` (no curated
    /// triggers) still matches on a *discriminating* description word, but a
    /// generic-stoplist word in that same request matches nothing.
    #[test]
    fn trigger_less_fallback_matches_discriminating_word_only() {
        // No triggers → keywords come from the pruned description.
        let s = skill_desc(
            "rebrander",
            "Rebrand a product: rename every occurrence across the codebase.",
        );
        let skills = vec![s];

        // A discriminating word (`rebrand`) matches.
        let chosen = parse_choices("rebrander", &skills);
        let turns = vec![PredictionTurn {
            user: "please rebrand the product".into(),
            agent: String::new(),
        }];
        assert_eq!(
            names_of(&relevance_filter(&chosen, &turns)),
            vec!["rebrander"],
            "discriminating description word matches in the trigger-less fallback"
        );

        // A request sharing only generic-stoplist words (`codebase`,
        // `application`) with the description matches nothing — those were
        // pruned from the keyword side.
        let chosen = parse_choices("rebrander", &skills);
        let turns = vec![PredictionTurn {
            user: "look at the codebase for this application".into(),
            agent: String::new(),
        }];
        assert!(
            relevance_filter(&chosen, &turns).is_empty(),
            "a generic-stoplist-only overlap must not pass the backstop"
        );
    }

    // ---- once-per-session suppression (change 4) ----

    /// The already-injected exclusion is applied at the same discover-then-
    /// filter step `select_inner` uses (before the catalog): a skill in the
    /// exclusion set drops out, the rest stay.
    fn select_catalog_excluding(
        cwd: &Path,
        cfg: &crate::config::extended::SkillsConfig,
        already_injected: &std::collections::HashSet<String>,
    ) -> Vec<crate::skills::Skill> {
        crate::skills::discover(cwd, cfg)
            .unwrap()
            .into_iter()
            .filter(|s| !s.frontmatter.disable_model_invocation)
            .filter(|s| !already_injected.contains(&s.frontmatter.name))
            .collect()
    }

    #[test]
    fn already_injected_skill_excluded_before_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_fm_skill(&scan, "firecrawl", "");
        write_fm_skill(&scan, "release-notes", "");
        let cfg = crate::config::extended::SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            auto_bang_commands: false,
            ancestor_walk: false,
        };

        // With firecrawl already injected this session, it is gone from the
        // candidate set; a different still-relevant skill is unaffected.
        let mut injected = std::collections::HashSet::new();
        injected.insert("firecrawl".to_string());
        let candidates = select_catalog_excluding(tmp.path(), &cfg, &injected);
        let names: Vec<&str> = candidates
            .iter()
            .map(|s| s.frontmatter.name.as_str())
            .collect();
        assert!(
            !names.contains(&"firecrawl"),
            "already-injected firecrawl excluded from the catalog; got {names:?}"
        );
        assert!(
            names.contains(&"release-notes"),
            "a different skill is unaffected; got {names:?}"
        );

        // Excluding the only candidate empties the set → `select_inner`
        // returns `Selection::None` (its `skills.is_empty()` path), never an
        // error.
        let mut both = std::collections::HashSet::new();
        both.insert("firecrawl".to_string());
        both.insert("release-notes".to_string());
        let candidates = select_catalog_excluding(tmp.path(), &cfg, &both);
        assert!(
            candidates.is_empty(),
            "excluding every candidate yields an empty set (→ Selection::None)"
        );
    }

    /// End-to-end through `select`: the once-per-session set short-circuits to
    /// `Selection::None` when it empties the candidates — no utility model is
    /// ever consulted, no error. (A genuine match on `firecrawl` — proven by
    /// `backstop_keeps_genuine_matches` — would otherwise inject; suppression
    /// is the gate that stops the repeat.)
    #[tokio::test]
    async fn select_returns_none_when_exclusion_empties_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(scan.join("firecrawl")).unwrap();
        std::fs::write(
            scan.join("firecrawl").join("SKILL.md"),
            "---\nname: firecrawl\ndescription: scrape the web\n---\nBODY",
        )
        .unwrap();

        let mut extended = ExtendedConfig::default();
        extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
        // A utility model IS configured (so the unset-model short-circuit is
        // not what we're testing) — but exclusion empties the candidates
        // before any call is made.
        extended.utility_model = Some("nope/nope".into());
        let providers = ProvidersConfig::default();
        let redact = std::sync::Arc::new(
            crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
        );
        let turns = vec![PredictionTurn {
            user: "scrape the pricing page".into(),
            agent: String::new(),
        }];
        let mut injected = std::collections::HashSet::new();
        injected.insert("firecrawl".to_string());

        let sel = select(tmp.path(), &extended, &providers, redact, &turns, &injected).await;
        assert!(
            matches!(sel, Selection::None),
            "exclusion empties the candidates → Selection::None, no error, no model call"
        );
    }

    // ---- prompt window ----

    #[test]
    fn prompt_carries_last_turn_transcript_not_a_single_message() {
        let turns = vec![
            PredictionTurn {
                user: "set up CI".into(),
                agent: "Added a workflow.".into(),
            },
            PredictionTurn {
                user: "now deploy it".into(),
                agent: String::new(),
            },
        ];
        let p = build_select_prompt("- deploy: d\n", &turns);
        assert!(p.contains("USER: set up CI"), "{p}");
        assert!(p.contains("AGENT: Added a workflow."), "{p}");
        assert!(p.contains("USER: now deploy it"), "{p}");
        // Open turn (no agent reply) omits the AGENT marker for that turn.
        assert!(!p.contains("AGENT: \n"), "{p}");
        // Catalog present; no body content leaks in.
        assert!(p.contains("- deploy: d"), "{p}");
    }

    // ---- relevance-filter matched words + fallback reason ----

    /// The backstop returns the matched content words per survivor (sorted),
    /// and the keyword fallback synthesizes `matches: a, b, c` from them.
    #[test]
    fn relevance_filter_returns_matched_words_and_fallback() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        let chosen = parse_choices("firecrawl", &skills); // bare name → no model reason
        let turns = vec![PredictionTurn {
            user: "please scrape the webpage content".into(),
            agent: String::new(),
        }];
        let kept = relevance_filter(&chosen, &turns);
        assert_eq!(names_of(&kept), vec!["firecrawl"]);
        // The matched set is the request ∩ keyword intersection, sorted.
        // `content` is a generic skill-keyword stopword now, so it does not
        // contribute; the discriminating `scrape`/`webpage` do.
        let m = &kept[0].matched;
        assert!(m.contains(&"scrape".to_string()), "matched: {m:?}");
        assert!(m.contains(&"webpage".to_string()), "matched: {m:?}");
        assert!(
            !m.contains(&"content".to_string()),
            "generic stopword pruned from keyword side: {m:?}"
        );
        assert!(m.windows(2).all(|w| w[0] <= w[1]), "sorted: {m:?}");
        // No model reason → keyword fallback is synthesized.
        assert_eq!(kept[0].reason, None);
        let fb = fallback_reason(&kept[0].matched).expect("a fallback reason");
        assert!(fb.starts_with("matches: "), "fallback shape: {fb:?}");
        // Capped to the first few words.
        let listed = fb.trim_start_matches("matches: ").split(", ").count();
        assert!(listed <= FALLBACK_KEYWORD_COUNT, "fallback capped: {fb:?}");
    }

    /// A model reason on the line survives the backstop and takes precedence
    /// over the keyword fallback in `render_capped_and_budgeted`.
    #[test]
    fn relevance_filter_preserves_model_reason() {
        let firecrawl = skill_desc("firecrawl", FIRECRAWL_DESC);
        let skills = vec![firecrawl];
        let chosen = parse_choices("firecrawl — to scrape the page you named", &skills);
        let turns = vec![PredictionTurn {
            user: "scrape the content".into(),
            agent: String::new(),
        }];
        let kept = relevance_filter(&chosen, &turns);
        assert_eq!(
            kept[0].reason.as_deref(),
            Some("to scrape the page you named")
        );
    }

    // ---- cap + budget rendering ----

    /// Build a `Survivor` for the render tests: no model reason, no matched
    /// words (the render path's reason population is exercised separately).
    fn survivor(skill: &Skill) -> Survivor<'_> {
        Survivor {
            skill,
            reason: None,
            matched: Vec::new(),
        }
    }

    #[test]
    fn render_multi_match_injects_all_in_relevance_order() {
        let tmp = tempfile::tempdir().unwrap();
        let a = write_skill(tmp.path(), "deploy", "deploy body");
        let b = write_skill(tmp.path(), "review", "review body");
        let chosen = vec![survivor(&a), survivor(&b)];
        let extended = ExtendedConfig::default();
        let injected =
            render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
        assert_eq!(names(&injected), vec!["deploy", "review"]);
        assert_eq!(injected[0].body.trim(), "deploy body");
        assert_eq!(injected[1].body.trim(), "review body");
    }

    #[test]
    fn render_single_match_injects_one() {
        let tmp = tempfile::tempdir().unwrap();
        let a = write_skill(tmp.path(), "deploy", "deploy body");
        let chosen = vec![survivor(&a)];
        let extended = ExtendedConfig::default();
        let injected =
            render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
        assert_eq!(names(&injected), vec!["deploy"]);
    }

    /// `render_capped_and_budgeted` populates the reason: the model reason
    /// when present, else the keyword fallback from the matched words.
    #[test]
    fn render_populates_reason_model_then_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let a = write_skill(tmp.path(), "deploy", "deploy body");
        let b = write_skill(tmp.path(), "review", "review body");
        let extended = ExtendedConfig::default();
        let chosen = vec![
            Survivor {
                skill: &a,
                reason: Some("because you asked to ship".into()),
                matched: vec!["ship".into()],
            },
            Survivor {
                skill: &b,
                reason: None,
                matched: vec!["review".into(), "diff".into()],
            },
        ];
        let injected =
            render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
        assert_eq!(
            injected[0].reason.as_deref(),
            Some("because you asked to ship"),
            "model reason wins"
        );
        assert_eq!(
            injected[1].reason.as_deref(),
            Some("matches: review, diff"),
            "keyword fallback when no model reason"
        );
    }

    #[test]
    fn render_cap_keeps_top_n_by_order() {
        let tmp = tempfile::tempdir().unwrap();
        // More skills than the cap; all tiny so the budget never bites.
        let s: Vec<Skill> = (0..MAX_SELECTED_SKILLS + 2)
            .map(|i| write_skill(tmp.path(), &format!("s{i}"), "x"))
            .collect();
        let chosen: Vec<Survivor> = s.iter().map(survivor).collect();
        let extended = ExtendedConfig::default();
        let injected =
            render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
        assert_eq!(injected.len(), MAX_SELECTED_SKILLS);
        // The kept set is the top-N by relevance order (s0..s{N-1}).
        let expected: Vec<String> = (0..MAX_SELECTED_SKILLS).map(|i| format!("s{i}")).collect();
        assert_eq!(names(&injected), expected);
    }

    #[test]
    fn render_budget_drops_lowest_priority_whole_bodies() {
        let tmp = tempfile::tempdir().unwrap();
        // First body nearly fills the budget; the second is non-trivial and
        // cannot fit, so it is dropped whole (never truncated). Both within
        // the count cap so only the budget is under test.
        let near_full = "word ".repeat(SELECTED_BODY_TOKEN_BUDGET - 50);
        let second = "word ".repeat(200);
        assert!(
            crate::tokens::count(&near_full) <= SELECTED_BODY_TOKEN_BUDGET,
            "first body must fit alone"
        );
        assert!(
            crate::tokens::count(&near_full) + crate::tokens::count(&second)
                > SELECTED_BODY_TOKEN_BUDGET,
            "combined must exceed budget"
        );
        let a = write_skill(tmp.path(), "deploy", &near_full);
        let b = write_skill(tmp.path(), "review", &second);
        let chosen = vec![survivor(&a), survivor(&b)];
        let extended = ExtendedConfig::default();
        let injected =
            render_capped_and_budgeted(&chosen, tmp.path(), &extended, &no_redact(tmp.path()));
        // Only the high-priority body survives; the lower one is dropped
        // whole. The survivor is byte-for-byte the full body (no truncation).
        assert_eq!(names(&injected), vec!["deploy"]);
        assert_eq!(injected[0].body.trim(), near_full.trim());
    }

    // ---- auto-select invocation filter ----

    /// Mirror of the discover-then-filter step in `select_inner`: a skill
    /// enters the utility-model catalog iff `disable-model-invocation` is not
    /// true. `user-invocable` does not affect catalog membership.
    fn auto_select_catalog(cwd: &Path, cfg: &crate::config::extended::SkillsConfig) -> String {
        let skills: Vec<crate::skills::Skill> = crate::skills::discover(cwd, cfg)
            .unwrap()
            .into_iter()
            .filter(|s| !s.frontmatter.disable_model_invocation)
            .collect();
        crate::skills::catalog_lines(&skills)
    }

    fn write_fm_skill(dir: &Path, name: &str, frontmatter_extra: &str) {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: d-{name}\n{frontmatter_extra}---\nB"),
        )
        .unwrap();
    }

    #[test]
    fn disable_model_invocation_excluded_from_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_fm_skill(&scan, "plain", "");
        write_fm_skill(&scan, "useronly", "disable-model-invocation: true\n");
        let cfg = crate::config::extended::SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            auto_bang_commands: false,
            ancestor_walk: false,
        };
        let catalog = auto_select_catalog(tmp.path(), &cfg);
        assert!(catalog.contains("plain"), "got {catalog:?}");
        assert!(
            !catalog.contains("useronly") && !catalog.contains("d-useronly"),
            "a disable-model-invocation skill must not enter the catalog; got {catalog:?}"
        );
    }

    #[test]
    fn user_invocable_false_stays_in_catalog() {
        // A model-only skill (hidden from the slash menu) is still
        // auto-injectable, so its description stays in the catalog.
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_fm_skill(&scan, "modelonly", "user-invocable: false\n");
        let cfg = crate::config::extended::SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            auto_bang_commands: false,
            ancestor_walk: false,
        };
        let catalog = auto_select_catalog(tmp.path(), &cfg);
        assert!(
            catalog.contains("modelonly"),
            "a user-invocable:false skill must remain in the auto-select catalog; got {catalog:?}"
        );
    }

    // ---- graceful degradation ----

    #[tokio::test]
    async fn select_skips_when_utility_model_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(scan.join("deploy")).unwrap();
        std::fs::write(
            scan.join("deploy").join("SKILL.md"),
            "---\nname: deploy\ndescription: d\n---\nBODY",
        )
        .unwrap();

        let mut extended = ExtendedConfig::default();
        extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
        // utility_model deliberately unset.
        let providers = ProvidersConfig::default();
        let redact = std::sync::Arc::new(
            crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
        );

        let turns = vec![PredictionTurn {
            user: "deploy please".into(),
            agent: String::new(),
        }];
        let sel = select(
            tmp.path(),
            &extended,
            &providers,
            redact,
            &turns,
            &std::collections::HashSet::new(),
        )
        .await;
        assert!(
            matches!(sel, Selection::None),
            "unset utility_model must skip auto-selection without error"
        );
    }

    #[tokio::test]
    async fn select_low_information_turn_skips_before_model_lookup_with_diagnostics() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(scan.join("release-notes")).unwrap();
        std::fs::write(
            scan.join("release-notes").join("SKILL.md"),
            "---\nname: release-notes\ndescription: draft release notes\n---\nBODY",
        )
        .unwrap();

        let mut extended = ExtendedConfig::default();
        extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];
        extended.utility_model = Some("missing-provider/missing-model".into());
        let providers = ProvidersConfig::default();
        let redact = std::sync::Arc::new(
            crate::redact::RedactionTable::build(&Default::default(), tmp.path()).unwrap(),
        );
        let turns = vec![PredictionTurn {
            user: "thanks".into(),
            agent: String::new(),
        }];

        let (sel, diagnostics) = select_with_diagnostics(
            tmp.path(),
            &extended,
            &providers,
            redact,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            &turns,
            &std::collections::HashSet::new(),
        )
        .await;

        assert!(matches!(sel, Selection::None));
        assert_eq!(diagnostics.rejections.len(), 1);
        assert_eq!(diagnostics.rejections[0].skill, None);
        assert_eq!(diagnostics.rejections[0].reason, "current_turn_gate");
    }
}
