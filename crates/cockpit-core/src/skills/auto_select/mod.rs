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

use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::engine::predict::{PredictionTurn, last_turns};

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
    pub package_dir: String,
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
        None,
        &[],
        turns,
        already_injected,
    )
    .await
    .0
}

#[allow(clippy::too_many_arguments)]
pub async fn select_with_diagnostics(
    cwd: &Path,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown_gate: Option<crate::daemon::shutdown::ShutdownSignal>,
    active_tools: &[String],
    turns: &[PredictionTurn],
    already_injected: &std::collections::HashSet<String>,
) -> (Selection, SelectionDiagnostics) {
    match select_inner(
        cwd,
        extended,
        providers,
        redact,
        trusted_only,
        shutdown_gate,
        active_tools,
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

#[allow(clippy::too_many_arguments)]
async fn select_inner(
    cwd: &Path,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown_gate: Option<crate::daemon::shutdown::ShutdownSignal>,
    active_tools: &[String],
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
    let activation =
        crate::skills::ActivationContext::from_tool_names(active_tools.iter().map(String::as_str));
    let skills: Vec<crate::skills::Skill> =
        crate::skills::discover_for_session(cwd, &extended.skills, &activation)?
            .into_iter()
            .filter(crate::skills::is_model_invocable)
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
    let model = match shutdown_gate {
        Some(gate) => model.with_shutdown_gate(gate),
        None => model,
    };
    let catalog = crate::skills::catalog_lines(&skills);
    let prompt = build_select_prompt(&catalog, &window);
    let response = model
        .text_completion_for(
            crate::engine::model::UtilityCallSite::SkillAutoSelect,
            &prompt,
        )
        .await?;

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
            package_dir: redact.scrub(&crate::skills::package_root(skill).display().to_string()),
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
/// one or more leading `Skill `<name>` (auto-selected, package directory: ...):` blocks separated
/// from the real user text by `\n\n---\n\n`.
fn strip_leading_folded_auto_skills(mut text: &str) -> &str {
    loop {
        let Some(rest) = text.strip_prefix("Skill `") else {
            return text;
        };
        let Some(after_name) = rest.split_once("` (auto-selected, package directory: ") else {
            return text;
        };
        let Some(after_header) = after_name.1.split_once("):\n\n") else {
            return text;
        };
        let Some((_body, after_block)) = after_header.1.split_once("\n\n---\n\n") else {
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
mod tests;
