//! Post-tool-result hint layer for `bash` (codebase-agnostic).
//!
//! After every `bash` call completes, the registered rules inspect the
//! current call's `(exit_code, stdout, stderr, command)` plus a read-only
//! slice of the agent's recent bash history (last [`HISTORY_WINDOW`] calls'
//! command strings + exit codes). Rules are checked in registration order;
//! the FIRST match wins. On a match the driver:
//!
//!   - appends a `--- hint(<rule_id>): <wire_text>` line to the model-bound
//!     `tool_result` (wire side — GOALS §14), and
//!   - records a `data.hint = { kind, text, severity }` field on the
//!     `tool_call` event (user side — surfaced as a TUI chip).
//!
//! This is the lighter, earlier-firing counterpart to the exact-string
//! `loop_guard_rule`: it never blocks, it only nudges, and it catches the
//! near-duplicate chains the exact-string guard misses (a filter-refinement
//! loop is a chain of *distinct* command strings).
//!
//! ## Extending with user-defined rules (deferred — out of scope here)
//!
//! The extension point is the [`BashHintRule`] trait + the [`registry`]
//! builder. A future PR that adds user-config rules (per-project TOML/JSON,
//! or seed overrides) implements [`BashHintRule`] for the config-loaded rule
//! and prepends it to the registry vec so it is consulted before the built-in
//! seeds (first-match-wins lets a higher-priority user rule shadow a seed by
//! matching the same trigger). No placeholder config field exists today —
//! adding one that parses-but-does-nothing would be tech debt; the clean seam
//! is this trait + the ordered registry, nothing more.

/// How many prior bash calls the hint layer keeps in the per-agent history
/// ring (command string + exit code each). Small and O(1)-bounded so the
/// per-call cost is negligible against a shell dispatch. Both seed rules
/// look back at most `K = 3`/`K = 4` of these.
pub const HISTORY_WINDOW: usize = 8;

/// One prior bash call in the recent-history slice: its command string and
/// the process exit code (`None` on a signaled / spawn-failed run).
#[derive(Debug, Clone)]
pub struct BashHistoryEntry {
    pub command: String,
    pub exit_code: Option<i32>,
}

/// The inputs a [`BashHintRule`] inspects: the current `bash` call plus a
/// read-only slice of the agent's recent bash history. `recent` is
/// **newest-last** (the call immediately before the current one is the last
/// element) and never includes the current call.
pub struct BashCallContext<'a> {
    pub command: &'a str,
    pub exit_code: Option<i32>,
    pub stdout: &'a str,
    /// The call's stderr. Part of the documented rule-input contract (a rule
    /// may match on it); neither built-in seed consults it today, so it is
    /// read only by future rules (built-in or the deferred user-config surface)
    /// — hence `allow(dead_code)` rather than dropping a contract field.
    #[allow(dead_code)]
    pub stderr: &'a str,
    /// Prior bash calls, oldest-first, current call excluded. At most
    /// [`HISTORY_WINDOW`] entries.
    pub recent: &'a [BashHistoryEntry],
}

/// A guidance hint produced by a matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// Stable rule id — both the wire marker key and the `data.hint.kind`.
    pub kind: &'static str,
    /// The one-line fragment appended to the model-bound `tool_result`.
    pub wire_text: String,
    /// The short user-facing chip text + severity recorded on the event.
    pub user_chip: UserChip,
}

/// The user-side surface of a hint: a short line + a severity, recorded as
/// `data.hint = { kind, text, severity }` on the `tool_call` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserChip {
    pub text: String,
    pub severity: Severity,
}

/// Hint severity — `info` (a nudge) or `warn` (a stronger course-correction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
        }
    }
}

/// A codebase-agnostic bash-result hint rule. Built-in seeds implement this;
/// the (deferred) user-config surface will implement it too and prepend its
/// rules to the [`registry`].
pub trait BashHintRule: Send + Sync {
    /// Stable id, used as `hint.kind` and as the future user-config override
    /// key. Must be unique across the registry.
    fn id(&self) -> &'static str;

    /// One-sentence human-readable description, surfaced by
    /// `cockpit bash-hints list`.
    fn description(&self) -> &'static str;

    /// Inspect the call; return `Some(hint)` to fire, `None` to pass.
    fn check(&self, call: &BashCallContext<'_>) -> Option<Hint>;
}

/// The ordered rule registry. Rules are consulted front-to-back and the
/// FIRST match wins (see [`first_hint`]). A future user-config PR prepends
/// its rules here so a user rule can shadow a seed on the same trigger.
pub fn registry() -> Vec<Box<dyn BashHintRule>> {
    vec![
        Box::new(FilterRefinementLoop),
        Box::new(ExitZeroEmptyThrash),
    ]
}

/// Split a `bash` tool-result body (the `tools::bash::format_combined` shape:
/// an optional `stdout:\n…` block, an optional `stderr:\n…` block, then the
/// `exit:`/annotation lines) into its `(stdout, stderr)` section bodies. A
/// missing section yields `""`. The trailing `exit:`/`(no output…)` lines are
/// never part of either section. This is how the dispatch site builds an
/// accurate [`BashCallContext`] from the assembled body without re-plumbing
/// the raw streams out of the `bash` tool.
pub fn split_bash_body(body: &str) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    // Section we're currently accumulating: 0 = none, 1 = stdout, 2 = stderr.
    let mut section = 0u8;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        match trimmed {
            "stdout:" => {
                section = 1;
                continue;
            }
            "stderr:" => {
                section = 2;
                continue;
            }
            _ => {}
        }
        // The trailing `exit:`/annotation lines close any open section and are
        // not body content.
        if trimmed.starts_with("exit:") || (trimmed.starts_with("(no output") && section == 0) {
            section = 0;
            continue;
        }
        match section {
            1 => stdout.push_str(line),
            2 => stderr.push_str(line),
            _ => {}
        }
    }
    (stdout, stderr)
}

/// Run the registry against `call` and return the first matching hint, if any
/// (first-match-wins; only the winner's `kind` is recorded — no suppression on
/// repeat, no dedup).
pub fn first_hint(call: &BashCallContext<'_>) -> Option<Hint> {
    registry().into_iter().find_map(|rule| rule.check(call))
}

/// Wire-side failure guard for a completed `bash` call
/// (implementation note). When a command exits
/// NON-ZERO (or is signaled — `exit_code == None` on a non-hard-failed bash
/// run), weak models skim past the trailing `exit:` line and report the step
/// as "verified." This returns the `(leading_marker, nudge)` pair to splice
/// into the WIRE `tool_result` only (GOALS §14 — the stored/user body is never
/// rewritten): the marker goes at the TOP of the model-facing body, the nudge
/// at the tail. `None` on success (`Some(0)`).
///
/// Exit-code-based ONLY — no cargo/test/git keywords, no stderr heuristics; an
/// exit-0-with-stderr command returns `None`. The marker is ADDITIVE — the
/// existing trailing `exit:` line stays. Coexists with the `--- hint(...)`
/// line: the marker is at the body's head and the nudge is appended before the
/// hint line, so neither clobbers the other (see the splice in
/// `engine::agent`).
pub fn failure_guard(exit_code: Option<i32>) -> Option<(String, String)> {
    match exit_code {
        Some(0) => None,
        Some(n) => Some((
            format!("FAILED (exit {n})"),
            format!(
                "This command FAILED (exit {n}). Do not report this step as verified / passing until a command for it exits 0."
            ),
        )),
        // No numeric code on a non-hard-failed bash run is the signaled/aborted
        // case (`bash.rs` omits `exit_code` only when `signaled`).
        None => Some((
            "FAILED (signaled)".to_string(),
            "This command FAILED (signaled). Do not report this step as verified / passing until a command for it exits 0.".to_string(),
        )),
    }
}

/// Splice the [`failure_guard`] marker + nudge onto a `bash` WIRE `tool_result`
/// body: marker at the TOP, the original body next, then the nudge at the tail.
/// On a passing command (`exit_code == Some(0)`) the body is returned unchanged
/// (byte-identical). This is the exact composition the dispatcher
/// (`engine::agent`) performs BEFORE the `--- hint(...)` line is appended, so a
/// failing command that also trips a hint rule keeps both the nudge and the
/// hint line (the hint line follows this output untouched).
pub fn apply_failure_guard(wire: String, exit_code: Option<i32>) -> String {
    match failure_guard(exit_code) {
        None => wire,
        Some((marker, nudge)) => {
            let mut out = format!("{marker}\n{wire}");
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&nudge);
            out.push('\n');
            out
        }
    }
}

// ---------------------------------------------------------------------------
// Seed rule 1: filter_refinement_loop
// ---------------------------------------------------------------------------

/// The number of consecutive narrowing steps required to fire
/// `filter_refinement_loop` (the current call + the two before it).
const FILTER_LOOP_K: usize = 3;

/// Fires when the last `K = 3` bash calls (current + the two prior) share the
/// same base invocation (the prefix up to the first `|`) AND each successive
/// call extends the previous one by appending exactly one more stdin-filter
/// segment (`grep -v` / `rg -v` / `awk '!/…/'` / `sed -e '/…/d'`). This is the
/// near-duplicate chain the exact-string `loop_guard_rule` misses.
struct FilterRefinementLoop;

impl BashHintRule for FilterRefinementLoop {
    fn id(&self) -> &'static str {
        "filter_refinement_loop"
    }

    fn description(&self) -> &'static str {
        "Fires when the last three bash calls keep appending another stdin exclusion filter to the same base command."
    }

    fn check(&self, call: &BashCallContext<'_>) -> Option<Hint> {
        // Need K-1 prior calls; combine them with the current call into a
        // newest-last chain of exactly K command strings.
        if call.recent.len() < FILTER_LOOP_K - 1 {
            return None;
        }
        let prior = &call.recent[call.recent.len() - (FILTER_LOOP_K - 1)..];
        let mut chain: Vec<&str> = prior.iter().map(|e| e.command.as_str()).collect();
        chain.push(call.command);

        if !is_filter_refinement_chain(&chain) {
            return None;
        }

        Some(Hint {
            kind: "filter_refinement_loop",
            wire_text: "You've narrowed this filter ≥3 times in a row. Read the source directly (`read <file>` or the `search` intel tool) instead of refining stdin filters."
                .to_string(),
            user_chip: UserChip {
                text: "narrowing the same filter ≥3× — read the source instead".to_string(),
                severity: Severity::Warn,
            },
        })
    }
}

/// True when `chain` (newest-last, length ≥ 2) is a filter-refinement chain:
/// every entry shares the same base invocation (prefix up to the first `|`)
/// and each successive entry adds exactly one more stdin-filter segment to the
/// prior one's pipeline (the prior's segments are a strict prefix of the
/// next's, and the appended tail segment is itself an exclusion filter).
fn is_filter_refinement_chain(chain: &[&str]) -> bool {
    if chain.len() < 2 {
        return false;
    }
    let stages: Vec<Vec<String>> = chain.iter().map(|c| pipeline_segments(c)).collect();

    // Same base invocation across the chain (first segment, normalized).
    let base = &stages[0][0];
    if !stages.iter().all(|s| &s[0] == base) {
        return false;
    }

    for win in stages.windows(2) {
        let (prev, next) = (&win[0], &win[1]);
        // Each step adds exactly one segment.
        if next.len() != prev.len() + 1 {
            return false;
        }
        // The prior pipeline is a strict prefix of the next.
        if next[..prev.len()] != prev[..] {
            return false;
        }
        // The newly appended segment must be an exclusion filter.
        if !is_exclusion_filter(next.last().unwrap()) {
            return false;
        }
    }
    true
}

/// Split a command on top-level `|` and trim/whitespace-normalize each
/// segment. (Codebase-agnostic and cheap — no shell parse; a quoted `|` is a
/// rare false-negative that simply skips the hint, never a false fire.)
fn pipeline_segments(command: &str) -> Vec<String> {
    command
        .split('|')
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// Whether a pipeline segment is a recognized stdin exclusion filter. The set
/// is intentionally capped (don't over-engineer): `grep -v` / `rg -v`,
/// `awk '!/…/'`, `sed -e '/…/d'` (or `sed '/…/d'`).
fn is_exclusion_filter(segment: &str) -> bool {
    let seg = segment.trim();
    let mut tokens = seg.split_whitespace();
    let Some(prog) = tokens.next() else {
        return false;
    };
    match prog {
        // `grep -v …` / `rg -v …` — a `-v` flag anywhere before the pattern,
        // including bundled forms like `-rv`/`-iv`.
        "grep" | "rg" => seg
            .split_whitespace()
            .skip(1)
            .any(|t| t == "-v" || (t.starts_with('-') && !t.starts_with("--") && t.contains('v'))),
        // `awk '!/…/'` — a negated match-and-print one-liner.
        "awk" => seg.contains("!/"),
        // `sed -e '/…/d'` or `sed '/…/d'` — a delete-matching-lines script.
        "sed" => {
            seg.contains("/d'") || seg.contains("/d\"") || seg.contains("d;") || seg.ends_with('d')
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Seed rule 2: exit_zero_empty_thrash
// ---------------------------------------------------------------------------

/// Look-back window for `exit_zero_empty_thrash` (the prior calls examined).
const THRASH_K: usize = 4;
/// How many of the last `K` prior calls must also be exit-0-empty on the same
/// target for the rule to fire.
const THRASH_MIN_PRIOR: usize = 2;

/// Fires when the current call returns exit 0 + empty stdout (whitespace-only
/// counts as empty) AND ≥ [`THRASH_MIN_PRIOR`] of the last [`THRASH_K`] prior
/// calls also returned exit 0 + empty stdout AND target the same path-shaped
/// argument as the current call but with a DIFFERENT flag set. The model keeps
/// re-running an empty-but-successful inspection, reading the void as "I typed
/// it wrong" rather than "the answer is empty."
struct ExitZeroEmptyThrash;

impl BashHintRule for ExitZeroEmptyThrash {
    fn id(&self) -> &'static str {
        "exit_zero_empty_thrash"
    }

    fn description(&self) -> &'static str {
        "Fires when repeated exit-0 empty-output commands keep probing the same target with different flags."
    }

    fn check(&self, call: &BashCallContext<'_>) -> Option<Hint> {
        // Current call must itself be exit-0 + empty stdout.
        if call.exit_code != Some(0) || !is_blank(call.stdout) {
            return None;
        }
        let target = same_target_token(call.command)?;
        let cur_flags = flag_set(call.command);

        // Count prior exit-0-empty calls on the same target with a different
        // flag set, within the last K.
        let window = if call.recent.len() > THRASH_K {
            &call.recent[call.recent.len() - THRASH_K..]
        } else {
            call.recent
        };
        let matching = window
            .iter()
            .filter(|e| e.exit_code == Some(0))
            .filter(|e| same_target_token(&e.command).as_deref() == Some(target.as_str()))
            .filter(|e| flag_set(&e.command) != cur_flags)
            .count();
        if matching < THRASH_MIN_PRIOR {
            return None;
        }

        Some(Hint {
            kind: "exit_zero_empty_thrash",
            wire_text: "These commands keep returning empty output successfully — the result *is* empty for this target. Confirm the target exists / is tracked, or try a different inspection (`read` the file, `ls`/`stat` the path, etc.) before retrying with new flags."
                .to_string(),
            user_chip: UserChip {
                text: "empty result is the answer — stop permuting flags".to_string(),
                severity: Severity::Info,
            },
        })
    }
}

/// Whether a stdout slice counts as empty (whitespace-only included).
fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// The "same target" token for a command: the first argument that looks
/// path-ish (contains `/`) or extension-ish (matches `\.[A-Za-z0-9]+$`),
/// falling back to the first non-flag token if no path-ish token exists.
/// `None` only when the command has no non-flag token at all.
fn same_target_token(command: &str) -> Option<String> {
    let args: Vec<&str> = command.split_whitespace().skip(1).collect();
    // First path-ish / extension-ish arg.
    if let Some(t) = args.iter().find(|t| !is_flag(t) && is_path_ish(t)) {
        return Some((*t).to_string());
    }
    // Else first non-flag token.
    args.iter().find(|t| !is_flag(t)).map(|t| (*t).to_string())
}

/// A token is a flag when it starts with `-` (and isn't a lone `-`).
fn is_flag(token: &str) -> bool {
    token.len() > 1 && token.starts_with('-')
}

/// Path-ish / extension-ish: contains a `/`, or ends in `.<alnum+>`.
fn is_path_ish(token: &str) -> bool {
    if token.contains('/') {
        return true;
    }
    if let Some(dot) = token.rfind('.') {
        let ext = &token[dot + 1..];
        return !ext.is_empty() && ext.chars().all(|c| c.is_ascii_alphanumeric());
    }
    false
}

/// The set of flag tokens in a command (order-independent), used to decide
/// "different flag set" between two calls on the same target.
fn flag_set(command: &str) -> std::collections::BTreeSet<String> {
    command
        .split_whitespace()
        .skip(1)
        .filter(|t| is_flag(t))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(command: &str, exit_code: Option<i32>) -> BashHistoryEntry {
        BashHistoryEntry {
            command: command.to_string(),
            exit_code,
        }
    }

    // ---- filter_refinement_loop -------------------------------------------

    #[test]
    fn filter_refinement_fires_on_third_narrowing_step() {
        // Three calls, each appending one more `| grep -v …` to the prior.
        let recent = vec![
            entry("grep -r needle src", Some(0)),
            entry("grep -r needle src | grep -v test", Some(0)),
        ];
        let call = BashCallContext {
            command: "grep -r needle src | grep -v test | grep -v mock",
            exit_code: Some(0),
            stdout: "some output\n",
            stderr: "",
            recent: &recent,
        };
        let hint = first_hint(&call).expect("filter-refinement loop fires on the 3rd step");
        assert_eq!(hint.kind, "filter_refinement_loop");
        assert_eq!(hint.user_chip.severity, Severity::Warn);
    }

    #[test]
    fn filter_refinement_control_three_distinct_bases_does_not_fire() {
        // Three different base commands → not a refinement chain.
        let recent = vec![
            entry("ls src | grep -v test", Some(0)),
            entry("cat README | grep -v TODO", Some(0)),
        ];
        let call = BashCallContext {
            command: "find . | grep -v node_modules",
            exit_code: Some(0),
            stdout: "x\n",
            stderr: "",
            recent: &recent,
        };
        assert!(
            FilterRefinementLoop.check(&call).is_none(),
            "distinct base invocations must not fire the refinement rule"
        );
    }

    #[test]
    fn filter_refinement_needs_appended_exclusion_not_a_different_filter() {
        // Same base, but the 3rd call swaps the tail rather than appending a
        // new exclusion segment → not a strict-prefix extension → no fire.
        let recent = vec![
            entry("grep -r needle src", Some(0)),
            entry("grep -r needle src | grep -v test", Some(0)),
        ];
        let call = BashCallContext {
            command: "grep -r needle src | grep -v mock",
            exit_code: Some(0),
            stdout: "x\n",
            stderr: "",
            recent: &recent,
        };
        assert!(FilterRefinementLoop.check(&call).is_none());
    }

    #[test]
    fn filter_refinement_matches_awk_and_sed_and_rg_exclusions() {
        // Base + rg -v + awk '!/…/' is a valid two-step extension chain.
        let recent = vec![
            entry("rg foo .", Some(0)),
            entry("rg foo . | rg -v bar", Some(0)),
        ];
        let call = BashCallContext {
            command: "rg foo . | rg -v bar | awk '!/baz/'",
            exit_code: Some(0),
            stdout: "x\n",
            stderr: "",
            recent: &recent,
        };
        assert_eq!(
            FilterRefinementLoop.check(&call).map(|h| h.kind),
            Some("filter_refinement_loop")
        );
    }

    #[test]
    fn filter_refinement_needs_at_least_two_prior_calls() {
        let recent = vec![entry("grep -r needle src", Some(0))];
        let call = BashCallContext {
            command: "grep -r needle src | grep -v test",
            exit_code: Some(0),
            stdout: "x\n",
            stderr: "",
            recent: &recent,
        };
        assert!(FilterRefinementLoop.check(&call).is_none());
    }

    // ---- exit_zero_empty_thrash -------------------------------------------

    #[test]
    fn exit_zero_empty_thrash_fires_on_same_path_different_flags() {
        // Three exit-0 empty-stdout calls on the same path, different flags.
        let recent = vec![
            entry("git log src/main.rs", Some(0)),
            entry("git log --oneline src/main.rs", Some(0)),
        ];
        let call = BashCallContext {
            command: "git log -p src/main.rs",
            exit_code: Some(0),
            stdout: "   \n  ",
            stderr: "",
            recent: &recent,
        };
        let hint = first_hint(&call).expect("empty-thrash fires");
        assert_eq!(hint.kind, "exit_zero_empty_thrash");
        assert_eq!(hint.user_chip.severity, Severity::Info);
    }

    #[test]
    fn exit_zero_empty_thrash_control_same_flags_varying_nonpath_arg() {
        // Same flag set, the varying token is the non-path arg → the "different
        // flag set" condition is never met → no fire.
        let recent = vec![
            entry("grep -n alpha src/main.rs", Some(0)),
            entry("grep -n beta src/main.rs", Some(0)),
        ];
        let call = BashCallContext {
            command: "grep -n gamma src/main.rs",
            exit_code: Some(0),
            stdout: "",
            stderr: "",
            recent: &recent,
        };
        assert!(
            ExitZeroEmptyThrash.check(&call).is_none(),
            "identical flag sets must not fire the thrash rule"
        );
    }

    #[test]
    fn exit_zero_empty_thrash_control_nonempty_stdout_does_not_fire() {
        let recent = vec![
            entry("git log src/main.rs", Some(0)),
            entry("git log --oneline src/main.rs", Some(0)),
        ];
        let call = BashCallContext {
            command: "git log -p src/main.rs",
            exit_code: Some(0),
            stdout: "commit abc123\n",
            stderr: "",
            recent: &recent,
        };
        assert!(
            ExitZeroEmptyThrash.check(&call).is_none(),
            "non-empty stdout means the result is not empty — no thrash hint"
        );
    }

    #[test]
    fn exit_zero_empty_thrash_needs_two_prior_matches() {
        // Only one prior exit-0-empty call on the same target → below the
        // ≥2 threshold.
        let recent = vec![
            entry("git log --oneline src/main.rs", Some(0)),
            entry("ls -la other/path.txt", Some(0)),
        ];
        let call = BashCallContext {
            command: "git log -p src/main.rs",
            exit_code: Some(0),
            stdout: "",
            stderr: "",
            recent: &recent,
        };
        assert!(ExitZeroEmptyThrash.check(&call).is_none());
    }

    #[test]
    fn exit_zero_empty_thrash_nonzero_current_exit_does_not_fire() {
        let recent = vec![
            entry("git log src/main.rs", Some(0)),
            entry("git log --oneline src/main.rs", Some(0)),
        ];
        let call = BashCallContext {
            command: "git log -p src/main.rs",
            exit_code: Some(1),
            stdout: "",
            stderr: "",
            recent: &recent,
        };
        assert!(ExitZeroEmptyThrash.check(&call).is_none());
    }

    // ---- target / flag helpers --------------------------------------------

    #[test]
    fn same_target_prefers_path_ish_token() {
        assert_eq!(
            same_target_token("grep -n foo src/main.rs").as_deref(),
            Some("src/main.rs")
        );
        assert_eq!(
            same_target_token("cat -n config.toml").as_deref(),
            Some("config.toml")
        );
        // No path-ish token → first non-flag token.
        assert_eq!(
            same_target_token("git -C log status").as_deref(),
            Some("log")
        );
        // Only flags → None.
        assert_eq!(same_target_token("ls -la").as_deref(), None);
    }

    #[test]
    fn flag_set_distinguishes_flag_changes_only() {
        assert_ne!(flag_set("git log src/x"), flag_set("git log -p src/x"));
        assert_eq!(flag_set("git log -p a"), flag_set("git log -p b"));
    }

    // ---- registry / first-match-wins --------------------------------------

    #[test]
    fn registry_has_exactly_the_two_seeds_in_order() {
        let reg = registry();
        let ids: Vec<&str> = reg.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            vec!["filter_refinement_loop", "exit_zero_empty_thrash"]
        );
    }

    // ---- split_bash_body --------------------------------------------------

    #[test]
    fn split_bash_body_separates_streams_and_drops_exit() {
        let body = "stdout:\nhello\nworld\nstderr:\noops\nexit: 0\n";
        let (out, err) = split_bash_body(body);
        assert_eq!(out, "hello\nworld\n");
        assert_eq!(err, "oops\n");
    }

    #[test]
    fn split_bash_body_empty_stdout_when_no_block() {
        // The exit-0-no-output shape: no `stdout:` block, just the exit line
        // and the void annotation.
        let body =
            "exit: 0\n(no output — command succeeded and produced nothing; complete result)\n";
        let (out, err) = split_bash_body(body);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn no_match_returns_none() {
        let call = BashCallContext {
            command: "echo hello",
            exit_code: Some(0),
            stdout: "hello\n",
            stderr: "",
            recent: &[],
        };
        assert!(first_hint(&call).is_none());
    }

    // ---- failure_guard (verification guard) -------------------------------

    #[test]
    fn failure_guard_nonzero_exit_marker_at_top_and_nudge_at_tail() {
        // A failing command's wire body: the FIRST line is `FAILED (exit N)`,
        // the trailing `exit: N` line is still present, and the tail carries
        // the non-verification nudge.
        let body = "stdout:\nbuilding...\nstderr:\nerror[E0001]\nexit: 101\n";
        let out = apply_failure_guard(body.to_string(), Some(101));
        let first = out.lines().next().unwrap();
        assert_eq!(first, "FAILED (exit 101)", "marker must be the first line");
        assert!(out.contains("exit: 101\n"), "trailing exit line preserved");
        assert!(
            out.trim_end().ends_with("until a command for it exits 0."),
            "nudge at the tail, got: {out}"
        );
        assert!(out.contains("Do not report this step as verified"));
    }

    #[test]
    fn failure_guard_exit_zero_adds_nothing_even_with_stderr() {
        // Exit 0 (with non-empty stderr) is NOT a failure: byte-identical pass.
        let body = "stdout:\nok\nstderr:\nwarning: deprecated\nexit: 0\n";
        let out = apply_failure_guard(body.to_string(), Some(0));
        assert_eq!(out, body, "exit 0 must produce no marker and no nudge");
        assert!(!out.contains("FAILED"));
        assert!(failure_guard(Some(0)).is_none());
    }

    #[test]
    fn failure_guard_signaled_uses_signaled_form() {
        // A signaled run (no numeric code → `exit_code == None`) gets the
        // marker + nudge in the signaled form, with the `exit: signaled` line
        // preserved.
        let body = "stdout:\npartial\nexit: signaled\n";
        let out = apply_failure_guard(body.to_string(), None);
        assert_eq!(out.lines().next().unwrap(), "FAILED (signaled)");
        assert!(out.contains("exit: signaled\n"));
        assert!(out.contains("This command FAILED (signaled)."));
        assert!(out.trim_end().ends_with("until a command for it exits 0."));
    }

    #[test]
    fn failure_guard_coexists_with_bash_hint_line() {
        // A FAILING command that also trips a hint rule: assemble the wire body
        // exactly the way the dispatcher (`engine::agent`) does — failure guard
        // first, then the `--- hint(...)` line. Both must survive: the marker at
        // the head, the nudge in the body, and the hint line at the very tail,
        // neither clobbering the other.
        let body = "stdout:\nx\nexit: 2\n";
        let mut wire = apply_failure_guard(body.to_string(), Some(2));
        // Replicate the agent.rs hint append.
        if !wire.ends_with('\n') {
            wire.push('\n');
        }
        wire.push_str("\n--- hint(filter_refinement_loop): read the source directly.\n");

        // Marker at the head.
        assert_eq!(wire.lines().next().unwrap(), "FAILED (exit 2)");
        // Original body preserved.
        assert!(wire.contains("exit: 2\n"));
        // Nudge present (in the body, before the hint line).
        let nudge_pos = wire
            .find("Do not report this step as verified")
            .expect("nudge present");
        let hint_pos = wire.find("--- hint(").expect("hint line present");
        assert!(
            nudge_pos < hint_pos,
            "nudge must precede the hint line, neither clobbered"
        );
        // Hint line intact at the tail.
        assert!(
            wire.trim_end()
                .ends_with("--- hint(filter_refinement_loop): read the source directly.")
        );
    }
}
