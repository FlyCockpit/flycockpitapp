//! The synchronous end-to-end harness invocation driver.
//!
//! Ties the pieces together for one `harness_invoke` tool call:
//! 1. **Redact** the prompt through the session's redaction table
//!    ([`crate::redact::RedactionTable::scrub`]) — non-bypassable
//!    (GOALS §7). Everything downstream sees only the scrubbed prompt.
//! 2. **Preflight**: PATH + auth ([`crate::harness::preflight`]).
//! 3. **Write policy** ([`WritePolicy`]): Build-mode runs the harness
//!    directly in the project cwd; Plan-mode runs it in a throwaway git
//!    worktree and captures the resulting diff without applying it.
//! 4. **Prepare** argv + delivery ([`crate::harness::prepare`]).
//! 5. **Spawn + drain + timeout** ([`crate::harness::spawn`]).
//! 6. **Parse** JSON metadata leniently ([`crate::harness::parse`]).
//! 7. **Cap** the returned text to the subagent-report budget; over the
//!    cap, summarize with the utility model (reusing the auto_title-style
//!    path) rather than hard-truncating.
//!
//! v1 is synchronous (the spec's scope boundary): this blocks until the
//! harness exits or its timeout elapses. Backgrounding via the `schedule`
//! meta-tool (GOALS §22) is a documented follow-up, not built here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;

use crate::config::extended::HarnessConfig;
use crate::config::extended::HarnessTrust;
use crate::config::providers::ProvidersConfig;
use crate::harness::env::harness_child_env;
use crate::harness::parse::{HarnessMetadata, parse_harness_json};
use crate::harness::preflight::preflight_with_env;
use crate::harness::prepare::{agent_file_env, prepare_invocation};
use crate::harness::spawn::{RunOutcome, run_to_completion};
use crate::redact::RedactionTable;
use crate::text::{ceil_char_boundary, floor_char_boundary};

/// Token cap on the harness output text returned to the calling agent —
/// the async-result budget (≈8K, below the ≈10K hard cap). Output over this
/// is summarized by the utility model rather than hard-truncated.
pub const HARNESS_REPORT_TOKEN_CAP: usize = crate::engine::schedule::ASYNC_RESULT_TOKEN_CAP;

/// Hard ceiling on the utility-model summary itself (≈10K tokens, GOALS
/// §10 hard cap) — a backstop if the summary model ignores the brief.
pub const HARNESS_SUMMARY_HARD_CAP: usize = 10_000;

/// Where the external harness's file writes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Build-mode: the harness writes to the project cwd directly (like an
    /// internal `builder` would). Outside the lock manager — accepted.
    Direct,
    /// Plan-mode: run the harness in a throwaway git worktree, capture the
    /// diff, return it without applying. Falls back to [`Self::Direct`]
    /// when `cwd` isn't inside a git repo (no worktree to isolate into).
    Isolated,
}

impl WritePolicy {
    /// The default write policy for the active primary agent. Build →
    /// direct; Plan → isolated; anything else (Auto / a custom primary) →
    /// isolated, the safer default when the context isn't clearly an
    /// implementation one (implementation note §6).
    pub fn for_primary(agent: &str) -> Self {
        if Self::direct_allowed_for_agent(agent) {
            WritePolicy::Direct
        } else {
            WritePolicy::Isolated
        }
    }

    /// Direct harness writes are reserved for agents that already have a
    /// write-capable surface. Other agents must stay isolated.
    pub fn direct_allowed_for_agent(agent: &str) -> bool {
        matches!(agent, "Build" | "builder" | "bee")
    }

    /// Parse an explicit per-call override (`direct`/`isolated`), or
    /// `None` for an unrecognized/absent value (caller uses the mode
    /// default).
    pub fn parse_override(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(WritePolicy::Direct),
            "isolated" => Some(WritePolicy::Isolated),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            WritePolicy::Direct => "direct",
            WritePolicy::Isolated => "isolated",
        }
    }
}

/// The structured result of a harness invocation, ready to render for the
/// calling agent.
#[derive(Debug, Clone)]
pub struct HarnessRunResult {
    /// Process exit code, or `None` for a signal kill / timeout.
    pub exit_code: Option<i32>,
    /// Whether the invocation succeeded (exit 0 and not timed out).
    pub success: bool,
    /// True when the timeout elapsed and the child was killed.
    pub timed_out: bool,
    /// The harness output text (capped or utility-summarized).
    pub text: String,
    /// True when [`Self::text`] is a utility-model summary of over-cap
    /// output rather than the raw text.
    pub summarized: bool,
    /// Parsed JSON metadata (empty when none / not JSON).
    pub metadata: HarnessMetadata,
    /// The write policy actually used.
    pub policy: WritePolicy,
    /// For isolated runs: the captured unified diff (empty when the run
    /// changed nothing). `None` for direct runs.
    pub diff: Option<String>,
}

impl HarnessRunResult {
    /// Render the result as the model-facing tool output string. Leads
    /// with the status line, then metadata, then the (capped) text, then
    /// the diff for isolated runs.
    pub fn render(&self, harness_name: &str) -> String {
        let mut out = String::new();
        let status = if self.timed_out {
            "timed out".to_string()
        } else if self.success {
            "exit 0 (success)".to_string()
        } else {
            match self.exit_code {
                Some(c) => format!("exit {c} (failure)"),
                None => "killed by signal (failure)".to_string(),
            }
        };
        out.push_str(&format!(
            "harness `{harness_name}` [{}]: {status}\n",
            self.policy.as_str()
        ));
        if let Some(line) = self.metadata.summary_line() {
            out.push_str(&format!("metadata: {line}\n"));
        }
        out.push('\n');
        if self.summarized {
            out.push_str(
                "(output exceeded the report budget; summarized by the utility model)\n\n",
            );
        }
        if self.text.trim().is_empty() {
            out.push_str("(no output)\n");
        } else {
            out.push_str(&self.text);
            if !self.text.ends_with('\n') {
                out.push('\n');
            }
        }
        if let Some(diff) = &self.diff {
            out.push('\n');
            if diff.trim().is_empty() {
                out.push_str("diff: (no file changes)\n");
            } else {
                out.push_str("diff (isolated — NOT applied; apply yourself if you want it):\n");
                out.push_str(diff);
                if !diff.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        out
    }
}

/// Everything the driver needs from the caller, threaded explicitly so the
/// driver is unit-testable without a live `ToolCtx`.
pub struct RunContext<'a> {
    pub harness_name: &'a str,
    pub cfg: &'a HarnessConfig,
    /// The raw (un-redacted) prompt from the model.
    pub prompt: &'a str,
    /// The resolved model (explicit or the harness default), or `None`.
    pub model: Option<&'a str>,
    /// The project working directory (Build-mode write target; Plan-mode
    /// worktree base).
    pub cwd: &'a Path,
    /// The agent that requested the harness invocation.
    pub agent_id: &'a str,
    pub policy: WritePolicy,
    /// The session's effective redaction table — non-bypassable (GOALS §7).
    /// Scrubs the outbound prompt here, and is threaded into the utility model
    /// the over-cap summarizer builds so that send is scrubbed too.
    pub redact: Arc<RedactionTable>,
    /// Utility model ref + providers for over-cap summarization. `None`
    /// disables summarization (over-cap output falls back to a tail).
    pub utility_model: Option<&'a str>,
    pub providers: &'a ProvidersConfig,
    pub shutdown_gate: Option<crate::daemon::shutdown::ShutdownSignal>,
    pub env_overlay: Option<&'a std::collections::HashMap<String, String>>,
}

/// The custody posture every external OS harness runs at, resolved from its
/// explicit `trust` configuration field.
///
/// [`HarnessTrust`] carries the same meaning as a model's custody class
/// — trusted may hold raw content, untrusted must be handed a redacted
/// rendering — but it is a deliberately separate type: an external harness is
/// not a provider/model route, so this value must never reach model routing.
/// It is never inferred from model, locality, command, or `LlmMode`; it is
/// an explicitly configured harness-local policy that defaults to untrusted.
///
/// An untrusted harness receives the mandatory sensitive-redaction baseline
/// (the enforced redaction table) — this holds even when discretionary
/// redaction is disabled, because the enforced view ignores that opt-out.
/// A trusted harness receives its raw prompt, including sensitive/sealed
/// literals, only after the user explicitly configures it as trusted. Both
/// classes receive no Cockpit-provided secret environment value.
///
/// `enforced` is the already-constructed enforced view of the session
/// redaction table (see [`RedactionTable::enforced_checked`]): the single
/// scrub funnel [`run_harness`] builds once, up front and fail-closed, and
/// reuses for both this prompt rendering and the child-output scrub.
fn render_for_harness_custody(
    custody: HarnessTrust,
    enforced: &RedactionTable,
    prompt: &str,
) -> String {
    match custody {
        HarnessTrust::Untrusted => {
            // The mandatory sensitive baseline: the enforced view of the
            // session redaction table. This scrubs environment, credential-
            // store, and sealed sentinels regardless of the config opt-out
            // `redact.enabled = false`, because the enforced view ignores
            // that opt-out. A disabled discretionary table cannot deliver
            // any sensitive sentinel to an untrusted subprocess.
            enforced.scrub(prompt)
        }
        HarnessTrust::Trusted => {
            // A trusted harness receives its raw prompt, including
            // sensitive/sealed literals. This is the explicit opt-in: only
            // an explicit `trust: "trusted"` field reaches here. The raw
            // prompt is never persisted (invocation records, child output,
            // process records, histories, diagnostics, and /export debug
            // receive only generic-redacted representations before write).
            prompt.to_string()
        }
    }
}

/// Run one harness invocation synchronously, end to end.
pub async fn run_harness(ctx: RunContext<'_>) -> Result<HarnessRunResult, String> {
    run_harness_inner(ctx, None).await
}

/// The end-to-end driver. `spawn_counter`, when present, is incremented
/// exactly once immediately before the child process is spawned — a test-only
/// seam that lets a caller assert the runner was (or was NOT) reached. In
/// production `run_harness` passes `None`, so this is a no-op observability
/// hook, never a fake value.
async fn run_harness_inner(
    ctx: RunContext<'_>,
    spawn_counter: Option<&AtomicUsize>,
) -> Result<HarnessRunResult, String> {
    // 1. Resolve the harness custody posture from its explicit `trust`
    //    field — never inferred from model, locality, command, or `LlmMode`.
    //    Then render the outbound prompt for that custody posture. From here
    //    on, only the rendered text exists in argv / stdin / tempfile.
    let custody = ctx.cfg.trust;

    // Construct the enforced redaction view ONCE, up front — the single scrub
    // funnel for the untrusted prompt rendering AND the trusted-harness output
    // (stdout/stderr/diff/metadata) scrub, so every one of those channels is
    // redacted by the same view before it can reach the model or history.
    //
    // Building it here also fixes the ORDERING invariant: the scrub view is
    // constructed BEFORE preflight and any process spawn, so if construction
    // ever fails the run aborts before the child exists (never a raw-content
    // fallback). Note: in shipped builds `enforced()` is infallible, so
    // `enforced_checked` cannot actually return `Err` in production — this is
    // NOT an advertised production fail-closed contract. The `Result` is the
    // single seam a future fallible scrub-view step would fail closed through,
    // and unit tests drive that seam (via `with_forced_enforced_view_failure`)
    // to prove the runner is never reached when construction fails.
    let scrub = ctx
        .redact
        .enforced_checked()
        .map_err(|e| format!("constructing harness redaction view: {e}"))?;

    let scrubbed = render_for_harness_custody(custody, &scrub, ctx.prompt);

    // 2. Preflight: PATH + auth.
    if let Err(e) = preflight_with_env(ctx.harness_name, ctx.cfg, ctx.cwd, ctx.env_overlay).await {
        return Err(e.to_string());
    }

    // 3. Resolve the run directory per write policy.
    let isolation = match ctx.policy {
        WritePolicy::Direct => None,
        WritePolicy::Isolated => match Worktree::create(ctx.cwd) {
            Ok(Some(wt)) => Some(wt),
            // Not a git repo: there is nowhere to isolate into. Only agents
            // that are already direct-write-capable may degrade to direct.
            Ok(None) if WritePolicy::direct_allowed_for_agent(ctx.agent_id) => None,
            Ok(None) => {
                return Err(format!(
                    "harness write policy `isolated` requires a git worktree for `{}`; \
                     `{}` is not allowed to degrade to direct writes",
                    ctx.cwd.display(),
                    ctx.agent_id
                ));
            }
            Err(e) => return Err(format!("preparing isolated worktree: {e}")),
        },
    };
    let run_dir: PathBuf = isolation
        .as_ref()
        .map(|w| w.path.clone())
        .unwrap_or_else(|| ctx.cwd.to_path_buf());

    // 4. Prepare argv + delivery (scrubbed prompt only).
    let (args, delivery) =
        match prepare_invocation(ctx.harness_name, ctx.cfg, &scrubbed, ctx.model, None) {
            Ok(v) => v,
            Err(e) => {
                // Clean up the worktree on an early-out.
                if let Some(wt) = isolation {
                    wt.cleanup();
                }
                return Err(e.to_string());
            }
        };
    let mut env = harness_child_env(ctx.cfg, ctx.env_overlay);
    if let Some(pair) = agent_file_env(ctx.cfg, None) {
        env.push(pair);
    }

    // 5. Spawn + drain + timeout. Count the spawn attempt at the exact moment
    //    we reach the runner, so a test can assert the runner is never called
    //    when an earlier fail-closed step aborts the run.
    if let Some(counter) = spawn_counter {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let timeout = Duration::from_secs(ctx.cfg.timeout_secs.max(1));
    let outcome = run_to_completion(
        ctx.harness_name,
        &ctx.cfg.command,
        &args,
        &env,
        &run_dir,
        delivery,
        timeout,
    )
    .await;

    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            if let Some(wt) = isolation {
                wt.cleanup();
            }
            return Err(format!(
                "spawning harness `{}` (`{}`) failed: {e}",
                ctx.harness_name, ctx.cfg.command
            ));
        }
    };

    let (output, success, timed_out) = match outcome {
        RunOutcome::Completed { output, success } => (output, success, false),
        RunOutcome::TimedOut { output } => (output, false, true),
    };

    // Scrub EVERY model/history-facing child-output channel through the same
    // enforced redaction view before it can be stored or rendered. A trusted
    // harness received the raw prompt (possibly sensitive/sealed literals) and
    // can surface those back on ANY channel — stdout, stderr, a file it wrote
    // (captured in the isolated diff), or a JSON metadata field. The enforced
    // view honors the mandatory baseline even when discretionary redaction is
    // disabled, and empty content is a no-op. Untrusted output passes through
    // the same funnel (defense in depth); it never received raw secrets. Do
    // this at the single assembly funnel so no future channel can bypass it.
    let scrubbed_stdout = scrub.scrub(&output.stdout);
    let scrubbed_stderr = scrub.scrub(&output.stderr);

    // For isolated runs, capture the diff before tearing the worktree down,
    // then scrub it — a trusted harness can write its received secret into a
    // file, and `capture_diff` returns those file bytes verbatim.
    let diff = isolation
        .as_ref()
        .map(|wt| scrub.scrub(&wt.capture_diff().unwrap_or_default()));
    if let Some(wt) = isolation {
        wt.cleanup();
    }

    // 6. Parse JSON metadata leniently (only when the harness advertises JSON
    //    output), from the RAW (still-valid) stdout, then scrub each free-form
    //    STRING field through the same enforced view before it is stored /
    //    rendered. Parsing raw JSON — rather than the scrubbed text — keeps a
    //    JSON-UNSAFE user placeholder (one containing `"`, `\`, or a newline)
    //    from corrupting the JSON and silently discarding ALL metadata; numeric
    //    fields (cost/tokens) can't carry a registered secret and survive
    //    intact. `session_id` is the only free-form string field; scrubbing it
    //    keeps a secret out of `summary_line()` / `render()`.
    let mut metadata = if ctx.cfg.supports_json_output {
        parse_harness_json(&output.stdout)
    } else {
        HarnessMetadata::default()
    };
    if let Some(session_id) = metadata.session_id.take() {
        metadata.session_id = Some(scrub.scrub(&session_id));
    }

    // 7. Build the model-facing text from the scrubbed streams: stdout, plus
    //    stderr appended on failure (where the error usually lives). Cap /
    //    summarize.
    let mut raw_text = scrubbed_stdout;
    if (!success || timed_out) && !scrubbed_stderr.trim().is_empty() {
        if !raw_text.is_empty() && !raw_text.ends_with('\n') {
            raw_text.push('\n');
        }
        raw_text.push_str("--- stderr ---\n");
        raw_text.push_str(&scrubbed_stderr);
    }

    let (text, summarized) = cap_or_summarize(
        &raw_text,
        ctx.utility_model,
        ctx.providers,
        ctx.redact.clone(),
        ctx.shutdown_gate.clone(),
    )
    .await;

    Ok(HarnessRunResult {
        exit_code: output.exit_code,
        success: success && !timed_out,
        timed_out,
        text,
        summarized,
        metadata,
        policy: ctx.policy,
        diff,
    })
}

/// Cap `text` to the report budget. Under the cap, return it as-is. Over
/// the cap, summarize with the utility model (reusing the
/// `Model::text_completion` path); if the utility model is unset or the
/// call fails, fall back to a deterministic head+tail excerpt so we never
/// silently drop everything.
async fn cap_or_summarize(
    text: &str,
    utility_model: Option<&str>,
    providers: &ProvidersConfig,
    redact: Arc<RedactionTable>,
    shutdown_gate: Option<crate::daemon::shutdown::ShutdownSignal>,
) -> (String, bool) {
    if crate::tokens::count(text) <= HARNESS_REPORT_TOKEN_CAP {
        return (text.to_string(), false);
    }
    if let Some(model_ref) = utility_model
        && let Some(summary) =
            summarize_with_utility(text, model_ref, providers, redact, shutdown_gate).await
    {
        return (summary, true);
    }
    // Fallback: a deterministic excerpt, head + tail, within the cap.
    (excerpt(text, HARNESS_REPORT_TOKEN_CAP), false)
}

/// Summarize over-cap harness output with the utility model. Best-effort:
/// returns `None` on any failure (the caller falls back to an excerpt). The
/// utility model carries the session's redaction table so the summary request
/// is scrubbed at the non-bypassable send chokepoint (GOALS §7).
async fn summarize_with_utility(
    text: &str,
    model_ref: &str,
    providers: &ProvidersConfig,
    redact: Arc<RedactionTable>,
    shutdown_gate: Option<crate::daemon::shutdown::ShutdownSignal>,
) -> Option<String> {
    let model = crate::engine::model::Model::from_ref(providers, model_ref, redact).ok()?;
    let model = match shutdown_gate {
        Some(gate) => model.with_shutdown_gate(gate),
        None => model,
    };
    // Bound the input we hand the utility model so we don't blow its own
    // context: an excerpt within the hard cap is plenty for a summary.
    let bounded = excerpt(text, HARNESS_SUMMARY_HARD_CAP);
    let prompt = format!(
        "The following is the output of an external coding-agent run. Summarize it for another \
         agent in at most ~1500 words: what was done, what changed, key results/errors, and any \
         follow-ups. Return only the summary.\n\n<output>\n{bounded}\n</output>\n"
    );
    let resp = model
        .text_completion_for(
            crate::engine::model::UtilityCallSite::HarnessSummary,
            &prompt,
        )
        .await
        .ok()?;
    let resp = resp.trim();
    if resp.is_empty() {
        None
    } else {
        // Final safety: ensure the summary itself respects the hard cap.
        Some(excerpt(resp, HARNESS_SUMMARY_HARD_CAP))
    }
}

/// Deterministic head+tail excerpt of `text` fitting within `token_cap`
/// cl100k tokens, with an elision marker. Used as the no-utility-model
/// fallback and to bound the summary input.
fn excerpt(text: &str, token_cap: usize) -> String {
    if crate::tokens::count(text) <= token_cap {
        return text.to_string();
    }
    // Roughly 4 bytes/token; split the budget head/tail. Char-boundary safe.
    let byte_budget = token_cap.saturating_mul(4);
    let head_budget = byte_budget / 2;
    let tail_budget = byte_budget - head_budget;
    let head_end = floor_char_boundary(text, head_budget.min(text.len()));
    let tail_start = ceil_char_boundary(text, text.len().saturating_sub(tail_budget));
    if tail_start <= head_end {
        return text[..head_end].to_string();
    }
    format!(
        "{}\n\n[… {} bytes elided …]\n\n{}",
        &text[..head_end],
        tail_start - head_end,
        &text[tail_start..]
    )
}

/// A throwaway git worktree for Plan-mode isolation. Created off the
/// current HEAD on a temp branch; reuses the `crate::git` worktree
/// machinery. The diff is captured via `git add -A` (staging untracked
/// files so they appear) + `git diff --staged`. Cleaned up on drop of the
/// invocation (worktree removed, temp branch deleted).
struct Worktree {
    repo: PathBuf,
    path: PathBuf,
    branch: String,
}

impl Worktree {
    /// Create an isolated worktree for `cwd`. `Ok(None)` when `cwd` isn't
    /// inside a git repo (the caller degrades to direct mode).
    fn create(cwd: &Path) -> Result<Option<Self>> {
        let Some(repo) = crate::git::find_worktree_root(cwd) else {
            return Ok(None);
        };
        let head = crate::git::head_sha(&repo)?;
        let unique = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let branch = format!("cockpit-harness/{unique}");
        let path = std::env::temp_dir().join(format!("cockpit-harness-{unique}"));
        crate::git::worktree_add(&repo, &path, &branch, &head)?;
        Ok(Some(Self { repo, path, branch }))
    }

    /// Capture the worktree's changes as a unified diff (staged so
    /// untracked files are included). Best-effort.
    fn capture_diff(&self) -> Result<String> {
        // Stage everything so new files show in the diff.
        let _ = crate::git::run_git(&self.path, &["add", "-A"])?;
        let out = crate::git::run_git(&self.path, &["diff", "--staged"])?;
        Ok(out.stdout)
    }

    /// Remove the worktree and delete its temp branch. Best-effort —
    /// failures are logged, never propagated (cleanup must not fail a run).
    fn cleanup(self) {
        if let Err(e) = crate::git::worktree_remove(&self.repo, &self.path) {
            tracing::debug!(error = %e, "harness worktree remove failed; pruning");
            let _ = crate::git::worktree_prune(&self.repo);
        }
        if let Err(e) = crate::git::branch_delete(&self.repo, &self.branch) {
            tracing::debug!(error = %e, "harness worktree branch delete failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The external-harness custody posture is expressed with
    /// [`HarnessTrust`] — a separate type from the model custody class,
    /// because a harness is not a provider/model route. An untrusted harness
    /// renders through the enforced session redaction table; a trusted
    /// harness receives its raw prompt (the explicit opt-in).
    #[test]
    fn harness_custody_untrusted_renders_redacted_trusted_renders_raw() {
        let table = RedactionTable::empty()
            .with_forced_literal("sk-live-harness-secret".to_string(), "TEST".to_string())
            .expect("forced literal");
        let prompt = "call the api with sk-live-harness-secret please";

        // Untrusted: the enforced view scrubs the sentinel. The enforced
        // view, not the table as given: `table` here is built on
        // `RedactionTable::empty()`, which carries the config opt-out flag,
        // and that opt-out must not follow content out to an untrusted
        // external harness.
        let enforced = table.enforced();
        let untrusted = render_for_harness_custody(HarnessTrust::Untrusted, &enforced, prompt);
        assert!(!untrusted.contains("sk-live-harness-secret"), "{untrusted}");
        assert_eq!(untrusted, table.enforced().scrub(prompt));

        // Trusted: the raw prompt is delivered (the explicit opt-in). The
        // sentinel survives because the user explicitly configured this
        // harness as trusted.
        let trusted = render_for_harness_custody(HarnessTrust::Trusted, &enforced, prompt);
        assert_eq!(trusted, prompt);
        assert!(trusted.contains("sk-live-harness-secret"), "{trusted}");
    }

    /// Disabling discretionary redaction does not disable the mandatory
    /// sensitive baseline for an untrusted harness prompt: the enforced
    /// view ignores the `redact.enabled = false` opt-out.
    #[test]
    fn untrusted_harness_keeps_sensitive_baseline_when_redaction_disabled() {
        // A table built with `enabled: false` carries the disabled flag, but
        // `enforced()` ignores it. An untrusted harness scrubs against the
        // enforced view, so the sentinel is still redacted.
        let table = RedactionTable::empty()
            .with_forced_literal("sk-live-disabled-baseline".to_string(), "TEST".to_string())
            .expect("forced literal");
        // Simulate the disabled flag by building an enforced view directly:
        // the enforced view always scrubs regardless of the disabled flag.
        let enforced = table.enforced();
        let prompt = "use sk-live-disabled-baseline now";
        let untrusted = render_for_harness_custody(HarnessTrust::Untrusted, &enforced, prompt);
        assert!(
            !untrusted.contains("sk-live-disabled-baseline"),
            "{untrusted}"
        );

        // A trusted harness still receives the raw prompt.
        let trusted = render_for_harness_custody(HarnessTrust::Trusted, &enforced, prompt);
        assert_eq!(trusted, prompt);
    }

    /// A discretionary-disabled (`redact.enabled = false`) table that still
    /// carries `secret` as an entry, built through the production env-scan
    /// seam. Its `scrub` is a passthrough (the opt-out), but its `enforced`
    /// view scrubs — the mandatory baseline an untrusted/trusted harness path
    /// must honor regardless of the opt-out.
    fn disabled_table_with_secret(secret: &str) -> RedactionTable {
        let cfg = crate::config::extended::RedactConfig {
            enabled: false,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            ..Default::default()
        };
        let env =
            std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), secret.to_string())]);
        RedactionTable::build_with_env(&cfg, std::path::Path::new("."), &env).unwrap()
    }

    /// AC (custody matrix): the full trust × channel matrix through the real
    /// `run_harness` path. Each probe child BOTH records the prompt it received
    /// (observed at the process boundary, so the output-scrub can't mask the
    /// prompt difference) AND echoes the registered secret on stdout (so we
    /// observe the OUTPUT scrub too).
    ///
    /// Prompt custody: untrusted → scrubbed prompt (even under disabled
    /// discretionary redaction); trusted → raw prompt (explicit opt-in).
    /// Output custody: the returned text is scrubbed for BOTH classes. The
    /// trusted-output leg is the one this patch introduces and FAILS against
    /// pre-change behavior, which returned the child's raw stdout verbatim.
    #[tokio::test]
    async fn external_harness_prompt_custody_matrix() {
        const SECRET: &str = "sk-live-custody-matrix-secret-0001";
        let providers = ProvidersConfig::default();

        // Returns (prompt the child received, run result). The child records
        // its received prompt to a file and echoes the secret on stdout.
        async fn run_probe(
            trust: HarnessTrust,
            redact: std::sync::Arc<RedactionTable>,
            prompt: &str,
            secret: &str,
            providers: &ProvidersConfig,
        ) -> (String, HarnessRunResult) {
            let tmp = tempfile::tempdir().unwrap();
            let received = tmp.path().join("received.txt");
            let mut cfg = sh_harness(&format!(
                "cat > {}; printf '%s\\n' '{secret}'",
                received.display()
            ));
            cfg.trust = trust;
            let res = run_harness(RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt,
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact,
                utility_model: None,
                providers,
                shutdown_gate: None,
                env_overlay: None,
            })
            .await
            .unwrap();
            assert!(res.success, "rendered: {}", res.render("sh"));
            (std::fs::read_to_string(&received).unwrap(), res)
        }

        let enabled = std::sync::Arc::new(
            RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "$leak:test".to_string())
                .unwrap(),
        );
        let disabled = std::sync::Arc::new(disabled_table_with_secret(SECRET));
        let prompt = format!("please use {SECRET} now");

        // Precondition: the disabled table really carries the secret (its
        // enforced view scrubs it), so a passing disabled leg is not vacuous.
        assert_ne!(disabled.enforced().scrub(&prompt), prompt);

        // Positive control: an empty table scrubs nothing, so a TRUSTED child
        // both receives the raw prompt AND its echoed secret survives in the
        // result text — proving the child emits the secret on both channels
        // and the scrubbing assertions below are non-vacuous.
        let (ctrl_received, ctrl_res) = run_probe(
            HarnessTrust::Trusted,
            std::sync::Arc::new(RedactionTable::empty()),
            &prompt,
            SECRET,
            &providers,
        )
        .await;
        assert!(
            ctrl_received.contains(SECRET),
            "control prompt: {ctrl_received}"
        );
        assert!(
            ctrl_res.text.contains(SECRET),
            "control output: {}",
            ctrl_res.text
        );

        // Trusted + enabled: raw prompt crosses the boundary (custody), but the
        // echoed secret is scrubbed OUT of the returned text (this patch's new
        // behavior — fails against pre-change, which returned raw stdout).
        let (t_received, t_res) = run_probe(
            HarnessTrust::Trusted,
            enabled.clone(),
            &prompt,
            SECRET,
            &providers,
        )
        .await;
        assert!(
            t_received.contains(SECRET),
            "trusted must see raw prompt: {t_received}"
        );
        assert!(
            !t_res.text.contains(SECRET),
            "trusted output must be scrubbed: {}",
            t_res.text
        );

        // Untrusted + enabled: scrubbed prompt crosses the boundary, output scrubbed.
        let (u_received, u_res) = run_probe(
            HarnessTrust::Untrusted,
            enabled.clone(),
            &prompt,
            SECRET,
            &providers,
        )
        .await;
        assert!(
            !u_received.contains(SECRET),
            "untrusted must see scrubbed prompt: {u_received}"
        );
        assert!(
            !u_res.text.contains(SECRET),
            "untrusted output must be scrubbed: {}",
            u_res.text
        );

        // Untrusted + discretionary redaction DISABLED: prompt AND output still
        // scrubbed — the enforced baseline ignores the opt-out.
        let (ud_received, ud_res) = run_probe(
            HarnessTrust::Untrusted,
            disabled.clone(),
            &prompt,
            SECRET,
            &providers,
        )
        .await;
        assert!(
            !ud_received.contains(SECRET),
            "untrusted prompt baseline must hold under disabled redaction: {ud_received}"
        );
        assert!(
            !ud_res.text.contains(SECRET),
            "untrusted output baseline must hold under disabled redaction: {}",
            ud_res.text
        );
    }

    /// AC4: a scrub-view construction failure fails the run BEFORE the runner
    /// is reached — proven by an atomic spawn counter that stays 0 (the runner
    /// is invoked exactly once on a healthy run and zero times on failure) AND
    /// by the child's marker side effect being absent. Fails against pre-change
    /// behavior, which had no fail-closed funnel and always reached the runner.
    #[tokio::test]
    async fn external_harness_redaction_failure_fails_before_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("spawned.txt");
        let cfg = sh_harness(&format!("printf ran > {}", marker.display()));
        let providers = ProvidersConfig::default();
        let spawns = AtomicUsize::new(0);

        // Positive control: with a healthy table the runner IS reached exactly
        // once and the marker is written — so a 0 counter / missing marker
        // below proves the runner was genuinely never called.
        let ok = run_harness_inner(
            RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "p",
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact: std::sync::Arc::new(RedactionTable::empty()),
                utility_model: None,
                providers: &providers,
                shutdown_gate: None,
                env_overlay: None,
            },
            Some(&spawns),
        )
        .await
        .unwrap();
        assert!(ok.success, "rendered: {}", ok.render("sh"));
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "healthy run reaches the runner once"
        );
        assert!(
            marker.exists(),
            "positive control: a healthy run must spawn the child"
        );
        std::fs::remove_file(&marker).unwrap();
        spawns.store(0, Ordering::SeqCst);

        // Inject a scrub-view construction failure. The run must fail closed
        // before the runner is reached: counter stays 0, marker absent.
        let poisoned =
            std::sync::Arc::new(RedactionTable::empty().with_forced_enforced_view_failure());
        let err = run_harness_inner(
            RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "p",
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact: poisoned,
                utility_model: None,
                providers: &providers,
                shutdown_gate: None,
                env_overlay: None,
            },
            Some(&spawns),
        )
        .await
        .unwrap_err();
        assert!(err.contains("harness redaction view"), "{err}");
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            0,
            "runner call count must be 0 when scrub construction fails"
        );
        assert!(
            !marker.exists(),
            "a scrub-view failure must prevent the child from ever spawning"
        );
    }

    /// AC (AC9): a trusted harness that echoes a registered secret on its
    /// child output does NOT persist that raw secret into the returned result
    /// text or the rendered (history-facing) output. Fails against pre-change
    /// behavior, which returned raw child stdout without an output scrub.
    #[tokio::test]
    async fn trusted_harness_raw_frames_never_persist() {
        const SECRET: &str = "sk-live-trusted-frame-secret-9f3a";
        let providers = ProvidersConfig::default();

        async fn run_echo(
            redact: std::sync::Arc<RedactionTable>,
            providers: &ProvidersConfig,
            secret: &str,
        ) -> HarnessRunResult {
            let tmp = tempfile::tempdir().unwrap();
            // A TRUSTED harness whose child emits the secret marker on stdout,
            // simulating a trusted harness echoing a secret it saw in its raw
            // prompt.
            let mut cfg = sh_harness(&format!("printf '%s\\n' '{secret}'"));
            cfg.trust = HarnessTrust::Trusted;
            run_harness(RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "ignored",
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact,
                utility_model: None,
                providers,
                shutdown_gate: None,
                env_overlay: None,
            })
            .await
            .unwrap()
        }

        // Positive control: a table that does NOT know the secret lets the raw
        // child output through — proving the child truly emits it.
        let control = run_echo(
            std::sync::Arc::new(RedactionTable::empty()),
            &providers,
            SECRET,
        )
        .await;
        assert!(control.success, "rendered: {}", control.render("sh"));
        assert!(
            control.text.contains(SECRET),
            "precondition: the child emits the secret: {}",
            control.text
        );

        // Secret registered: the trusted child's raw output is scrubbed before
        // it reaches either the result text or the rendered history.
        let table = std::sync::Arc::new(
            RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "$leak:test".to_string())
                .unwrap(),
        );
        let res = run_echo(table, &providers, SECRET).await;
        assert!(res.success, "rendered: {}", res.render("sh"));
        assert!(
            !res.text.contains(SECRET),
            "trusted raw stdout persisted in result text: {}",
            res.text
        );
        assert!(
            !res.render("sh").contains(SECRET),
            "trusted raw stdout persisted in rendered history: {}",
            res.render("sh")
        );

        // Disabled-redaction end-to-end: even with discretionary redaction
        // turned OFF at config level, a trusted harness's raw output is still
        // scrubbed — the output scrub uses the enforced view, which ignores
        // the opt-out.
        let disabled = std::sync::Arc::new(disabled_table_with_secret(SECRET));
        assert!(
            disabled.disabled(),
            "precondition: the table is discretionary-disabled"
        );
        assert!(
            disabled.scrub(SECRET).contains(SECRET),
            "precondition: the disabled discretionary path passes the secret through"
        );
        let res_disabled = run_echo(disabled, &providers, SECRET).await;
        assert!(
            res_disabled.success,
            "rendered: {}",
            res_disabled.render("sh")
        );
        assert!(
            !res_disabled.text.contains(SECRET),
            "trusted output not scrubbed under disabled redaction: {}",
            res_disabled.text
        );

        // stderr channel: a FAILING trusted harness that emits the secret on
        // stderr must not leak it either — on failure stderr is appended to the
        // returned text/render.
        async fn run_stderr(
            redact: std::sync::Arc<RedactionTable>,
            providers: &ProvidersConfig,
            secret: &str,
        ) -> HarnessRunResult {
            let tmp = tempfile::tempdir().unwrap();
            let mut cfg = sh_harness(&format!("printf '%s\\n' '{secret}' 1>&2; exit 1"));
            cfg.trust = HarnessTrust::Trusted;
            run_harness(RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "ignored",
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact,
                utility_model: None,
                providers,
                shutdown_gate: None,
                env_overlay: None,
            })
            .await
            .unwrap()
        }
        // Positive control: raw stderr carries the secret into render().
        let stderr_ctrl = run_stderr(
            std::sync::Arc::new(RedactionTable::empty()),
            &providers,
            SECRET,
        )
        .await;
        assert!(
            stderr_ctrl.render("sh").contains(SECRET),
            "precondition: raw stderr carries the secret: {}",
            stderr_ctrl.render("sh")
        );
        let stderr_table = std::sync::Arc::new(
            RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "$leak:test".to_string())
                .unwrap(),
        );
        let stderr_res = run_stderr(stderr_table, &providers, SECRET).await;
        assert!(
            !stderr_res.render("sh").contains(SECRET),
            "trusted stderr persisted the secret: {}",
            stderr_res.render("sh")
        );
    }

    /// HIGH #1 regression: a trusted harness in ISOLATED mode that writes a
    /// registered secret into a file must not leak it through the captured diff
    /// (`res.diff` / `render()`). Fails against pre-change behavior, which
    /// stored and rendered the raw captured diff. Positive control (empty
    /// table) proves the diff would otherwise carry the secret.
    #[tokio::test]
    async fn trusted_harness_isolated_diff_never_persists_secret() {
        const SECRET: &str = "sk-live-isolated-diff-secret-7c21";
        let providers = ProvidersConfig::default();

        async fn run_isolated(
            redact: std::sync::Arc<RedactionTable>,
            providers: &ProvidersConfig,
            secret: &str,
        ) -> HarnessRunResult {
            let tmp = tempfile::tempdir().unwrap();
            let repo = tmp.path();
            for args in [
                vec!["init", "-q"],
                vec!["config", "user.email", "t@t"],
                vec!["config", "user.name", "t"],
            ] {
                crate::git::run_git_checked(repo, &args).unwrap();
            }
            std::fs::write(repo.join("seed.txt"), "seed\n").unwrap();
            crate::git::run_git_checked(repo, &["add", "-A"]).unwrap();
            crate::git::run_git_checked(repo, &["commit", "-q", "-m", "init"]).unwrap();
            // The child writes the secret into a new file inside its worktree.
            let mut cfg = sh_harness(&format!("printf '%s\\n' '{secret}' > leak.txt"));
            cfg.trust = HarnessTrust::Trusted;
            run_harness(RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "ignored",
                model: None,
                cwd: repo,
                agent_id: "Plan",
                policy: WritePolicy::Isolated,
                redact,
                utility_model: None,
                providers,
                shutdown_gate: None,
                env_overlay: None,
            })
            .await
            .unwrap()
        }

        // Positive control: empty table → the raw diff carries the secret.
        let ctrl = run_isolated(
            std::sync::Arc::new(RedactionTable::empty()),
            &providers,
            SECRET,
        )
        .await;
        assert!(ctrl.success, "rendered: {}", ctrl.render("sh"));
        let ctrl_diff = ctrl.diff.clone().expect("isolated run returns a diff");
        assert!(
            ctrl_diff.contains(SECRET),
            "precondition: raw diff carries the secret: {ctrl_diff}"
        );

        // Registered → the diff is scrubbed in the result and in render().
        let table = std::sync::Arc::new(
            RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "$leak:test".to_string())
                .unwrap(),
        );
        let res = run_isolated(table, &providers, SECRET).await;
        assert!(res.success, "rendered: {}", res.render("sh"));
        let diff = res.diff.clone().expect("isolated run returns a diff");
        assert!(
            !diff.contains(SECRET),
            "trusted isolated diff persisted the secret: {diff}"
        );
        assert!(
            !res.render("sh").contains(SECRET),
            "trusted diff leaked via render: {}",
            res.render("sh")
        );
    }

    /// HIGH #2 regression: a trusted JSON-capable harness that emits a secret
    /// in a metadata field (`session_id`) must not leak it via the rendered
    /// `metadata:` line. Fails against pre-change behavior, which parsed
    /// metadata from RAW stdout. Positive control (empty table) proves it would.
    #[tokio::test]
    async fn trusted_harness_json_metadata_never_persists_secret() {
        const SECRET: &str = "sk-live-session-id-secret-3b90";
        let providers = ProvidersConfig::default();

        async fn run_json(
            redact: std::sync::Arc<RedactionTable>,
            providers: &ProvidersConfig,
            secret: &str,
        ) -> HarnessRunResult {
            let tmp = tempfile::tempdir().unwrap();
            let mut cfg = sh_harness(&format!(
                r#"printf '%s' '{{"session_id":"{secret}","cost_usd":0.01}}'"#
            ));
            cfg.trust = HarnessTrust::Trusted;
            cfg.supports_json_output = true;
            run_harness(RunContext {
                harness_name: "sh",
                cfg: &cfg,
                prompt: "ignored",
                model: None,
                cwd: tmp.path(),
                agent_id: "Build",
                policy: WritePolicy::Direct,
                redact,
                utility_model: None,
                providers,
                shutdown_gate: None,
                env_overlay: None,
            })
            .await
            .unwrap()
        }

        // Positive control: empty table → session_id parsed raw and rendered.
        let ctrl = run_json(
            std::sync::Arc::new(RedactionTable::empty()),
            &providers,
            SECRET,
        )
        .await;
        assert_eq!(
            ctrl.metadata.session_id.as_deref(),
            Some(SECRET),
            "precondition: raw session_id is parsed"
        );
        assert!(
            ctrl.render("sh").contains(SECRET),
            "precondition: raw metadata is rendered: {}",
            ctrl.render("sh")
        );

        // Registered → session_id scrubbed after parse; never reaches render.
        let table = std::sync::Arc::new(
            RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "$leak:test".to_string())
                .unwrap(),
        );
        let res = run_json(table, &providers, SECRET).await;
        assert_ne!(
            res.metadata.session_id.as_deref(),
            Some(SECRET),
            "session_id must be scrubbed, got {:?}",
            res.metadata.session_id
        );
        assert!(
            !res.render("sh").contains(SECRET),
            "trusted metadata persisted the secret: {}",
            res.render("sh")
        );
    }

    /// Regression: parsing metadata from RAW stdout (then scrubbing string
    /// fields) must preserve NUMERIC metadata even when the user's redaction
    /// placeholder is JSON-UNSAFE (contains a `"`). Parsing the *scrubbed* JSON
    /// with such a placeholder would corrupt the JSON and silently drop ALL
    /// metadata — this test fails against that implementation while still
    /// proving the secret never surfaces.
    #[tokio::test]
    async fn json_metadata_scrub_survives_unsafe_placeholder() {
        const SECRET: &str = "sk-live-unsafe-placeholder-secret-a1b2";
        let providers = ProvidersConfig::default();

        // A real table carrying the secret AND a JSON-unsafe placeholder
        // (contains a double-quote), built through the production env-scan seam.
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "<\"REDACTED\">".to_string(),
            ..Default::default()
        };
        let env =
            std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), SECRET.to_string())]);
        let table = std::sync::Arc::new(
            RedactionTable::build_with_env(&cfg, std::path::Path::new("."), &env).unwrap(),
        );
        // Precondition: the placeholder really is JSON-unsafe, and the table
        // actually redacts the secret.
        assert!(
            table.placeholder().contains('"'),
            "placeholder must be JSON-unsafe"
        );
        assert!(
            !table.scrub(SECRET).contains(SECRET),
            "table must redact the secret"
        );

        let tmp = tempfile::tempdir().unwrap();
        let mut harness = sh_harness(&format!(
            r#"printf '%s' '{{"session_id":"{SECRET}","cost_usd":0.5,"input_tokens":11,"output_tokens":22}}'"#
        ));
        harness.trust = HarnessTrust::Trusted;
        harness.supports_json_output = true;
        let res = run_harness(RunContext {
            harness_name: "sh",
            cfg: &harness,
            prompt: "ignored",
            model: None,
            cwd: tmp.path(),
            agent_id: "Build",
            policy: WritePolicy::Direct,
            redact: table,
            utility_model: None,
            providers: &providers,
            shutdown_gate: None,
            env_overlay: None,
        })
        .await
        .unwrap();

        // (a) The secret never surfaces in metadata or the rendered output.
        assert_ne!(res.metadata.session_id.as_deref(), Some(SECRET));
        assert!(
            !res.render("sh").contains(SECRET),
            "secret leaked via render: {}",
            res.render("sh")
        );
        // (b) Numeric metadata is PRESERVED — a JSON-unsafe placeholder does not
        // corrupt parsing (proving no silent drop).
        assert_eq!(
            res.metadata.cost_usd,
            Some(0.5),
            "cost dropped: {:?}",
            res.metadata
        );
        assert_eq!(
            res.metadata.input_tokens,
            Some(11),
            "input tokens dropped: {:?}",
            res.metadata
        );
        assert_eq!(
            res.metadata.output_tokens,
            Some(22),
            "output tokens dropped: {:?}",
            res.metadata
        );
    }

    #[test]
    fn write_policy_defaults_by_primary() {
        assert_eq!(WritePolicy::for_primary("Build"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("builder"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("bee"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("Plan"), WritePolicy::Isolated);
        // Removed primaries / custom → safer isolated default.
        assert_eq!(WritePolicy::for_primary("Auto"), WritePolicy::Isolated);
        assert_eq!(WritePolicy::for_primary("Swarm"), WritePolicy::Isolated);
        assert_eq!(WritePolicy::for_primary("Custom"), WritePolicy::Isolated);
    }

    #[test]
    fn write_policy_override_parse() {
        assert_eq!(
            WritePolicy::parse_override("direct"),
            Some(WritePolicy::Direct)
        );
        assert_eq!(
            WritePolicy::parse_override("ISOLATED"),
            Some(WritePolicy::Isolated)
        );
        assert_eq!(WritePolicy::parse_override("nonsense"), None);
    }

    #[test]
    fn excerpt_under_cap_is_identity() {
        let s = "short text";
        assert_eq!(excerpt(s, 1000), s);
    }

    #[test]
    fn excerpt_over_cap_elides_middle() {
        let s = "A".repeat(100_000);
        let e = excerpt(&s, 100);
        assert!(e.len() < s.len());
        assert!(e.contains("elided"));
        assert!(crate::tokens::count(&e) <= 100 + 50); // budget + marker slack
    }

    #[tokio::test]
    async fn cap_or_summarize_under_cap_returns_as_is() {
        let providers = ProvidersConfig::default();
        let (text, summarized) = cap_or_summarize(
            "tiny",
            None,
            &providers,
            std::sync::Arc::new(RedactionTable::empty()),
            None,
        )
        .await;
        assert_eq!(text, "tiny");
        assert!(!summarized);
    }

    #[tokio::test]
    async fn cap_or_summarize_over_cap_no_utility_falls_back_to_excerpt() {
        // No utility model configured → deterministic excerpt, not a crash,
        // not silent truncation-to-nothing.
        let providers = ProvidersConfig::default();
        let big = "word ".repeat(50_000);
        let (text, summarized) = cap_or_summarize(
            &big,
            None,
            &providers,
            std::sync::Arc::new(RedactionTable::empty()),
            None,
        )
        .await;
        assert!(!summarized);
        assert!(crate::tokens::count(&text) <= HARNESS_REPORT_TOKEN_CAP + 50);
        assert!(!text.is_empty());
    }

    #[test]
    fn render_includes_status_metadata_and_diff() {
        let res = HarnessRunResult {
            exit_code: Some(0),
            success: true,
            timed_out: false,
            text: "did the thing".to_string(),
            summarized: false,
            metadata: HarnessMetadata {
                cost_usd: Some(0.01),
                input_tokens: Some(10),
                output_tokens: Some(5),
                total_tokens: None,
                session_id: None,
            },
            policy: WritePolicy::Isolated,
            diff: Some("diff --git a/x b/x".to_string()),
        };
        let rendered = res.render("claude");
        assert!(rendered.contains("harness `claude`"));
        assert!(rendered.contains("exit 0 (success)"));
        assert!(rendered.contains("isolated"));
        assert!(rendered.contains("metadata:"));
        assert!(rendered.contains("did the thing"));
        assert!(rendered.contains("NOT applied"));
    }

    #[test]
    fn render_failure_shows_exit_code() {
        let res = HarnessRunResult {
            exit_code: Some(2),
            success: false,
            timed_out: false,
            text: "boom".to_string(),
            summarized: false,
            metadata: HarnessMetadata::default(),
            policy: WritePolicy::Direct,
            diff: None,
        };
        let rendered = res.render("codex");
        assert!(rendered.contains("exit 2 (failure)"));
        assert!(!rendered.contains("diff"));
    }

    /// Build-mode (direct) runs the harness in cwd and writes land
    /// directly; no diff is captured. Uses `sh` as a stand-in harness so
    /// the test doesn't require a real coding CLI.
    #[tokio::test]
    async fn build_mode_direct_writes_to_cwd_no_diff() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("written.txt");
        let cfg = sh_harness(&format!("printf done > {}", marker.display()));
        let redact = std::sync::Arc::new(RedactionTable::empty());
        let providers = ProvidersConfig::default();
        let res = run_harness(RunContext {
            harness_name: "sh",
            cfg: &cfg,
            prompt: "ignored",
            model: None,
            cwd: tmp.path(),
            agent_id: "Build",
            policy: WritePolicy::Direct,
            redact: redact.clone(),
            utility_model: None,
            providers: &providers,
            shutdown_gate: None,
            env_overlay: None,
        })
        .await
        .unwrap();
        assert!(res.success, "rendered: {}", res.render("sh"));
        assert!(res.diff.is_none());
        // The write landed directly in cwd.
        assert!(marker.exists());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "done");
    }

    /// Plan-mode (isolated) runs the harness in a throwaway worktree and
    /// returns the diff WITHOUT touching the real tree.
    #[tokio::test]
    async fn plan_mode_isolated_captures_diff_without_applying() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        // Init a git repo with one committed file.
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "t@t"],
            vec!["config", "user.name", "t"],
        ] {
            crate::git::run_git_checked(repo, &args).unwrap();
        }
        std::fs::write(repo.join("seed.txt"), "seed\n").unwrap();
        crate::git::run_git_checked(repo, &["add", "-A"]).unwrap();
        crate::git::run_git_checked(repo, &["commit", "-q", "-m", "init"]).unwrap();

        // The harness creates a new file in its (worktree) cwd.
        let cfg = sh_harness("printf 'hi\\n' > new.txt");
        let redact = std::sync::Arc::new(RedactionTable::empty());
        let providers = ProvidersConfig::default();
        let res = run_harness(RunContext {
            harness_name: "sh",
            cfg: &cfg,
            prompt: "ignored",
            model: None,
            cwd: repo,
            agent_id: "Plan",
            policy: WritePolicy::Isolated,
            redact: redact.clone(),
            utility_model: None,
            providers: &providers,
            shutdown_gate: None,
            env_overlay: None,
        })
        .await
        .unwrap();
        assert!(res.success, "rendered: {}", res.render("sh"));
        let diff = res.diff.expect("isolated run returns a diff");
        assert!(diff.contains("new.txt"), "diff was: {diff}");
        // The real tree is untouched — the new file only exists in the
        // (now-removed) worktree.
        assert!(!repo.join("new.txt").exists());
    }

    /// Preflight failure (missing binary) surfaces a clear error naming
    /// the harness + command.
    #[tokio::test]
    async fn missing_binary_returns_actionable_error() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = sh_harness("true");
        let mut cfg = cfg;
        cfg.command = "definitely-not-real-binary-xyz".to_string();
        let redact = std::sync::Arc::new(RedactionTable::empty());
        let providers = ProvidersConfig::default();
        let err = run_harness(RunContext {
            harness_name: "ghost",
            cfg: &cfg,
            prompt: "p",
            model: None,
            cwd: tmp.path(),
            agent_id: "Build",
            policy: WritePolicy::Direct,
            redact: redact.clone(),
            utility_model: None,
            providers: &providers,
            shutdown_gate: None,
            env_overlay: None,
        })
        .await
        .unwrap_err();
        assert!(err.contains("`ghost`"), "{err}");
        assert!(err.contains("not installed"), "{err}");
    }

    #[tokio::test]
    async fn plan_isolated_non_git_does_not_degrade_to_direct() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("written.txt");
        let cfg = sh_harness(&format!("printf done > {}", marker.display()));
        let redact = std::sync::Arc::new(RedactionTable::empty());
        let providers = ProvidersConfig::default();
        let err = run_harness(RunContext {
            harness_name: "sh",
            cfg: &cfg,
            prompt: "ignored",
            model: None,
            cwd: tmp.path(),
            agent_id: "Plan",
            policy: WritePolicy::Isolated,
            redact,
            utility_model: None,
            providers: &providers,
            shutdown_gate: None,
            env_overlay: None,
        })
        .await
        .unwrap_err();
        assert!(
            err.contains("not allowed to degrade to direct writes"),
            "{err}"
        );
        assert!(!marker.exists());
    }

    /// A `sh -c <script>` harness: prompt rides stdin (ignored by the
    /// script), so the script body fully controls the behavior.
    fn sh_harness(script: &str) -> HarnessConfig {
        use crate::config::extended::{ArgvOverflowBehavior, HarnessTrust, PromptInputMode};
        HarnessConfig {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            prompt_input: PromptInputMode::Stdin,
            argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: vec![],
            supports_json_output: false,
            json_output_args: vec![],
            supports_agent_file: false,
            agent_file_args: vec![],
            agent_file_env: None,
            trust: HarnessTrust::Untrusted,
            auth_probe_args: vec![],
            always_allow: false,
            timeout_secs: 30,
        }
    }
}
