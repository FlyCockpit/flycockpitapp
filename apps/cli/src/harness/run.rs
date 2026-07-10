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
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;

use crate::config::extended::HarnessConfig;
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

/// Timeout for the utility-model summarization call. Best-effort: if the
/// summary doesn't land in time we fall back to a deterministic tail.
const SUMMARY_CALL_TIMEOUT: Duration = Duration::from_secs(30);

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
        matches!(agent, "Build" | "Swarm" | "builder" | "bee")
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
    /// Live trusted-only gate for the utility model used by over-cap
    /// summarization.
    pub trusted_only: Arc<AtomicBool>,
    /// Utility model ref + providers for over-cap summarization. `None`
    /// disables summarization (over-cap output falls back to a tail).
    pub utility_model: Option<&'a str>,
    pub providers: &'a ProvidersConfig,
    pub env_overlay: Option<&'a std::collections::HashMap<String, String>>,
}

/// Run one harness invocation synchronously, end to end.
pub async fn run_harness(ctx: RunContext<'_>) -> Result<HarnessRunResult, String> {
    // 1. Redact the outbound prompt — non-bypassable (GOALS §7). From here
    //    on, only the scrubbed text exists in argv / stdin / tempfile.
    let scrubbed = ctx.redact.scrub(ctx.prompt);

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

    // 5. Spawn + drain + timeout.
    let timeout = Duration::from_secs(ctx.cfg.timeout_secs.max(1));
    let outcome =
        run_to_completion(&ctx.cfg.command, &args, &env, &run_dir, delivery, timeout).await;

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

    // For isolated runs, capture the diff before tearing the worktree down.
    let diff = isolation
        .as_ref()
        .map(|wt| wt.capture_diff().unwrap_or_default());
    if let Some(wt) = isolation {
        wt.cleanup();
    }

    // 6. Parse JSON metadata leniently (only when the harness advertises
    //    JSON output).
    let metadata = if ctx.cfg.supports_json_output {
        parse_harness_json(&output.stdout)
    } else {
        HarnessMetadata::default()
    };

    // 7. Build the model-facing text: stdout, plus stderr appended on
    //    failure (where the error usually lives). Cap / summarize.
    let mut raw_text = output.stdout.clone();
    if (!success || timed_out) && !output.stderr.trim().is_empty() {
        if !raw_text.is_empty() && !raw_text.ends_with('\n') {
            raw_text.push('\n');
        }
        raw_text.push_str("--- stderr ---\n");
        raw_text.push_str(&output.stderr);
    }

    let (text, summarized) = cap_or_summarize(
        &raw_text,
        ctx.utility_model,
        ctx.providers,
        ctx.redact.clone(),
        ctx.trusted_only.clone(),
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
    trusted_only: Arc<AtomicBool>,
) -> (String, bool) {
    if crate::tokens::count(text) <= HARNESS_REPORT_TOKEN_CAP {
        return (text.to_string(), false);
    }
    if let Some(model_ref) = utility_model
        && let Some(summary) =
            summarize_with_utility(text, model_ref, providers, redact, trusted_only).await
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
    trusted_only: Arc<AtomicBool>,
) -> Option<String> {
    let model = crate::engine::model::Model::from_ref_trusted_only(
        providers,
        model_ref,
        redact,
        trusted_only,
    )
    .ok()?;
    // Bound the input we hand the utility model so we don't blow its own
    // context: an excerpt within the hard cap is plenty for a summary.
    let bounded = excerpt(text, HARNESS_SUMMARY_HARD_CAP);
    let prompt = format!(
        "The following is the output of an external coding-agent run. Summarize it for another \
         agent in at most ~1500 words: what was done, what changed, key results/errors, and any \
         follow-ups. Return only the summary.\n\n<output>\n{bounded}\n</output>\n"
    );
    let resp = tokio::time::timeout(SUMMARY_CALL_TIMEOUT, model.text_completion(&prompt))
        .await
        .ok()?
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

    fn trust_flag_off() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn write_policy_defaults_by_primary() {
        assert_eq!(WritePolicy::for_primary("Build"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("Swarm"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("builder"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("bee"), WritePolicy::Direct);
        assert_eq!(WritePolicy::for_primary("Plan"), WritePolicy::Isolated);
        // Auto / custom → safer isolated default.
        assert_eq!(WritePolicy::for_primary("Auto"), WritePolicy::Isolated);
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
            trust_flag_off(),
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
            trust_flag_off(),
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
            trusted_only: trust_flag_off(),
            utility_model: None,
            providers: &providers,
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
            trusted_only: trust_flag_off(),
            utility_model: None,
            providers: &providers,
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
            trusted_only: trust_flag_off(),
            utility_model: None,
            providers: &providers,
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
            trusted_only: trust_flag_off(),
            utility_model: None,
            providers: &providers,
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
        use crate::config::extended::{ArgvOverflowBehavior, PromptInputMode};
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
            auth_env_vars: vec![],
            auth_probe_args: vec![],
            timeout_secs: 30,
        }
    }
}
