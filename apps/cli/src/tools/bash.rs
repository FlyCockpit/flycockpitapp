//! `bash` — execute a shell command.
//!
//! Auto-allow for v0 (GOALS bootstrap policy). The `exec_approval` flow
//! and Shift+Tab approval-mode cycling will land alongside the rest of
//! plan §3e.
//!
//! Per the tool-availability-policy memory: at startup we probe
//! `$PATH` for `rg`/`fd` and (on macOS) `gsed`. The tool description
//! advertises which of these are available so the model picks the
//! right binary, and on macOS-with-gsed we prepend a small `sed()`
//! shell function so `sed` invocations use the GNU implementation —
//! BSD `sed` differs enough that scripts written for Linux fail
//! silently on macOS.
//!
//! Safety:
//!   - Output is capped at [`crate::tools::common::OUTPUT_BYTE_CAP`].
//!   - The env scrub list from plan §3c removes the well-known
//!     injection-vector vars (`BASH_ENV`, `PROMPT_COMMAND`, …) and
//!     anything matching shared secret-name patterns.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::engine::TurnEvent;
use crate::engine::tool::{ResourceMeta, Tool, ToolCtx, ToolOutput, ToolOutputSidecar};
use crate::tools::common::{OUTPUT_BYTE_CAP, truncate_head_tail};

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 600_000;
pub(crate) const SHELL_WRITE_NATIVE_TOOL_HINT: &str = "Use `writeunlock` to create or rewrite files; shell redirection is for commands whose output you inspect, not files you intend to keep.";

/// One-shot guard so the Windows "shell sandboxing unavailable" notice
/// prints at most once per process (≈ per session — the daemon runs one
/// process). Token economy §10: a single terse line, never repeated.
#[cfg(windows)]
static WINDOWS_NOTICE_SHOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Configured at construction time from a `$PATH` probe. `description`
/// is the cached string returned by [`Tool::description`]; `prelude`
/// is prepended to every shell command (currently used only for the
/// macOS `sed → gsed` alias).
pub struct BashTool {
    description: String,
    /// The explicit, steering [`LlmMode::Defensive`] description
    /// (implementation note). Built at construction
    /// alongside `description` so it carries the same PATH-probe hints.
    defensive_description: String,
    prelude: String,
}

impl Default for BashTool {
    fn default() -> Self {
        Self::new()
    }
}

impl BashTool {
    pub fn new() -> Self {
        let has_rg = which::which("rg").is_ok();
        let has_fd = which::which("fd").is_ok();
        let has_gsed = which::which("gsed").is_ok();
        let alias_sed = cfg!(target_os = "macos") && has_gsed;

        // Build the description. GOALS §10 says: one sentence,
        // terse. We append a short suffix listing the search binaries
        // that are actually on PATH — saves the model a probe step.
        let mut hints: Vec<&str> = Vec::new();
        if has_rg {
            hints.push("rg");
        }
        if has_fd {
            hints.push("fd");
        }
        let search_hint = if hints.is_empty() {
            String::new()
        } else {
            format!("; prefer {} over grep/find", hints.join("/"))
        };
        let sed_hint = if alias_sed {
            "; `sed` is wired to gsed (GNU)".to_string()
        } else {
            String::new()
        };
        let description = format!(
            "Execute shell command; stdout/stderr/exit display is capped at 8 KB; declare resources for expensive builds/tests; redirect verbose logs to $TMPDIR (120s default timeout){search_hint}{sed_hint}"
        );

        // The defensive, explicitly-steering form (`llm-modes-
        // defensive-normal.md`). Same PATH-probe hints, more guidance.
        let defensive_description = format!(
            "Run a single shell command — builds, tests, git, package managers, \
             process/binary inspection — and get back combined stdout, stderr, and exit code. \
             Use `bash` ONLY to *run* things. For working with files the dedicated tools are \
             faster, budget-capped, and index-backed — reach for them instead: read a file → \
             `read` (NOT `cat`/`head`/`tail`/`less`); see what files exist or lay out a repo → \
             `tree` (NOT `ls`/`find`); search text or a pattern → `search` (NOT `rg`/`grep`); \
             find where a name is defined or used → `symbol_find` / `word` (NOT `grep`); see a \
             file's functions/types without reading it → `outline`. If you are about to pipe \
             `cat`, `rg`, `grep`, `ls`, or `find` through bash, stop and use the tool above \
             instead. Each call is its own shell: `cd`/env changes do NOT persist — chain with \
             `&&` or set `cwd`. For expensive builds/tests, declare `resources` such as \
             {{\"cpu\":1,\"memory\":1}}; `queue_timeout_ms` limits scheduler wait only. \
             Display output caps at 8 KB (head+tail kept); redirect verbose \
             build/test logs to a file under the session temp dir (`$TMPDIR`/`$TMP`/`$TEMP`) \
             unless the user explicitly wants a persistent workspace artifact, then inspect \
             focused slices or searches from that file. Never edit a file you intend to keep via bash — use \
             `readlock`+`writeunlock`/`editunlock`.{search_hint}{sed_hint}"
        );

        // Prepend a `sed` shell function on macOS so the model can use
        // its standard Linux-style flags without having to remember to
        // type `gsed` itself. `command gsed` bypasses the function on
        // recursion (no infinite-loop hazard).
        let prelude = if alias_sed {
            "sed() { command gsed \"$@\"; }; ".to_string()
        } else {
            String::new()
        };

        Self {
            description,
            defensive_description,
            prelude,
        }
    }
}

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &str {
        "bash"
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn defensive_description(&self) -> Option<String> {
        Some(self.defensive_description.clone())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "command",
            "properties": {
                "command":    { "type": "string", "x-cockpit-aliases": ["cmd", "shell", "script", "commandLine"], "description": "Shell command" },
                "cwd":        { "type": "string", "description": "Working directory; defaults to session cwd" },
                "timeout_ms": { "type": "integer", "description": "Hard timeout in ms (max 600000)" },
                "queue_timeout_ms": { "type": "integer", "description": "Optional timeout in ms while waiting for resource scheduler permits" },
                "resources": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 }, "description": "Optional resource permits for expensive commands, e.g. {\"cpu\":1,\"memory\":1}" }
            },
            "required": ["command"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "command",
            "properties": {
                "command":    { "type": "string", "x-cockpit-aliases": ["cmd", "shell", "script", "commandLine"], "description": "The shell command line to run. May be a pipeline; chain dependent steps with `&&` since each call is a fresh shell with no carried-over state" },
                "cwd":        { "type": "string", "description": "Directory to run the command in; defaults to the session working directory. Use this instead of a leading `cd`, which does not persist to later calls" },
                "timeout_ms": { "type": "integer", "description": "Hard wall-clock timeout in milliseconds after the command starts before it is killed; defaults to 120000, maximum 600000. Raise it for long builds/test runs" },
                "queue_timeout_ms": { "type": "integer", "description": "Optional milliseconds to wait for declared resource permits before giving up; this is separate from process runtime timeout" },
                "resources": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 }, "description": "Declare resource permits for expensive commands, e.g. {\"cpu\":1,\"memory\":1} for builds, tests, or other CPU/RAM-heavy work" }
            },
            "required": ["command"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        call_bash_inner(&self.prelude, args, ctx, BashRunOptions::default()).await
    }
}

#[derive(Debug, Clone, Default)]
struct BashRunOptions {
    force_unconfined: bool,
    escalated: bool,
    approval_scope_recorded: Option<String>,
}

pub(crate) async fn rerun_escalated_bash(
    args: Value,
    ctx: &ToolCtx,
    approval_scope_recorded: Option<String>,
) -> Result<ToolOutput> {
    let tool = BashTool::new();
    call_bash_inner(
        &tool.prelude,
        args,
        ctx,
        BashRunOptions {
            force_unconfined: true,
            escalated: true,
            approval_scope_recorded,
        },
    )
    .await
}

pub(crate) async fn rerun_escalated_bash_confined(
    args: Value,
    ctx: &ToolCtx,
) -> Result<ToolOutput> {
    let tool = BashTool::new();
    call_bash_inner(
        &tool.prelude,
        args,
        ctx,
        BashRunOptions {
            force_unconfined: false,
            escalated: true,
            approval_scope_recorded: None,
        },
    )
    .await
}

async fn call_bash_inner(
    prelude: &str,
    args: Value,
    ctx: &ToolCtx,
    options: BashRunOptions,
) -> Result<ToolOutput> {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::engine::tool::invalid_input("`command` is required"))?;
    let cwd = args
        .get("cwd")
        .and_then(Value::as_str)
        .map(|s| crate::tools::common::resolve(s, &ctx.cwd))
        .unwrap_or_else(|| ctx.cwd.clone());
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .min(MAX_TIMEOUT_MS);
    let queue_timeout_ms = args.get("queue_timeout_ms").and_then(Value::as_u64);
    let declared_resources = parse_resource_requirements(args.get("resources"))?;

    if let Some(outside) =
        outside_session_boundary(&cwd, &ctx.cwd, ctx.session.tmp_dir().as_deref())
    {
        approve_outside_working_directory(ctx, &outside).await?;
    }
    if let Some(outside) =
        command_directory_escape(command, &cwd, &ctx.cwd, ctx.session.tmp_dir().as_deref())
    {
        approve_outside_working_directory(ctx, &outside).await?;
    }

    tracing::debug!(command, timeout_ms, "bash: spawning");

    let prefixed = if prelude.is_empty() {
        command.to_string()
    } else {
        format!("{prelude}{command}")
    };

    // Resolve whether to confine this run (sandboxing part 2):
    //
    //   - Windows: never (no zerobox backend) — run unconfined and
    //     show the one-time per-session notice.
    //   - Sandboxing disabled for this session (`/sandbox off` /
    //     `--no-sandbox`): run unconfined.
    //   - Otherwise consult part 1: if every constituent simple
    //     command is already granted broad access (Session/Project/
    //     Global), skip the box and run with broadened access.
    //   - Else consult the once-per-process environment probe: if the
    //     sandbox can't initialize here (user namespaces blocked, WSL1,
    //     bwrap absent), refuse with an actionable `/sandbox off` error
    //     instead of failing into the escalation prompt.
    //   - Else run sandboxed (cwd + session tmp rw, PATH exec, deny
    //     outside).
    let sandbox_enabled =
        ctx.session.sandbox_enabled() && crate::tools::shell_sandbox::shell_sandbox_supported();
    let sandbox_on = sandbox_enabled && !options.force_unconfined;

    // Windows has no zerobox backend: show the one-time per-session
    // notice that the shell runs unconfined. The flag is only ever
    // `Some` on Windows; elsewhere it stays `None`.
    let windows_notice: Option<&'static str> = windows_shell_notice(ctx);

    let granted_broad = if sandbox_on {
        command_granted_broad(ctx, command).await
    } else {
        false
    };

    let session_env = ctx
        .env_overlay
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let tmp_dir = ctx.session.tmp_dir();
    let scrub = scrub_overrides(&session_env);
    let command_classification = crate::approval::classify::classify(command);
    let extended_config = crate::config::extended::load_for_cwd(&cwd);
    let profile_introspector =
        crate::tools::command_resource_profiles::ProductionProfileIntrospector::new(
            true,
            tmp_dir.clone(),
        );
    let command_resource_plan = command_resource_plan_with_user_grants(
        crate::tools::command_resource_profiles::plan_for_command(
            command_classification.simple_commands(),
            &cwd,
            &session_env,
            &extended_config.command_resource_profiles,
            &profile_introspector,
        ),
        ctx,
    );
    let resource_plan = build_resource_plan(
        declared_resources,
        &extended_config.resource_scheduler,
        command,
        &command_classification,
        queue_timeout_ms,
    );

    if !options.force_unconfined && ctx.session.sandbox_mode().is_container() {
        return run_container_bash(
            command,
            &prefixed,
            &cwd,
            timeout_ms,
            &session_env,
            &scrub,
            &extended_config,
            &command_resource_plan,
            &resource_plan,
            ctx,
        )
        .await;
    }

    // Resolve the gating decision. When confinement is actually on the
    // table (sandbox on, not already broad-granted) we consult the
    // once-per-process environment probe: if the sandbox cannot
    // initialize here, refuse with an actionable `/sandbox off` error
    // rather than letting every command fail into run-fail-escalate. The
    // probe is skipped entirely for the off / broad-granted paths (no
    // probe cost, no spawn). The probe needs a real cwd — we pass the
    // command's resolved cwd (it falls back to a temp dir internally).
    let availability = if sandbox_on && !granted_broad {
        crate::tools::shell_sandbox::sandbox_available(&cwd)
            .await
            .clone()
    } else {
        // Not consulted on these paths; the gate ignores it.
        crate::tools::shell_sandbox::SandboxAvailability::Available
    };
    let gate = crate::tools::shell_sandbox::gate_decision(sandbox_on, granted_broad, &availability);

    if let crate::tools::shell_sandbox::SandboxGate::Refuse { reason } = &gate {
        // Sandbox enabled but cannot initialize: record the accurate
        // diagnostic state (enabled, not confined, not run) out-of-band
        // and return a model-facing error (token economy §10). The
        // message is addressed to the *model*, not a human: the probe is
        // cached process-lifetime so this verdict is permanent for the
        // session, and `/sandbox off` is a composer UI command, never a
        // shell command — saying so explicitly stops weaker models from
        // both retrying the dead sandbox and shell-executing `/sandbox
        // off` (the original phrasing read as a shell instruction).
        // Never falls through to the escalation prompt.
        let meta = crate::engine::tool::SandboxMeta {
            enabled: sandbox_enabled,
            confined: false,
            escalated: options.escalated,
            broad_grant_simple_commands: granted_broad,
            approval_scope_recorded: options.approval_scope_recorded.clone(),
            // The sandbox-unavailable signal: carry the diagnosed `reason`
            // (incl. the `sudo sysctl …=0` command when diagnosed) out-of-
            // band so the engine raises the deterministic user-facing
            // indicator (§6.5). Never enters the model-facing body above.
            unavailable_reason: Some(reason.clone()),
            resource_profiles: command_resource_plan.metas.clone(),
        };
        if !options.escalated
            && matches!(ctx.llm_mode, crate::config::extended::LlmMode::Defensive)
            && ctx.session.sandbox_escalation_enabled()
            && let Some(output) = defensive_human_escalation_offer(
                args.clone(),
                command,
                &cwd,
                1,
                format!("sandbox unavailable: {reason}"),
                ctx,
            )
            .await?
        {
            return Ok(output);
        }
        return Ok(ToolOutput::text(format!(
                "Error: the shell sandbox cannot start here ({reason}); `bash` will fail for the rest of the session until the user types `/sandbox off` in the cockpit composer (a UI command, not a shell command) — ask them to do that; do not retry or run `/sandbox off` yourself."
            ))
            .with_sandbox(meta));
    }

    let confine = matches!(gate, crate::tools::shell_sandbox::SandboxGate::Confine);

    // Part B: the sandbox-state sub-object for the tool_call event. We
    // accumulate the four-state record as the run proceeds and attach it
    // to whichever `ToolOutput` we return (every path), so an export is
    // diagnosable across sandbox-off / broad-grant-skip / confined-
    // success / confined-fail→escalate. It is NEVER added to the
    // model-facing body (token economy §10).
    let mut meta = crate::engine::tool::SandboxMeta {
        enabled: sandbox_enabled,
        confined: confine,
        escalated: options.escalated,
        broad_grant_simple_commands: granted_broad,
        approval_scope_recorded: options.approval_scope_recorded.clone(),
        // Not the refuse path — the sandbox initialized (or was off /
        // broad-granted), so there's no unavailable remedy to surface.
        unavailable_reason: None,
        resource_profiles: command_resource_plan.metas.clone(),
    };

    if confine && !command_resource_plan.invalid_roots.is_empty() {
        let issues = command_resource_plan
            .invalid_roots
            .iter()
            .map(|issue| issue.render())
            .collect::<Vec<_>>()
            .join("; ");
        return Ok(ToolOutput::text(format!(
                "Error: command resource profiles cannot expose configured toolchain roots ({issues}). Fix the root environment variables/profile config or use a broad command approval so the command runs without shell confinement."
            ))
            .with_sandbox(meta));
    }

    let (resource_meta, _resource_lease) =
        match acquire_resource_lease(ctx, &resource_plan, &meta).await {
            Ok(acquired) => acquired,
            Err(output) => return Ok(output),
        };

    // First attempt: sandboxed (confined) or broadened/unconfined.
    let attempt = run_shell(
        &prefixed,
        &cwd,
        confine,
        tmp_dir.as_deref(),
        &scrub,
        &session_env,
        &command_resource_plan.allow_paths,
        ctx,
        timeout_ms,
    )
    .await;
    let outcome = match attempt {
        RunOutcome::Cancelled => {
            return Ok(ToolOutput::truncated_text(
                "Error: command cancelled by user (ctrl+c)".to_string(),
            )
            .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::TimedOut => {
            return Ok(ToolOutput::truncated_text(format!(
                "Error: timeout after {timeout_ms} ms{}",
                crate::tools::command_resource_profiles::resource_profile_context(
                    &command_resource_plan
                )
            ))
            .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::SpawnError(e) => {
            let mut message = render_spawn_error(&prefixed, &cwd, &e);
            message.push_str(
                &crate::tools::command_resource_profiles::resource_profile_context(
                    &command_resource_plan,
                ),
            );
            return Ok(ToolOutput::text(message).with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::WaitError(e) => {
            return Ok(ToolOutput::text(format!(
                    "Error: the command failed to run ({e}); check the command syntax or try a simpler invocation"
                ))
                .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::Done(o) => o,
    };

    // Run-fail-escalate (sandboxing part 2): automatic unconfined reruns
    // are only allowed from trusted sandbox metadata. Child stderr is
    // attacker-controlled, and zerobox currently exposes no structured
    // "the sandbox denied this operation" signal here, so confined
    // failures fall through with their original result.
    let mut final_outcome = outcome;
    if confine
        && let Some((confined_exit, confined_stderr)) =
            confined_failure_escalation_offer(&final_outcome)
        && let Some(approver) = ctx.approver.as_ref()
    {
        meta.escalated = true;
        // The distinct escalation prompt: carries the FIRST confined
        // attempt's trusted denial detail, captured before the re-run
        // overwrites `final_outcome`.
        let decision = approver
            .approve_command_escalated(command, confined_exit, confined_stderr)
            .await?;
        if let crate::approval::Decision::Allow { scope } = decision {
            meta.approval_scope_recorded = Some(scope.as_str().to_string());
            let rerun = run_shell(
                &prefixed,
                &cwd,
                false, // broadened — no confinement
                tmp_dir.as_deref(),
                &scrub,
                &session_env,
                &command_resource_plan.allow_paths,
                ctx,
                timeout_ms,
            )
            .await;
            match rerun {
                RunOutcome::Cancelled => {
                    return Ok(ToolOutput::truncated_text(
                        "Error: command cancelled by user (ctrl+c)".to_string(),
                    )
                    .with_bash_meta(meta, &resource_meta));
                }
                RunOutcome::TimedOut => {
                    return Ok(ToolOutput::truncated_text(format!(
                        "Error: timeout after {timeout_ms} ms{}",
                        crate::tools::command_resource_profiles::resource_profile_context(
                            &command_resource_plan
                        )
                    ))
                    .with_bash_meta(meta, &resource_meta));
                }
                RunOutcome::SpawnError(e) => {
                    let mut message = render_spawn_error(&prefixed, &cwd, &e);
                    message.push_str(
                        &crate::tools::command_resource_profiles::resource_profile_context(
                            &command_resource_plan,
                        ),
                    );
                    return Ok(ToolOutput::text(message).with_bash_meta(meta, &resource_meta));
                }
                RunOutcome::WaitError(e) => {
                    return Ok(ToolOutput::text(format!(
                            "Error: the command failed to run ({e}); check the command syntax or try a simpler invocation"
                        ))
                        .with_bash_meta(meta, &resource_meta));
                }
                RunOutcome::Done(o) => final_outcome = o,
            }
        } else if matches!(decision, crate::approval::Decision::NoninteractiveDeny) {
            // A headless run must give the model the structured reason for
            // the refusal, not merely replay the sandbox's opaque stderr.
            return Ok(ToolOutput::text(crate::approval::NONINTERACTIVE_RUN_DENIAL)
                .with_bash_meta(meta, &resource_meta));
        }
    }

    if confine
        && !options.escalated
        && !final_outcome.success
        && matches!(ctx.llm_mode, crate::config::extended::LlmMode::Defensive)
        && ctx.session.sandbox_escalation_enabled()
        && let Some(output) = defensive_human_escalation_offer(
            args.clone(),
            command,
            &cwd,
            final_outcome.exit,
            String::from_utf8_lossy(&final_outcome.stderr)
                .trim_end()
                .to_string(),
            ctx,
        )
        .await?
    {
        return Ok(output);
    }

    if confine
        && !final_outcome.success
        && let Some(hint) = command_resource_plan.unsupported_hint()
    {
        final_outcome.stderr.extend_from_slice(hint.as_bytes());
        final_outcome.stderr.push(b'\n');
    }

    // Native shell-output compression (implementation note):
    // when the session has the `shell compression` setting enabled, run
    // each stream through cockpit's rtk-native filter (generic noise strip
    // + per-command strategy) BEFORE the body is assembled — so the model
    // sees compressed output, the user's setting decides verbatim vs not,
    // and the failure-signal-preserving `exit:` line is always appended
    // outside the filter. This sits strictly before the §7 redaction
    // chokepoint (`redact::scrub`, applied in `engine::agent::turn`), which
    // still scrubs whatever the filter leaves. Disabled → verbatim.
    let compress = ctx.session.shell_compression_enabled();

    // Defensive-mode routing nudge (`defensive-tool-routing-
    // behavioral-nudge.md`): in `Defensive` mode only, classify the command
    // off its first program and — unless the model has already adopted the
    // dedicated tool this session (self-suppression) — append ONE terse tip
    // line to the model-facing body, after the `exit:` line and outside
    // compression. `Normal` mode appends nothing (token economy §10), and a
    // command with no file/search replacement classifies to `None`.
    let tip = if matches!(ctx.llm_mode, crate::config::extended::LlmMode::Defensive) {
        crate::tools::shell_compress::classify_tip(command)
            .filter(|t| !ctx.session.tip_suppressed(*t))
    } else {
        None
    };
    let native_write_hint = durable_shell_write_hint(command);

    // Model-facing body is unchanged — only `final_outcome` is rendered,
    // never the sandbox metadata (which rides out-of-band for the event).
    let body = render_output(
        &final_outcome,
        windows_notice,
        compress,
        command,
        &cwd,
        tip,
        native_write_hint,
    );
    // Structured exit code for the `tool_call` event (export-audit
    // fidelity): authoritative source, distinct from the `exit: N` text the
    // body still carries. A signaled run has no numeric code, so the field
    // is omitted (the body's `exit: signaled` line remains the signal).
    let exit_field = if final_outcome.signaled {
        None
    } else {
        Some(final_outcome.exit)
    };
    let truncated_for_display = body.len() > OUTPUT_BYTE_CAP;
    let sidecar = bash_output_sidecar(command, &cwd, &final_outcome, &body, truncated_for_display);
    if truncated_for_display {
        // Head+tail so the `exit:` line and any stderr at the tail
        // survive — the failure signal usually lives there.
        let mut out = ToolOutput::truncated_text(truncate_head_tail(&body, OUTPUT_BYTE_CAP))
            .with_bash_meta(meta, &resource_meta);
        if let Some(sidecar) = sidecar {
            out = out.with_output_sidecar(sidecar);
        }
        Ok(match exit_field {
            Some(code) => out.with_exit_code(code),
            None => out,
        })
    } else {
        let mut out = ToolOutput::text(body).with_bash_meta(meta, &resource_meta);
        if let Some(sidecar) = sidecar {
            out = out.with_output_sidecar(sidecar);
        }
        Ok(match exit_field {
            Some(code) => out.with_exit_code(code),
            None => out,
        })
    }
}

const OUTSIDE_CWD_ERROR: &str = "Error: command working directory resolves outside the session root. Use a subdirectory of {root}, or ask the user for approval to work outside it.";

async fn approve_outside_working_directory(ctx: &ToolCtx, path: &Path) -> Result<()> {
    let Some(approver) = ctx.approver.as_ref() else {
        return Err(crate::engine::tool::invalid_input(outside_cwd_error(
            &ctx.cwd,
        )));
    };
    let decision = approver
        .approve_path(
            path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
    if decision.is_allowed() {
        Ok(())
    } else if matches!(decision, crate::approval::Decision::NoninteractiveDeny) {
        Err(crate::engine::tool::invalid_input(
            crate::approval::NONINTERACTIVE_RUN_DENIAL,
        ))
    } else {
        Err(crate::engine::tool::invalid_input(outside_cwd_error(
            &ctx.cwd,
        )))
    }
}

fn outside_cwd_error(root: &Path) -> String {
    OUTSIDE_CWD_ERROR.replace("{root}", &root.display().to_string())
}

pub(crate) fn outside_session_boundary(
    path: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    crate::tools::sandbox::outside_session_boundary(path, root, tmp_dir)
}

pub(crate) fn command_directory_escape(
    command: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    let tokens = shell_tokens(command);
    let mut i = 0;
    let mut command_start = true;
    let mut current_program: Option<String> = None;
    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Operator(op) => {
                command_start = matches!(op.as_str(), ";" | "&" | "&&" | "||" | "|" | "(");
                if command_start || op == ")" {
                    current_program = None;
                }
                i += 1;
            }
            ShellToken::Word(word) => {
                if command_start {
                    if (word == "cd" || word == "pushd")
                        && let Some(target) =
                            directory_change_target(&tokens, i + 1, word == "pushd")
                    {
                        let resolved = crate::tools::common::resolve(&target, command_cwd);
                        if let Some(outside) = outside_session_boundary(&resolved, root, tmp_dir) {
                            return Some(outside);
                        }
                    }
                    current_program = Some(word.clone());
                    command_start = false;
                    i += 1;
                    continue;
                }
                // Best-effort native boundary gate for unconfined platforms
                // and `/sandbox off`: absolute path tokens are always checked,
                // while relative path-looking operands are checked for common
                // path-oriented commands. Dynamic/eval-expanded paths (`$HOME`,
                // command substitution, globs expanded by the shell) are outside
                // this static pass and remain governed by sandboxing or approval.
                if literal_path_operand_command(current_program.as_deref())
                    && let Some(outside) =
                        literal_path_word_escape(word, command_cwd, root, tmp_dir)
                {
                    return Some(outside);
                }
                if Path::new(word).is_absolute()
                    && let Some(outside) =
                        literal_path_word_escape(word, command_cwd, root, tmp_dir)
                {
                    return Some(outside);
                }
                i += 1;
            }
        }
    }
    None
}

fn literal_path_operand_command(program: Option<&str>) -> bool {
    matches!(
        program,
        Some(
            "cat"
                | "head"
                | "tail"
                | "less"
                | "more"
                | "ls"
                | "find"
                | "stat"
                | "file"
                | "wc"
                | "cp"
                | "mv"
                | "rm"
                | "mkdir"
                | "touch"
                | "tee"
                | "chmod"
                | "chown"
                | "grep"
                | "rg"
        )
    )
}

fn literal_path_word_escape(
    word: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    if word.starts_with('-') || dynamic_shell_path(word) {
        return None;
    }
    let path = Path::new(word);
    let path_like = path.is_absolute()
        || word.contains('/')
        || word.contains('\\')
        || word == "."
        || word == "..";
    if !path_like {
        return None;
    }
    let resolved = crate::tools::common::resolve(word, command_cwd);
    outside_session_boundary(&resolved, root, tmp_dir)
}

fn directory_change_target(tokens: &[ShellToken], mut i: usize, pushd: bool) -> Option<String> {
    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Operator(_) => return None,
            ShellToken::Word(word) if word.is_empty() => i += 1,
            ShellToken::Word(word) if word.contains('=') && !word.starts_with('/') => i += 1,
            ShellToken::Word(word) if pushd && (word.starts_with('+') || word.starts_with('-')) => {
                i += 1
            }
            ShellToken::Word(word) if word.starts_with('-') && word != "-" => i += 1,
            ShellToken::Word(word) => return Some(word.clone()),
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellToken {
    Word(String),
    Operator(String),
}

fn shell_tokens(command: &str) -> Vec<ShellToken> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if ch == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            } else {
                word.push(ch);
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            c if c.is_whitespace() => {
                push_word(&mut tokens, &mut word);
            }
            ';' | '(' | ')' => {
                push_word(&mut tokens, &mut word);
                tokens.push(ShellToken::Operator(ch.to_string()));
            }
            '&' | '|' => {
                push_word(&mut tokens, &mut word);
                let mut op = ch.to_string();
                if chars.peek().copied() == Some(ch) {
                    op.push(chars.next().unwrap());
                }
                tokens.push(ShellToken::Operator(op));
            }
            _ => word.push(ch),
        }
    }
    push_word(&mut tokens, &mut word);
    tokens
}

fn push_word(tokens: &mut Vec<ShellToken>, word: &mut String) {
    if !word.is_empty() {
        tokens.push(ShellToken::Word(std::mem::take(word)));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShellWriteTargets {
    None,
    Concrete(Vec<PathBuf>),
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WriteToken {
    Word(String),
    Op(&'static str),
    HeredocBody(String),
}

struct PendingHeredoc {
    delimiter: String,
    strip_tabs: bool,
}

pub(crate) fn shell_write_targets(command: &str, cwd: &Path) -> ShellWriteTargets {
    let tokens = shell_write_tokens(command);
    if tokens.is_empty() {
        return ShellWriteTargets::None;
    }

    let mut targets: Vec<PathBuf> = Vec::new();
    let mut command_start = true;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            WriteToken::Op(op) => {
                match *op {
                    ">" | ">>" | ">|" => {
                        let Some(WriteToken::Word(target)) = tokens.get(i + 1) else {
                            return ShellWriteTargets::Dynamic;
                        };
                        if dynamic_shell_path(target) {
                            return ShellWriteTargets::Dynamic;
                        }
                        push_shell_write_target(&mut targets, target, cwd);
                        i += 2;
                        command_start = false;
                        continue;
                    }
                    "<<" | "<<-" | "<" => {
                        i += 2;
                        command_start = false;
                        continue;
                    }
                    ";" | "&" | "&&" | "||" | "|" | "(" => {
                        command_start = true;
                    }
                    ")" => command_start = false,
                    _ => {}
                }
                i += 1;
            }
            WriteToken::Word(word) => {
                if command_start && word == "tee" {
                    let mut j = i + 1;
                    while j < tokens.len() {
                        match &tokens[j] {
                            WriteToken::Op(_) | WriteToken::HeredocBody(_) => break,
                            WriteToken::Word(arg) if arg.starts_with('-') && arg != "-" => {
                                j += 1;
                            }
                            WriteToken::Word(arg) => {
                                if dynamic_shell_path(arg) {
                                    return ShellWriteTargets::Dynamic;
                                }
                                push_shell_write_target(&mut targets, arg, cwd);
                                j += 1;
                            }
                        }
                    }
                }
                command_start = false;
                i += 1;
            }
            WriteToken::HeredocBody(_) => {
                i += 1;
            }
        }
    }

    if targets.is_empty() {
        ShellWriteTargets::None
    } else {
        ShellWriteTargets::Concrete(targets)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShellWriteContentPreview {
    Literal(String),
    Dynamic(String),
}

pub(crate) fn shell_write_content_preview(
    command: &str,
) -> crate::daemon::proto::WriteContentPreview {
    match shell_write_content_preview_inner(command) {
        ShellWriteContentPreview::Literal(content) => crate::daemon::proto::WriteContentPreview {
            content,
            dynamic: false,
        },
        ShellWriteContentPreview::Dynamic(source) => crate::daemon::proto::WriteContentPreview {
            content: format!("(output of `{source}`)"),
            dynamic: true,
        },
    }
}

fn shell_write_content_preview_inner(command: &str) -> ShellWriteContentPreview {
    let tokens = shell_write_tokens(command);
    if let Some(body) = tokens.iter().find_map(|token| match token {
        WriteToken::HeredocBody(body) => Some(body),
        _ => None,
    }) {
        return ShellWriteContentPreview::Literal(body.clone());
    }
    let Some((op_index, _)) = tokens
        .iter()
        .enumerate()
        .find(|(_, token)| matches!(token, WriteToken::Op(">" | ">>" | ">|")))
    else {
        return ShellWriteContentPreview::Dynamic(command.trim().to_string());
    };
    let words = words_before_redirect(&tokens[..op_index]);
    if let Some(literal) = literal_shell_write_source(&words) {
        ShellWriteContentPreview::Literal(literal)
    } else {
        let source = words.join(" ");
        ShellWriteContentPreview::Dynamic(source)
    }
}

fn words_before_redirect(tokens: &[WriteToken]) -> Vec<&str> {
    tokens
        .iter()
        .filter_map(|token| match token {
            WriteToken::Word(word) => Some(word.as_str()),
            WriteToken::Op(_) | WriteToken::HeredocBody(_) => None,
        })
        .collect()
}

fn literal_shell_write_source(words: &[&str]) -> Option<String> {
    let mut words = words.iter().copied();
    let program = words.next()?;
    let mut args: Vec<&str> = words.collect();
    match program {
        "echo" => {
            let newline = if args.first() == Some(&"-n") {
                args.remove(0);
                ""
            } else {
                "\n"
            };
            Some(format!("{}{newline}", args.join(" ")))
        }
        "printf" => printf_literal_preview(&args),
        _ => None,
    }
}

fn printf_literal_preview(args: &[&str]) -> Option<String> {
    let format = args.first()?;
    if format.contains('%') || format.contains('\\') {
        return None;
    }
    Some(format.to_string())
}

fn durable_shell_write_hint(command: &str) -> Option<&'static str> {
    let tokens = shell_write_tokens(command);
    let mut command_start = true;
    let mut current_program: Option<&str> = None;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            WriteToken::Op(op) => {
                match *op {
                    ">" | ">>" | ">|"
                        if matches!(current_program, Some("cat" | "printf" | "echo"))
                            && matches!(tokens.get(i + 1), Some(WriteToken::Word(_))) =>
                    {
                        return Some(SHELL_WRITE_NATIVE_TOOL_HINT);
                    }
                    ";" | "&" | "&&" | "||" | "|" | "(" => {
                        command_start = true;
                        current_program = None;
                    }
                    ")" => {
                        command_start = false;
                        current_program = None;
                    }
                    _ => {}
                }
                i += 1;
            }
            WriteToken::HeredocBody(_) => {
                i += 1;
            }
            WriteToken::Word(word) => {
                if command_start {
                    if word == "tee" {
                        return Some(SHELL_WRITE_NATIVE_TOOL_HINT);
                    }
                    current_program = Some(word.as_str());
                    command_start = false;
                }
                i += 1;
            }
        }
    }
    None
}

fn shell_write_tokens(command: &str) -> Vec<WriteToken> {
    let mut tokens = Vec::new();
    let mut lines = command.split_inclusive('\n').peekable();
    while let Some(raw_line) = lines.next() {
        let had_newline = raw_line.ends_with('\n');
        let line = raw_line.trim_end_matches('\n');
        let line_start = tokens.len();
        tokenize_write_line(line, &mut tokens);
        let pending = pending_heredocs(&tokens[line_start..]);
        if had_newline {
            tokens.push(WriteToken::Op(";"));
        }
        for heredoc in pending {
            let mut body = String::new();
            for body_raw in lines.by_ref() {
                let body_had_newline = body_raw.ends_with('\n');
                let body_line = body_raw.trim_end_matches('\n');
                let compare = if heredoc.strip_tabs {
                    body_line.trim_start_matches('\t')
                } else {
                    body_line
                };
                if compare == heredoc.delimiter {
                    break;
                }
                let content = if heredoc.strip_tabs {
                    body_line.trim_start_matches('\t')
                } else {
                    body_line
                };
                body.push_str(content);
                if body_had_newline {
                    body.push('\n');
                }
            }
            tokens.push(WriteToken::HeredocBody(body));
            tokens.push(WriteToken::Op(";"));
        }
    }
    tokens
}

fn pending_heredocs(tokens: &[WriteToken]) -> Vec<PendingHeredoc> {
    let mut pending = Vec::new();
    let mut i = 0;
    while i + 1 < tokens.len() {
        match (&tokens[i], &tokens[i + 1]) {
            (WriteToken::Op("<<"), WriteToken::Word(delimiter)) => {
                pending.push(PendingHeredoc {
                    delimiter: delimiter.clone(),
                    strip_tabs: false,
                });
                i += 2;
            }
            (WriteToken::Op("<<-"), WriteToken::Word(delimiter)) => {
                pending.push(PendingHeredoc {
                    delimiter: delimiter.clone(),
                    strip_tabs: true,
                });
                i += 2;
            }
            _ => i += 1,
        }
    }
    pending
}

fn tokenize_write_line(command: &str, tokens: &mut Vec<WriteToken>) {
    let mut word = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if ch == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            } else {
                word.push(ch);
            }
            continue;
        }

        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            c if c.is_whitespace() => push_write_word(tokens, &mut word),
            ';' | '(' | ')' => {
                push_write_word(tokens, &mut word);
                tokens.push(WriteToken::Op(match ch {
                    ';' => ";",
                    '(' => "(",
                    ')' => ")",
                    _ => unreachable!(),
                }));
            }
            '&' | '|' => {
                push_write_word(tokens, &mut word);
                let op = if chars.peek().copied() == Some(ch) {
                    chars.next();
                    if ch == '&' { "&&" } else { "||" }
                } else if ch == '&' {
                    "&"
                } else {
                    "|"
                };
                tokens.push(WriteToken::Op(op));
            }
            '>' => {
                push_write_word(tokens, &mut word);
                let op = match chars.peek().copied() {
                    Some('>') => {
                        chars.next();
                        ">>"
                    }
                    Some('|') => {
                        chars.next();
                        ">|"
                    }
                    _ => ">",
                };
                tokens.push(WriteToken::Op(op));
            }
            '<' => {
                push_write_word(tokens, &mut word);
                let op = if chars.peek().copied() == Some('<') {
                    chars.next();
                    if chars.peek().copied() == Some('<') {
                        chars.next();
                        "<<<"
                    } else if chars.peek().copied() == Some('-') {
                        chars.next();
                        "<<-"
                    } else {
                        "<<"
                    }
                } else {
                    "<"
                };
                tokens.push(WriteToken::Op(op));
            }
            _ => word.push(ch),
        }
    }
    push_write_word(tokens, &mut word);
}

fn push_write_word(tokens: &mut Vec<WriteToken>, word: &mut String) {
    if !word.is_empty() {
        tokens.push(WriteToken::Word(std::mem::take(word)));
    }
}

fn push_shell_write_target(targets: &mut Vec<PathBuf>, target: &str, cwd: &Path) {
    if target == "-" {
        return;
    }
    let resolved = crate::tools::common::resolve(target, cwd);
    if !targets.iter().any(|existing| existing == &resolved) {
        targets.push(resolved);
    }
}

fn dynamic_shell_path(path: &str) -> bool {
    path.is_empty()
        || path == "-"
        || path.starts_with('~')
        || path.contains('$')
        || path.contains('`')
        || path.contains('*')
        || path.contains('?')
        || path.contains('[')
        || path.contains(']')
        || path.contains('{')
        || path.contains('}')
}

/// Returns the trusted escalation offer for a confined failure, if the shell
/// sandbox provided one.
///
/// Child stderr is not trusted input: a command can print "Permission denied"
/// or "Read-only file system" itself. Zerobox does not expose structured
/// per-operation denial metadata to this caller, so today there is no safe
/// automatic rerun signal and the original confined failure is preserved.
fn confined_failure_escalation_offer(_outcome: &ShellOutcome) -> Option<(i32, String)> {
    None
}

/// Whether *every* simple command in `command` is already granted broad
/// (Session/Project/Global) access through part 1's store — in which
/// case the sandboxed run is skipped and the command runs broadened with
/// no prompt. A wrapper, an ungranted command, or no approver all return
/// `false` (run sandboxed). Pure store reads — never prompts here.
fn command_resource_plan_with_user_grants(
    mut plan: crate::tools::command_resource_profiles::CommandResourcePlan,
    ctx: &ToolCtx,
) -> crate::tools::command_resource_profiles::CommandResourcePlan {
    let Some(approver) = ctx.approver.as_ref() else {
        return plan;
    };
    plan.allow_paths.extend(
        approver
            .store()
            .effective_path_grants()
            .into_iter()
            .map(|grant| crate::tools::shell_sandbox::ExtraSandboxPath {
                kind: "user_grant".to_string(),
                path: grant.path,
                access: grant.access,
            }),
    );
    plan
}

async fn command_granted_broad(ctx: &ToolCtx, command: &str) -> bool {
    let Some(approver) = ctx.approver.as_ref() else {
        return false;
    };
    let classification = crate::approval::classify::classify(command);
    let simple = classification.simple_commands();
    if simple.is_empty() || classification.has_wrapper() {
        // Empty / unparseable / no simple commands, or any wrapper → run
        // sandboxed (a wrapper is never persistable, so never "granted
        // broad").
        return false;
    }
    simple
        .iter()
        .all(|info| crate::approval::command_grant_allowed_by_policy(approver.store(), info))
}

async fn defensive_human_escalation_offer(
    args: Value,
    command: &str,
    cwd: &Path,
    confined_exit: i32,
    confined_stderr: String,
    ctx: &ToolCtx,
) -> Result<Option<ToolOutput>> {
    if matches!(
        crate::tools::escalate::escalation_route(
            ctx.session.approval_mode(),
            None, // Defensive human offers force Auto through the user.
        ),
        crate::tools::escalate::EscalationRoute::RunUnconfinedOnce
    ) {
        return Box::pin(crate::tools::bash::rerun_escalated_bash(args, ctx, None))
            .await
            .map(Some);
    }
    if !matches!(
        ctx.session.approval_mode(),
        crate::config::extended::ApprovalMode::Manual | crate::config::extended::ApprovalMode::Auto
    ) {
        return Ok(None);
    }

    let Some(approver) = ctx.approver.as_ref() else {
        return Ok(None);
    };
    let detail = crate::daemon::proto::CommandDetail {
        full_command: command.to_string(),
        highlight: None,
        step: 1,
        step_count: 1,
        cwd: Some(cwd.display().to_string()),
        remembered_key: None,
        write_content: None,
        risk_tier: None,
        risk_reasons: Vec::new(),
        affected_targets: Vec::new(),
        native_tool_hints: Vec::new(),
        offered_scopes: vec![crate::approval::store::Scope::Once.as_str().to_string()],
        policy_cap: Some(crate::approval::store::Scope::Once.as_str().to_string()),
    };
    match approver
        .approve_sandbox_escalation(command, confined_exit, confined_stderr, None, Some(detail))
        .await?
    {
        crate::approval::SandboxEscalationApproval::RunUnconfinedOnce => {
            Box::pin(crate::tools::bash::rerun_escalated_bash(args, ctx, None))
                .await
                .map(Some)
        }
        crate::approval::SandboxEscalationApproval::NoninteractiveDeny => Ok(Some(
            ToolOutput::text(crate::approval::NONINTERACTIVE_RUN_DENIAL),
        )),
        crate::approval::SandboxEscalationApproval::Deny
        | crate::approval::SandboxEscalationApproval::GrantAndRetryConfined { .. } => Ok(None),
    }
}

/// The combined outcome of one shell run.
struct ShellOutcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i32,
    signaled: bool,
    success: bool,
}

/// Internal run result, distinguishing the abort paths from a completed
/// run so the caller can early-return the right marker.
enum RunOutcome {
    Done(ShellOutcome),
    Cancelled,
    TimedOut,
    SpawnError(std::io::Error),
    WaitError(std::io::Error),
}

/// Render the model-facing body from a finished run, prepending a
/// one-time platform notice when present.
///
/// When `compress` is set (the `shell compression` setting is enabled for
/// the session), stdout and stderr are each run through the native rtk-style
/// compression filter ([`crate::tools::shell_compress::compress_stream`])
/// before the body is assembled. The `command` is passed so the filter can
/// apply a per-command strategy. The `exit:` line is always appended outside
/// the filter so the failure signal is never compressed away.
///
/// `tip`, when `Some`, is the defensive-mode routing nudge: ONE terse line
/// appended after the `exit:` line — outside compression, so it is never
/// stripped — steering the model to the dedicated tool that replaces the file/
/// search command it just ran (`defensive-tool-routing-behavioral-
/// nudge.md`). `None` in normal mode, for a non-file/search command, or once
/// the model has adopted the tool (self-suppression).
fn render_output(
    o: &ShellOutcome,
    notice: Option<&str>,
    compress: bool,
    command: &str,
    cwd: &Path,
    tip: Option<crate::tools::shell_compress::BashTip>,
    native_write_hint: Option<&str>,
) -> String {
    let stdout_raw = String::from_utf8_lossy(&o.stdout);
    let stderr_raw = String::from_utf8_lossy(&o.stderr);
    let (stdout, stderr): (std::borrow::Cow<str>, std::borrow::Cow<str>) = if compress {
        (
            std::borrow::Cow::Owned(crate::tools::shell_compress::compress_stream(
                command,
                &stdout_raw,
            )),
            std::borrow::Cow::Owned(crate::tools::shell_compress::compress_stream(
                command,
                &stderr_raw,
            )),
        )
    } else {
        (stdout_raw, stderr_raw)
    };
    let missing_binary = missing_binary_from_shell_failure(o.exit, &stderr);
    let mut body = format_combined(&stdout, &stderr, o.exit, o.signaled);
    if !o.success {
        let exit_status = if o.signaled {
            "signaled".to_string()
        } else {
            o.exit.to_string()
        };
        body.push_str(&cockpit_command_environment_block(
            command,
            cwd,
            Some(&exit_status),
            None,
            missing_binary.as_deref(),
        ));
    }
    // Defensive-mode routing nudge: after the `exit:` line, outside the
    // compression filter, so it always survives and reads as metadata.
    if let Some(tip) = tip {
        body.push_str(tip.line());
        body.push('\n');
    }
    if let Some(hint) = native_write_hint {
        body.push_str("--- hint(shell_write_native_tool): ");
        body.push_str(hint);
        body.push('\n');
    }
    match notice {
        Some(n) => format!("{n}\n{body}"),
        None => body,
    }
}

fn render_spawn_error(command: &str, cwd: &Path, error: &std::io::Error) -> String {
    let missing = if error.kind() == std::io::ErrorKind::NotFound {
        Some("sh")
    } else {
        None
    };
    let mut out = format!("Error: could not start cockpit shell: {error}\n");
    out.push_str(&cockpit_command_environment_block(
        command,
        cwd,
        None,
        Some(&error.to_string()),
        missing,
    ));
    out
}

#[derive(Debug, Clone, Default)]
struct ResourcePlan {
    enabled: bool,
    declared: BTreeMap<String, u32>,
    policy: BTreeMap<String, u32>,
    reviewer: BTreeMap<String, u32>,
    effective: BTreeMap<String, u32>,
    queue_timeout_ms: Option<u64>,
}

fn parse_resource_requirements(value: Option<&Value>) -> Result<BTreeMap<String, u32>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let Some(object) = value.as_object() else {
        return Err(crate::engine::tool::invalid_input(
            "`resources` must be an object of resource name to permit count",
        ));
    };
    let mut resources = BTreeMap::new();
    for (name, count) in object {
        let Some(count) = count.as_u64() else {
            return Err(crate::engine::tool::invalid_input(format!(
                "`resources.{name}` must be a non-negative integer"
            )));
        };
        let count = u32::try_from(count).map_err(|_| {
            crate::engine::tool::invalid_input(format!("`resources.{name}` is too large"))
        })?;
        if count > 0 {
            resources.insert(name.clone(), count);
        }
    }
    Ok(resources)
}

fn build_resource_plan(
    declared: BTreeMap<String, u32>,
    config: &crate::config::extended::ResourceSchedulerConfig,
    command: &str,
    classification: &crate::approval::classify::Classification,
    queue_timeout_ms: Option<u64>,
) -> ResourcePlan {
    if !config.enabled {
        return ResourcePlan {
            enabled: false,
            declared,
            queue_timeout_ms,
            ..ResourcePlan::default()
        };
    }
    let policy = policy_resource_requirements(config, command, classification);
    let reviewer = BTreeMap::new();
    let mut effective = BTreeMap::new();
    merge_requirements(&mut effective, &declared);
    merge_requirements(&mut effective, &policy);
    merge_requirements(&mut effective, &reviewer);
    ResourcePlan {
        enabled: true,
        declared,
        policy,
        reviewer,
        effective,
        queue_timeout_ms,
    }
}

fn policy_resource_requirements(
    config: &crate::config::extended::ResourceSchedulerConfig,
    command: &str,
    classification: &crate::approval::classify::Classification,
) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for rule in &config.rules {
        if resource_rule_matches(rule, command, classification) {
            merge_requirements(&mut out, &rule.resources);
        }
    }
    out
}

fn resource_rule_matches(
    rule: &crate::config::extended::ResourceSchedulerRuleConfig,
    command: &str,
    classification: &crate::approval::classify::Classification,
) -> bool {
    let has_structured =
        rule.program.is_some() || rule.subcommand.is_some() || rule.approval_key.is_some();
    let structured = has_structured
        && classification.simple_commands().iter().any(|simple| {
            rule.program
                .as_ref()
                .is_none_or(|program| program == &simple.normalized_program)
                && rule
                    .subcommand
                    .as_ref()
                    .is_none_or(|sub| simple.subcommand.as_ref() == Some(sub))
                && rule
                    .approval_key
                    .as_ref()
                    .is_none_or(|key| key == &simple.key.as_storage_str())
        });
    if structured {
        return true;
    }
    rule.regex
        .as_ref()
        .and_then(|pattern| regex::Regex::new(pattern).ok())
        .is_some_and(|regex| regex.is_match(command))
}

fn merge_requirements(target: &mut BTreeMap<String, u32>, source: &BTreeMap<String, u32>) {
    for (name, count) in source {
        target
            .entry(name.clone())
            .and_modify(|existing| *existing = (*existing).max(*count))
            .or_insert(*count);
    }
}

async fn acquire_resource_lease(
    ctx: &ToolCtx,
    plan: &ResourcePlan,
    sandbox: &crate::engine::tool::SandboxMeta,
) -> std::result::Result<(Option<ResourceMeta>, Option<ResourceLeaseGuard>), ToolOutput> {
    if !plan.enabled || plan.effective.is_empty() {
        return Ok((None, None));
    }
    let Some(scheduler) = ctx.resource_scheduler.as_ref() else {
        return Ok((None, None));
    };

    let queued_at_ms = chrono::Utc::now().timestamp_millis();
    let mut meta = ResourceMeta {
        declared: plan.declared.clone(),
        policy: plan.policy.clone(),
        reviewer: plan.reviewer.clone(),
        effective: plan.effective.clone(),
        scheduler_request_id: None,
        scheduler_display_id: None,
        lease_id: None,
        queue_position: None,
        queue_timeout_ms: plan.queue_timeout_ms,
        queued_at_ms: Some(queued_at_ms),
        acquired_at_ms: None,
        wait_ms: None,
        acquired: false,
        released_on_drop: true,
        error: None,
    };

    let resources =
        crate::engine::resource_scheduler::ResourceRequirements::new(plan.effective.clone());
    let request = crate::engine::resource_scheduler::ResourceAcquireRequest {
        resources: resources.clone(),
        metadata: crate::engine::resource_scheduler::ResourceRequestMetadata {
            session_id: Some(ctx.session.id),
            agent_id: Some(ctx.agent_id.clone()),
            command_label: Some("bash".to_string()),
            declared_requirements: crate::engine::resource_scheduler::ResourceRequirements::new(
                plan.declared.clone(),
            ),
            policy_requirements: crate::engine::resource_scheduler::ResourceRequirements::new(
                plan.policy.clone(),
            ),
            reviewer_requirements: crate::engine::resource_scheduler::ResourceRequirements::new(
                plan.reviewer.clone(),
            ),
            effective_requirements: resources,
            ..crate::engine::resource_scheduler::ResourceRequestMetadata::default()
        },
    };

    let ticket = match scheduler.submit(request) {
        Ok(ticket) => ticket,
        Err(error) => {
            meta.error = Some(error.to_string());
            return Err(ToolOutput::text(resource_acquire_error_message(&error))
                .with_bash_meta(sandbox.clone(), &Some(meta)));
        }
    };
    let request_id = ticket.request_id();
    let display_id = ticket.display_id().to_string();
    meta.scheduler_request_id = Some(request_id.to_string());
    meta.scheduler_display_id = Some(display_id.clone());
    meta.queue_position = scheduler
        .snapshot()
        .queued
        .iter()
        .position(|entry| entry.id == request_id)
        .map(|pos| pos + 1);
    if meta.queue_position.is_some()
        && let Some(tx) = ctx.events.as_ref()
    {
        let _ = tx.try_send(TurnEvent::ResourceWait {
            agent: ctx.agent_id.clone(),
            request_id,
            display_id: display_id.clone(),
            resources: plan.effective.clone().into_iter().collect(),
            queue_position: meta.queue_position,
            command_label: Some("bash".to_string()),
        });
    }

    let wait = ticket.wait(&ctx.cancel);
    let lease = if let Some(timeout_ms) = plan.queue_timeout_ms {
        match tokio::time::timeout(Duration::from_millis(timeout_ms), wait).await {
            Ok(Ok(lease)) => lease,
            Ok(Err(error)) => {
                meta.error = Some(error.to_string());
                return Err(ToolOutput::text(resource_acquire_error_message(&error))
                    .with_bash_meta(sandbox.clone(), &Some(meta)));
            }
            Err(_) => {
                meta.error = Some(format!(
                    "resource scheduler queue timeout after {timeout_ms} ms"
                ));
                return Err(ToolOutput::text(format!(
                    "Error: resource scheduler queue timeout after {timeout_ms} ms"
                ))
                .with_bash_meta(sandbox.clone(), &Some(meta)));
            }
        }
    } else {
        match wait.await {
            Ok(lease) => lease,
            Err(error) => {
                meta.error = Some(error.to_string());
                return Err(ToolOutput::text(resource_acquire_error_message(&error))
                    .with_bash_meta(sandbox.clone(), &Some(meta)));
            }
        }
    };

    let acquired_at_ms = chrono::Utc::now().timestamp_millis();
    meta.acquired = true;
    meta.acquired_at_ms = Some(acquired_at_ms);
    meta.wait_ms = acquired_at_ms.saturating_sub(queued_at_ms).try_into().ok();
    meta.lease_id = Some(lease.request_id().to_string());
    let wait_ms = meta.wait_ms.unwrap_or(0);
    if let Some(tx) = ctx.events.as_ref() {
        let _ = tx.try_send(TurnEvent::ResourceStart {
            agent: ctx.agent_id.clone(),
            request_id,
            display_id: display_id.clone(),
            resources: plan.effective.clone().into_iter().collect(),
            wait_ms,
            command_label: Some("bash".to_string()),
        });
    }
    let guard = ResourceLeaseGuard {
        _lease: lease,
        event_tx: ctx.events.clone(),
        agent: ctx.agent_id.clone(),
        request_id,
        display_id,
        resources: plan.effective.clone().into_iter().collect(),
        command_label: Some("bash".to_string()),
    };
    Ok((Some(meta), Some(guard)))
}

struct ResourceLeaseGuard {
    _lease: crate::engine::resource_scheduler::ResourceLease,
    event_tx: Option<tokio::sync::mpsc::Sender<TurnEvent>>,
    agent: String,
    request_id: uuid::Uuid,
    display_id: String,
    resources: std::collections::HashMap<String, u32>,
    command_label: Option<String>,
}

impl Drop for ResourceLeaseGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.event_tx.as_ref() {
            let _ = tx.try_send(TurnEvent::ResourceClear {
                agent: self.agent.clone(),
                request_id: self.request_id,
                display_id: self.display_id.clone(),
                resources: self.resources.clone(),
                command_label: self.command_label.clone(),
            });
        }
    }
}

fn resource_acquire_error_message(
    error: &crate::engine::resource_scheduler::ResourceAcquireError,
) -> String {
    match error {
        crate::engine::resource_scheduler::ResourceAcquireError::OverCapacity {
            pool,
            requested,
            capacity,
        } => format!(
            "Error: requested resources exceed scheduler capacity ({pool} requested {requested}, capacity {capacity})"
        ),
        crate::engine::resource_scheduler::ResourceAcquireError::QueueFull { max_queued } => {
            format!("Error: resource scheduler queue is full ({max_queued} waiting); retry later")
        }
        crate::engine::resource_scheduler::ResourceAcquireError::Cancelled => {
            "Error: command cancelled while waiting for resource scheduler permits".to_string()
        }
        crate::engine::resource_scheduler::ResourceAcquireError::UnknownPool { pool } => {
            format!("Error: unknown resource scheduler pool `{pool}`")
        }
    }
}

fn cockpit_command_environment_block(
    command: &str,
    cwd: &Path,
    exit_status: Option<&str>,
    spawn_error: Option<&str>,
    missing_binary: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str("cockpit_command_environment:\n");
    out.push_str(&format!("attempted_command: {command}\n"));
    out.push_str(&format!("cwd: {}\n", cwd.display()));
    if let Some(status) = exit_status {
        out.push_str(&format!("exit_code: {status}\n"));
    }
    if let Some(error) = spawn_error {
        out.push_str(&format!("spawn_error: {error}\n"));
    }
    if let Some(binary) = missing_binary {
        out.push_str(&format!("missing_binary: {binary}\n"));
        out.push_str(&format!(
            "diagnostic: `{binary}` was not found in cockpit's command environment (PATH inherited from cockpit launch); this does not establish that it is absent from the host system.\n"
        ));
    } else {
        out.push_str(
            "diagnostic: failure occurred while running in cockpit's command environment.\n",
        );
    }
    out
}

fn missing_binary_from_shell_failure(exit: i32, stderr: &str) -> Option<String> {
    if exit != 127 {
        return None;
    }
    let first = stderr.lines().find_map(binary_from_not_found_line)?;
    let cleaned = first.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
    if cleaned.is_empty() || cleaned.contains('/') || cleaned.contains(char::is_whitespace) {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn binary_from_not_found_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    for needle in [": not found", ": command not found"] {
        if let Some(prefix) = trimmed.strip_suffix(needle)
            && let Some((_, binary)) = prefix.rsplit_once(':')
        {
            return Some(binary.trim());
        }
    }
    None
}

fn bash_output_sidecar(
    command: &str,
    cwd: &Path,
    outcome: &ShellOutcome,
    rendered_output: &str,
    truncated_for_display: bool,
) -> Option<ToolOutputSidecar> {
    if !truncated_for_display && !looks_like_build_test_check(command) {
        return None;
    }
    let stdout = String::from_utf8_lossy(&outcome.stdout).to_string();
    let stderr = String::from_utf8_lossy(&outcome.stderr).to_string();
    Some(ToolOutputSidecar {
        payload: serde_json::json!({
            "kind": "bash_output",
            "command": command,
            "cwd": cwd.to_string_lossy(),
            "exit_code": if outcome.signaled { serde_json::Value::Null } else { serde_json::json!(outcome.exit) },
            "signaled": outcome.signaled,
            "success": outcome.success,
            "stdout": stdout,
            "stderr": stderr,
            "rendered_output": rendered_output,
            "display": {
                "cap_bytes": OUTPUT_BYTE_CAP,
                "truncated": truncated_for_display,
                "rendered_bytes": rendered_output.len(),
            },
        }),
    })
}

fn looks_like_build_test_check(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    [
        "cargo test",
        "cargo build",
        "cargo check",
        "cargo clippy",
        "npm test",
        "npm run build",
        "pnpm test",
        "pnpm build",
        "pnpm check",
        "yarn test",
        "yarn build",
        "go test",
        "go build",
        "pytest",
        "mvn test",
        "gradle test",
        "make test",
        "make check",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[allow(clippy::too_many_arguments)]
async fn run_container_bash(
    display_command: &str,
    command: &str,
    cwd: &std::path::Path,
    timeout_ms: u64,
    session_env: &std::collections::HashMap<String, String>,
    scrub: &[(String, String)],
    extended_config: &crate::config::extended::ExtendedConfig,
    command_resource_plan: &crate::tools::command_resource_profiles::CommandResourcePlan,
    resource_plan: &ResourcePlan,
    ctx: &ToolCtx,
) -> Result<ToolOutput> {
    let mode = ctx.session.sandbox_mode();
    let mut meta = crate::engine::tool::SandboxMeta {
        enabled: true,
        confined: true,
        escalated: false,
        broad_grant_simple_commands: false,
        approval_scope_recorded: None,
        unavailable_reason: None,
        resource_profiles: command_resource_plan.metas.clone(),
    };
    let (resource_meta, _resource_lease) =
        match acquire_resource_lease(ctx, resource_plan, &meta).await {
            Ok(acquired) => acquired,
            Err(output) => return Ok(output),
        };
    let attempt = run_container_shell(
        command,
        cwd,
        mode,
        session_env,
        scrub,
        extended_config,
        command_resource_plan,
        ctx,
        timeout_ms,
    )
    .await;
    let final_outcome = match attempt {
        RunOutcome::Cancelled => {
            return Ok(ToolOutput::truncated_text(
                "Error: command cancelled by user (ctrl+c)".to_string(),
            )
            .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::TimedOut => {
            return Ok(ToolOutput::truncated_text(format!(
                "Error: timeout after {timeout_ms} ms{}",
                crate::tools::command_resource_profiles::resource_profile_context(
                    command_resource_plan
                )
            ))
            .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::SpawnError(e) => {
            meta.unavailable_reason = Some(e.to_string());
            let mut message = format!(
                "Error: container sandbox command refused ({e}); fix the container runtime/Dockerfile or switch sandbox modes with `/sandbox off` or `/sandbox on`."
            );
            message.push_str(
                &crate::tools::command_resource_profiles::resource_profile_context(
                    command_resource_plan,
                ),
            );
            return Ok(ToolOutput::text(message).with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::WaitError(e) => {
            return Ok(ToolOutput::text(format!(
                "Error: the container command failed to run ({e}); fix the runtime or switch sandbox modes"
            ))
            .with_bash_meta(meta, &resource_meta));
        }
        RunOutcome::Done(o) => o,
    };
    Ok(render_bash_outcome(
        display_command,
        cwd,
        final_outcome,
        None,
        ctx,
        meta,
        &resource_meta,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_container_shell(
    command: &str,
    cwd: &std::path::Path,
    mode: crate::tools::sandbox_mode::SandboxMode,
    session_env: &std::collections::HashMap<String, String>,
    scrub: &[(String, String)],
    extended_config: &crate::config::extended::ExtendedConfig,
    command_resource_plan: &crate::tools::command_resource_profiles::CommandResourcePlan,
    ctx: &ToolCtx,
    timeout_ms: u64,
) -> RunOutcome {
    let manager = crate::container::container_manager()
        .get_or_init(|| async { crate::container::ContainerManager::detect() })
        .await;
    if let Err(reason) = manager.ensure_available() {
        return RunOutcome::SpawnError(std::io::Error::other(reason));
    }
    let map = crate::container::MountMap::for_current_platform(ctx.cwd.clone());
    let Some(container_cwd) = map.to_container(cwd) else {
        return RunOutcome::SpawnError(std::io::Error::other(format!(
            "working directory {} is outside the container project mount {}",
            cwd.display(),
            ctx.cwd.display()
        )));
    };
    let resolved = match crate::container::resolve_dockerfile_for_session(
        &ctx.cwd,
        &extended_config.sandbox,
    ) {
        Ok(resolved) => resolved,
        Err(e) => return RunOutcome::SpawnError(std::io::Error::other(e.to_string())),
    };
    let dockerfile_bytes = match std::fs::read(&resolved.path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return RunOutcome::SpawnError(std::io::Error::other(format!(
                "reading sandbox Dockerfile {} failed: {e}",
                resolved.path.display()
            )));
        }
    };
    let image = match manager
        .ensure_image(&resolved.path, &dockerfile_bytes)
        .await
    {
        Ok(image) => image,
        Err(e) => return RunOutcome::SpawnError(std::io::Error::other(e.to_string())),
    };
    let profile_mounts =
        crate::container::resource_profile_mounts(command_resource_plan, &map, cfg!(windows));
    let name = match manager
        .ensure_container(
            ctx.session.id,
            &image,
            mode,
            &map,
            &profile_mounts,
            ctx.session.container_network_enabled(),
        )
        .await
    {
        Ok(name) => name,
        Err(e) => return RunOutcome::SpawnError(std::io::Error::other(e.to_string())),
    };
    let env = crate::container::container_env(session_env, scrub);
    let cmd = match manager.exec_command(&name, &container_cwd, &env, command) {
        Ok(cmd) => cmd,
        Err(e) => return RunOutcome::SpawnError(std::io::Error::other(e.to_string())),
    };
    run_prepared_command(cmd, ctx, timeout_ms).await
}

fn render_bash_outcome(
    command: &str,
    cwd: &std::path::Path,
    final_outcome: ShellOutcome,
    windows_notice: Option<&'static str>,
    ctx: &ToolCtx,
    meta: crate::engine::tool::SandboxMeta,
    resource_meta: &Option<ResourceMeta>,
) -> ToolOutput {
    let compress = ctx.session.shell_compression_enabled();
    let tip = if matches!(ctx.llm_mode, crate::config::extended::LlmMode::Defensive) {
        crate::tools::shell_compress::classify_tip(command)
            .filter(|t| !ctx.session.tip_suppressed(*t))
    } else {
        None
    };
    let native_write_hint = durable_shell_write_hint(command);
    let body = render_output(
        &final_outcome,
        windows_notice,
        compress,
        command,
        cwd,
        tip,
        native_write_hint,
    );
    let exit_field = if final_outcome.signaled {
        None
    } else {
        Some(final_outcome.exit)
    };
    let truncated_for_display = body.len() > OUTPUT_BYTE_CAP;
    let sidecar = bash_output_sidecar(command, cwd, &final_outcome, &body, truncated_for_display);
    let mut out = if truncated_for_display {
        ToolOutput::truncated_text(truncate_head_tail(&body, OUTPUT_BYTE_CAP))
            .with_bash_meta(meta, resource_meta)
    } else {
        ToolOutput::text(body).with_bash_meta(meta, resource_meta)
    };
    if let Some(sidecar) = sidecar {
        out = out.with_output_sidecar(sidecar);
    }
    match exit_field {
        Some(code) => out.with_exit_code(code),
        None => out,
    }
}

/// Spawn `sh -c <command>` — confined via zerobox when `confine`, else
/// plain — apply the process-group + kill-on-drop + cancel/timeout/
/// pgid-kill logic (identical for both paths), and return the outcome.
///
/// Building the confined child via `Sandbox::...prepare().into_command()`
/// (not `.run()`/`.spawn()`) is what lets us keep pgid control through
/// the sandbox: we own the `tokio::process::Command` and apply the same
/// `process_group(0)` + `kill_on_drop` + `tokio::select!`(wait vs cancel
/// vs timeout) + negative-pgid kill the unsandboxed path uses.
#[allow(clippy::too_many_arguments)]
async fn run_shell(
    command: &str,
    cwd: &std::path::Path,
    confine: bool,
    tmp_dir: Option<&std::path::Path>,
    scrub: &[(String, String)],
    session_env: &std::collections::HashMap<String, String>,
    extra_sandbox_paths: &[crate::tools::shell_sandbox::ExtraSandboxPath],
    ctx: &ToolCtx,
    timeout_ms: u64,
) -> RunOutcome {
    let mut cmd = if confine {
        match crate::tools::shell_sandbox::build_sandboxed_command(
            command,
            cwd,
            tmp_dir,
            scrub,
            session_env,
            extra_sandbox_paths,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                // A policy-validation failure (e.g. unusable cwd) is a
                // spawn error to the model — never a silent downgrade to
                // unconfined.
                return RunOutcome::SpawnError(std::io::Error::other(format!(
                    "sandbox setup failed: {e}"
                )));
            }
        }
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.arg("-c")
            .arg(command)
            .current_dir(cwd)
            .env_clear()
            .envs(session_env);
        for (k, _v) in scrub {
            c.env_remove(k);
        }
        c
    };

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // If this future is dropped (e.g. the worker task is torn down)
        // the immediate child dies too — a leaked subprocess would
        // outlive its turn. The process-group kill below handles the
        // descendant tree on an explicit ctrl+c cancel.
        .kill_on_drop(true);
    // Unix: put the child in its own process group so a cancel can kill
    // the whole tree (the `sh -c` plus anything it spawned — a test
    // runner, a `make`, …), not just the immediate shell. We signal the
    // negative pgid below. `tokio::process::Command::process_group` is
    // the inherent wrapper over the `CommandExt` setting. Windows has no
    // process groups; we fall back to `Child::kill` on cancel. This is
    // applied identically whether or not the command was confined —
    // zerobox handed us a plain `tokio::process::Command`.
    #[cfg(unix)]
    cmd.process_group(0);

    run_prepared_command(cmd, ctx, timeout_ms).await
}

async fn run_prepared_command(
    mut cmd: tokio::process::Command,
    ctx: &ToolCtx,
    timeout_ms: u64,
) -> RunOutcome {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return RunOutcome::SpawnError(e),
    };
    let child_pid = child.id();

    use tokio::io::AsyncReadExt;
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(pipe) = stdout_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(pipe) = stderr_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });

    let timeout = std::time::Duration::from_millis(timeout_ms);
    let status = tokio::select! {
        biased;
        _ = ctx.cancel.cancelled() => {
            kill_child(&mut child, child_pid).await;
            stdout_task.abort();
            stderr_task.abort();
            return RunOutcome::Cancelled;
        }
        res = tokio::time::timeout(timeout, child.wait()) => match res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return RunOutcome::WaitError(e),
            Err(_) => {
                kill_child(&mut child, child_pid).await;
                stdout_task.abort();
                stderr_task.abort();
                return RunOutcome::TimedOut;
            }
        },
    };

    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    let exit = status.code().unwrap_or(-1);
    let signaled = !status.success() && status.code().is_none();

    RunOutcome::Done(ShellOutcome {
        stdout,
        stderr,
        exit,
        signaled,
        success: status.success(),
    })
}

/// Terminate a cancelled `bash` child.
async fn kill_child(child: &mut tokio::process::Child, pid: Option<u32>) {
    crate::process::terminate_group_async(child, pid, std::time::Duration::from_millis(200)).await;
}

fn format_combined(stdout: &str, stderr: &str, exit: i32, signaled: bool) -> String {
    let mut out = String::new();
    if !stdout.is_empty() {
        out.push_str("stdout:\n");
        out.push_str(stdout);
        if !stdout.ends_with('\n') {
            out.push('\n');
        }
    }
    if !stderr.is_empty() {
        out.push_str("stderr:\n");
        out.push_str(stderr);
        if !stderr.ends_with('\n') {
            out.push('\n');
        }
    }
    if signaled {
        out.push_str("exit: signaled\n");
    } else {
        out.push_str(&format!("exit: {exit}\n"));
        // Both streams empty collapses to a bare `exit: N` line, which a weak
        // model misreads as a failure it caused. Annotate the void case with
        // one terse metadata line naming the result as complete (not
        // truncated); neutral on nonzero (e.g. grep/diff exit 1 = "no
        // match"/"differs", a valid answer — never labelled an error).
        if stdout.is_empty() && stderr.is_empty() {
            if exit == 0 {
                out.push_str(
                    "(no output — command succeeded and produced nothing; complete result)\n",
                );
            } else {
                out.push_str(&format!(
                    "(no output — command exited {exit} with nothing on stdout/stderr)\n"
                ));
            }
        }
    }
    out
}

/// The one-time per-process "shell sandboxing unavailable on Windows"
/// notice (sandboxing part 2). Returns `Some(...)` at most once, and only
/// when the session wanted sandboxing on. A no-op (`None`) on every other
/// platform.
#[cfg(windows)]
fn windows_shell_notice(ctx: &ToolCtx) -> Option<&'static str> {
    if ctx.session.sandbox_enabled()
        && !WINDOWS_NOTICE_SHOWN.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        Some("Note: shell sandboxing is unavailable on Windows; commands run unconfined.")
    } else {
        None
    }
}

#[cfg(not(windows))]
fn windows_shell_notice(_ctx: &ToolCtx) -> Option<&'static str> {
    None
}

/// The env-scrub list from plan §3c, as `(key, "")` pairs.
///
/// Returned as a list so both run paths apply it identically: the
/// unconfined path `env_remove`s each key, and the sandboxed path passes
/// the same keys to zerobox as empty-value `env` overrides (which clears
/// them in the confined child's environment, since zerobox builds the
/// child env from a filtered inherit + our overrides). The value is the
/// empty string for the override form; the key alone is what the
/// unconfined path removes.
fn scrub_overrides(
    session_env: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    session_env
        .keys()
        .cloned()
        .chain([
            "BASH_ENV".to_string(),
            "ENV".to_string(),
            "PROMPT_COMMAND".to_string(),
            "NODE_OPTIONS".to_string(),
            "SHELLOPTS".to_string(),
            "BASHOPTS".to_string(),
            "GREP_OPTIONS".to_string(),
            "GREP_COLORS".to_string(),
            "AWS_ACCESS_KEY_ID".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
        ])
        .filter(|k| crate::redact::env_scrub_patterns(k))
        .map(|k| (k, String::new()))
        .collect()
}

/// Platform-independent unit tests for the run-fail-escalate gate
/// (sandboxing part 2).
#[cfg(test)]
mod sandbox_escalation_signal_tests {
    use super::*;

    fn failed(stderr: &'static [u8]) -> ShellOutcome {
        ShellOutcome {
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
            exit: 1,
            signaled: false,
            success: false,
        }
    }

    #[test]
    fn fake_permission_stderr_does_not_offer_unconfined_rerun() {
        let outcome = failed(b"cat: /etc/secret: Permission denied\n");
        let mut meta = crate::engine::tool::SandboxMeta {
            enabled: true,
            confined: true,
            escalated: false,
            broad_grant_simple_commands: false,
            approval_scope_recorded: None,
            unavailable_reason: None,
            resource_profiles: Vec::new(),
        };

        if confined_failure_escalation_offer(&outcome).is_some() {
            meta.escalated = true;
        }

        assert!(!meta.escalated);
        assert!(confined_failure_escalation_offer(&outcome).is_none());
    }

    #[test]
    fn fake_readonly_stderr_from_write_target_does_not_offer_rerun() {
        let outcome = failed(b"sh: cannot create outside.txt: Read-only file system\n");

        assert!(confined_failure_escalation_offer(&outcome).is_none());
    }

    #[test]
    fn sandbox_failure_without_trusted_signal_keeps_actionable_result() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = failed(b"touch: cannot touch '/outside': Read-only file system\n");
        let body = render_output(
            &outcome,
            None,
            false,
            "touch /outside",
            tmp.path(),
            None,
            None,
        );

        assert!(confined_failure_escalation_offer(&outcome).is_none());
        assert!(body.contains("Read-only file system"));
        assert!(body.contains("exit: 1"));
    }
}

/// Windows-only: the shell-sandbox notice fires at most once per process
/// and only when the session wanted sandboxing on (sandboxing part 2).
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_notice_fires_once_then_silent() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        // test_ctx defaults sandbox OFF → no notice.
        assert!(windows_shell_notice(&ctx).is_none());
        // With sandbox requested ON, the notice fires once, then the
        // one-shot guard silences it (process-global).
        ctx.session.set_sandbox_enabled(true);
        let first = windows_shell_notice(&ctx);
        let second = windows_shell_notice(&ctx);
        // Exactly one of the two is `Some` (whichever observed the guard
        // first); the other is `None`. (Other tests in this binary may
        // have tripped the guard already, so we assert "at most one.")
        assert!(first.is_none() || second.is_none());
        // And shell sandboxing is reported unsupported on Windows.
        assert!(!crate::tools::shell_sandbox::shell_sandbox_supported());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    fn wait_for_file(path: &std::path::Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {}", path.display());
    }

    #[test]
    fn build_test_check_commands_get_output_sidecars() {
        let outcome = ShellOutcome {
            stdout: b"full stdout".to_vec(),
            stderr: b"full stderr".to_vec(),
            exit: 1,
            signaled: false,
            success: false,
        };
        let sidecar = bash_output_sidecar(
            "cargo test --workspace",
            Path::new("/repo"),
            &outcome,
            "stderr:\nshort\nexit: 1\n",
            false,
        )
        .expect("build/test command gets sidecar even when display is not truncated");
        assert_eq!(sidecar.payload["command"], "cargo test --workspace");
        assert_eq!(sidecar.payload["stdout"], "full stdout");
        assert_eq!(sidecar.payload["stderr"], "full stderr");
        assert_eq!(sidecar.payload["display"]["truncated"], false);
    }

    #[test]
    fn bash_description_mentions_cap_and_tmpdir_redirection() {
        let tool = BashTool::new();
        assert!(tool.description().contains("capped at 8 KB"));
        assert!(tool.description().contains("declare resources"));
        assert!(tool.description().contains("$TMPDIR"));
        let defensive = tool.defensive_description().unwrap();
        assert!(defensive.contains("declare `resources`"));
        assert!(defensive.contains("Display output caps at 8 KB"));
        assert!(defensive.contains("$TMPDIR"));
        assert!(defensive.contains("persistent workspace artifact"));
    }

    /// A turn-cancel (ctrl+c) terminates a long-running `bash` command
    /// promptly — the tool returns the cancelled marker in well under the
    /// command's natural runtime — and the killed command's *descendant*
    /// (spawned in the same process group) dies too, so a runaway test
    /// runner can't outlive its turn.
    #[tokio::test]
    async fn cancel_kills_process_group_promptly() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let tool = BashTool::new();

        // A descendant subshell touches a heartbeat file every 100ms. If the
        // process group is killed, the heartbeat stops; if only the immediate
        // `sh -c` died, the descendant would keep updating it.
        let heartbeat = tmp.path().join("heartbeat");
        let hb = heartbeat.to_string_lossy().to_string();
        let command = format!("( while true; do touch '{hb}'; sleep 0.1; done ) & sleep 30",);

        let cancel = ctx.cancel.clone();
        // Fire the cancel shortly after the command starts.
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.cancel();
        });

        let start = Instant::now();
        let out = tool
            .call(serde_json::json!({ "command": command }), &ctx)
            .await
            .expect("bash call returns");
        let elapsed = start.elapsed();
        canceller.await.unwrap();

        // Returned promptly (well under the 30s sleep) with the cancel marker.
        assert!(
            elapsed < Duration::from_secs(5),
            "cancel should return promptly, took {elapsed:?}"
        );
        assert!(
            out.content.contains("cancelled by user"),
            "expected cancel marker, got: {}",
            out.content
        );

        // Give the SIGTERM→SIGKILL window time to land, then confirm the
        // descendant heartbeat has stopped (process group was killed).
        tokio::time::sleep(Duration::from_millis(600)).await;
        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating — process group was not killed"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_child_skips_grace_when_sigterm_reaps_child() {
        let tmp = tempfile::tempdir().unwrap();
        let ready = tmp.path().join("ready");
        let script = format!(
            "trap 'exit 0' TERM; touch '{}'; while true; do sleep 1; done",
            ready.display()
        );
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);

        let start = Instant::now();
        kill_child(&mut child, pid).await;

        assert!(
            start.elapsed() < Duration::from_millis(150),
            "clean SIGTERM exit should not wait out the grace timer"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_child_sends_sigkill_after_grace_when_sigterm_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let ready = tmp.path().join("ready");
        let script = format!(
            "trap '' TERM; touch '{}'; while true; do sleep 1; done",
            ready.display()
        );
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);

        let start = Instant::now();
        let mut killer = tokio::spawn(async move {
            kill_child(&mut child, pid).await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !killer.is_finished(),
            "SIGKILL should wait for the grace timer"
        );
        tokio::time::timeout(Duration::from_secs(2), &mut killer)
            .await
            .expect("SIGKILL fallback should reap the child")
            .unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(200),
            "SIGKILL fallback should honor the grace timer"
        );
    }

    // ---- shell compression setting (implementation note) -

    /// With shell compression ENABLED (the default once seeded), noisy bash
    /// output is compressed before it enters context — cargo-style progress
    /// (`Compiling …`) is stripped — while the error/warning diagnostics and
    /// the non-zero `exit:` line SURVIVE intact. The signal-preservation
    /// guarantee (priority #1) is the load-bearing assertion here.
    #[tokio::test]
    async fn compression_enabled_strips_noise_keeps_signal_and_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session
            .set_shell_compression(crate::config::extended::ShellCompression::Enabled);
        let tool = BashTool::new();
        // Emit cargo-shaped output then exit non-zero. The command line starts
        // with `cargo` so the per-command (rust) strategy is recognized.
        let script = "printf '%s\\n' \
            '   Compiling foo v0.1.0' \
            '   Compiling bar v0.2.0' \
            'warning: unused variable: x' \
            'error[E0382]: borrow of moved value' \
            '   Finished dev in 2.3s'; exit 2";
        let out = tool
            .call(
                serde_json::json!({ "command": format!("cargo build; {script}") }),
                &ctx,
            )
            .await
            .expect("bash call returns");
        let compressed_output = out
            .content
            .split("cockpit_command_environment:")
            .next()
            .unwrap_or(&out.content);
        // Noise stripped from command output. The environment diagnostic below
        // still echoes the exact attempted command, which may contain the same
        // words as shell-script arguments.
        assert!(
            !compressed_output.contains("Compiling foo"),
            "progress noise should be stripped, got: {}",
            out.content
        );
        assert!(!compressed_output.contains("Finished dev"));
        // Signal preserved.
        assert!(
            out.content.contains("error[E0382]"),
            "error diagnostic must survive, got: {}",
            out.content
        );
        assert!(out.content.contains("warning: unused variable"));
        // Non-zero exit context preserved.
        assert!(out.content.contains("exit: 2"), "got: {}", out.content);
    }

    /// With shell compression DISABLED, bash output is byte-for-byte the raw
    /// command output — no line is stripped, deduped, or collapsed.
    #[tokio::test]
    async fn compression_disabled_returns_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session
            .set_shell_compression(crate::config::extended::ShellCompression::Disabled);
        let tool = BashTool::new();
        let script = "printf '%s\\n' \
            '   Compiling foo v0.1.0' \
            '   Compiling bar v0.2.0' \
            'warning: unused variable: x' \
            'error[E0382]: borrow of moved value' \
            '   Finished dev in 2.3s'";
        let out = tool
            .call(
                serde_json::json!({ "command": format!("cargo build; {script}") }),
                &ctx,
            )
            .await
            .expect("bash call returns");
        // Verbatim: even the progress noise is present unchanged.
        assert!(out.content.contains("Compiling foo v0.1.0"));
        assert!(out.content.contains("Compiling bar v0.2.0"));
        assert!(out.content.contains("Finished dev in 2.3s"));
        assert!(out.content.contains("error[E0382]"));
    }

    /// The compression boundary is exactly the `shell_compression_enabled`
    /// flag: the SAME command yields stripped output when enabled and
    /// verbatim output when disabled. Guards the toggle wiring end-to-end.
    #[tokio::test]
    async fn compression_toggle_changes_output() {
        let tmp = tempfile::tempdir().unwrap();
        let cmd = "cargo build; printf '   Compiling foo v0.1.0\\ndone\\n'";

        let ctx_on = crate::tools::common::test_ctx(tmp.path());
        ctx_on
            .session
            .set_shell_compression(crate::config::extended::ShellCompression::Enabled);
        let on = BashTool::new()
            .call(serde_json::json!({ "command": cmd }), &ctx_on)
            .await
            .unwrap();

        let ctx_off = crate::tools::common::test_ctx(tmp.path());
        ctx_off
            .session
            .set_shell_compression(crate::config::extended::ShellCompression::Disabled);
        let off = BashTool::new()
            .call(serde_json::json!({ "command": cmd }), &ctx_off)
            .await
            .unwrap();

        assert!(
            !on.content.contains("Compiling foo"),
            "enabled strips noise"
        );
        assert!(
            off.content.contains("Compiling foo"),
            "disabled keeps noise"
        );
        // Both keep the real content.
        assert!(on.content.contains("done"));
        assert!(off.content.contains("done"));
    }

    /// A normal (uncancelled) command still runs to completion and returns
    /// its output + exit line, AND the authoritative structured `exit_code`
    /// field (export-audit fidelity) matching the `exit: N` text.
    #[tokio::test]
    async fn normal_command_completes() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "printf hello" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(out.content.contains("hello"), "got: {}", out.content);
        assert!(out.content.contains("exit: 0"), "got: {}", out.content);
        // Structured exit code is the authoritative source, set to the same
        // value the human-readable line carries.
        assert_eq!(out.exit_code, Some(0));
    }

    /// A non-zero exit is reported on the structured `exit_code` field as well
    /// as the `exit: N` text line (export-audit fidelity, part c).
    #[tokio::test]
    async fn nonzero_exit_sets_structured_exit_code() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "exit 3" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(out.content.contains("exit: 3"), "got: {}", out.content);
        assert_eq!(out.exit_code, Some(3));
    }

    // ---- run-fail-escalate decision logic (sandboxing part 2) -------------

    use std::sync::Arc;

    use crate::approval::Approver;
    use crate::approval::ID_APPROVE_SESSION;
    use crate::approval::classify::SimpleCommandInfo;
    use crate::approval::store::{GrantStore, Scope};
    use crate::daemon::proto::ResolveResponse;

    /// Build a sandbox-enabled ctx with an approver + grant store.
    fn ctx_with_store(cwd: &std::path::Path) -> ToolCtx {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), cwd.to_path_buf(), "builder").unwrap();
        session.set_sandbox_enabled(true);
        let sid = session.id;
        let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
        let cfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, cwd).unwrap());
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let store = GrantStore::new(db.clone(), sid, cwd.to_path_buf());
        let approver = Arc::new(Approver::new(store, db, sid, "builder", hub.clone()));
        ToolCtx {
            agent_id: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::Normal,
            locks,
            session: Arc::new(session),
            cwd: cwd.to_path_buf(),
            redact,
            interrupts: hub,
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: Some(approver),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            root_agent_frame: true,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::new()),
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn scheduler(
        cpu: u32,
        memory: u32,
    ) -> Arc<crate::engine::resource_scheduler::ResourceScheduler> {
        let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
        cfg.pools.cpu.capacity = cpu;
        cfg.pools.memory.capacity = memory;
        Arc::new(crate::engine::resource_scheduler::ResourceScheduler::new(
            cfg,
        ))
    }

    #[test]
    fn user_path_grants_merge_into_sandbox_and_container_mount_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("repo");
        let read_dir = tmp.path().join("read-dir");
        let write_dir = tmp.path().join("write-dir");
        for dir in [&project, &read_dir, &write_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let ctx = ctx_with_store(&project);
        let store = GrantStore::new(ctx.session.db.clone(), ctx.session.id, ctx.cwd.clone());
        store
            .record_path(
                &read_dir,
                Scope::Session,
                crate::tools::shell_sandbox::SandboxPathAccess::Read,
            )
            .unwrap();
        store
            .record_path(
                &write_dir,
                Scope::Session,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            )
            .unwrap();

        let plan = command_resource_plan_with_user_grants(
            crate::tools::command_resource_profiles::CommandResourcePlan::default(),
            &ctx,
        );
        assert!(plan.allow_paths.iter().any(|path| {
            path.kind == "user_grant"
                && path.path == read_dir
                && path.access == crate::tools::shell_sandbox::SandboxPathAccess::Read
        }));
        assert!(plan.allow_paths.iter().any(|path| {
            path.kind == "user_grant"
                && path.path == write_dir
                && path.access == crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
        }));

        let map = crate::container::MountMap::unix(project);
        let mounts = crate::container::resource_profile_mounts(&plan, &map, false);
        assert!(
            mounts
                .iter()
                .any(|mount| mount.host == read_dir && mount.read_only)
        );
        assert!(
            mounts
                .iter()
                .any(|mount| mount.host == write_dir && !mount.read_only)
        );
    }

    fn ctx_with_scheduler(
        cwd: &std::path::Path,
        scheduler: Arc<crate::engine::resource_scheduler::ResourceScheduler>,
    ) -> ToolCtx {
        let mut ctx = crate::tools::common::test_ctx(cwd);
        ctx.resource_scheduler = Some(scheduler);
        ctx
    }

    #[test]
    fn resource_policy_matches_and_merges_by_max() {
        let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
        cfg.rules
            .push(crate::config::extended::ResourceSchedulerRuleConfig {
                approval_key: Some("cargo test".to_string()),
                resources: BTreeMap::from([("cpu".to_string(), 2), ("memory".to_string(), 1)]),
                ..crate::config::extended::ResourceSchedulerRuleConfig::default()
            });
        cfg.rules
            .push(crate::config::extended::ResourceSchedulerRuleConfig {
                regex: Some("--locked".to_string()),
                resources: BTreeMap::from([("cpu".to_string(), 1), ("memory".to_string(), 3)]),
                ..crate::config::extended::ResourceSchedulerRuleConfig::default()
            });
        let classification = crate::approval::classify::classify("cargo test --locked");
        let plan = build_resource_plan(
            BTreeMap::from([("cpu".to_string(), 1)]),
            &cfg,
            "cargo test --locked",
            &classification,
            Some(50),
        );
        assert_eq!(plan.effective.get("cpu"), Some(&2));
        assert_eq!(plan.effective.get("memory"), Some(&3));
        assert_eq!(plan.queue_timeout_ms, Some(50));
    }

    #[test]
    fn resource_policy_structured_fields_are_conjunctive() {
        let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
        cfg.rules
            .push(crate::config::extended::ResourceSchedulerRuleConfig {
                program: Some("cargo".to_string()),
                subcommand: Some("test".to_string()),
                resources: BTreeMap::from([("cpu".to_string(), 2)]),
                ..crate::config::extended::ResourceSchedulerRuleConfig::default()
            });
        cfg.rules
            .push(crate::config::extended::ResourceSchedulerRuleConfig {
                program: Some("npm".to_string()),
                subcommand: Some("build".to_string()),
                regex: Some("npm test".to_string()),
                resources: BTreeMap::from([("memory".to_string(), 1)]),
                ..crate::config::extended::ResourceSchedulerRuleConfig::default()
            });

        let cargo_test = crate::approval::classify::classify("cargo test --locked");
        assert_eq!(
            policy_resource_requirements(&cfg, "cargo test --locked", &cargo_test).get("cpu"),
            Some(&2)
        );

        let npm_test = crate::approval::classify::classify("npm test");
        let npm_policy = policy_resource_requirements(&cfg, "npm test", &npm_test);
        assert!(!npm_policy.contains_key("cpu"));
        assert_eq!(npm_policy.get("memory"), Some(&1));
    }

    #[tokio::test]
    async fn bash_without_effective_resources_bypasses_scheduler() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let out = BashTool::new()
            .call(serde_json::json!({ "command": "printf ok" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("ok"));
        assert!(out.resource.is_none());
    }

    #[tokio::test]
    async fn bash_resource_over_capacity_returns_model_error() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_scheduler(tmp.path(), scheduler(1, 1));
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "printf nope",
                    "resources": { "cpu": 2, "memory": 1 }
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            out.content
                .contains("requested resources exceed scheduler capacity")
        );
        assert_eq!(out.resource.unwrap().effective.get("cpu"), Some(&2));
    }

    #[tokio::test]
    async fn bash_queue_timeout_cancels_wait_without_spawning() {
        let tmp = tempfile::tempdir().unwrap();
        let scheduler = scheduler(1, 1);
        let hold = scheduler
            .acquire(
                crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                    crate::engine::resource_scheduler::ResourceRequirements::new([
                        ("cpu", 1),
                        ("memory", 1),
                    ]),
                ),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        let ctx = ctx_with_scheduler(tmp.path(), scheduler.clone());
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "touch should-not-exist",
                    "resources": { "cpu": 1, "memory": 1 },
                    "queue_timeout_ms": 10
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("resource scheduler queue timeout"));
        assert!(!tmp.path().join("should-not-exist").exists());
        assert!(scheduler.snapshot().queued.is_empty());
        drop(hold);
    }

    #[tokio::test]
    async fn bash_cancel_while_queued_removes_scheduler_request() {
        let tmp = tempfile::tempdir().unwrap();
        let scheduler = scheduler(1, 1);
        let _hold = scheduler
            .acquire(
                crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                    crate::engine::resource_scheduler::ResourceRequirements::new([
                        ("cpu", 1),
                        ("memory", 1),
                    ]),
                ),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        let ctx = ctx_with_scheduler(tmp.path(), scheduler.clone());
        ctx.cancel.cancel();
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "printf nope",
                    "resources": { "cpu": 1, "memory": 1 }
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("cancelled while waiting"));
        assert!(scheduler.snapshot().queued.is_empty());
    }

    #[tokio::test]
    async fn bash_runtime_timeout_starts_after_resource_acquire() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_scheduler(tmp.path(), scheduler(1, 1));
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "sleep 1",
                    "timeout_ms": 1,
                    "queue_timeout_ms": 1000,
                    "resources": { "cpu": 1, "memory": 1 }
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("timeout after 1 ms"));
        let meta = out.resource.unwrap();
        assert!(meta.acquired);
        assert!(meta.wait_ms.is_some());
    }

    async fn resolve_next_interrupt(
        db: crate::db::Db,
        sid: uuid::Uuid,
        hub: Arc<crate::engine::interrupt::InterruptHub>,
        selected_id: &'static str,
        exclude: Option<uuid::Uuid>,
    ) -> uuid::Uuid {
        let iid = loop {
            let open = db.list_open_interrupts(sid).unwrap();
            if let Some(row) = open.iter().find(|row| Some(row.interrupt_id) != exclude) {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert!(hub.resolve(
            iid,
            ResolveResponse::Single {
                selected_id: selected_id.into(),
            }
        ));
        iid
    }

    async fn approve_next_path_prompt(ctx: &ToolCtx) {
        resolve_next_interrupt(
            ctx.session.db.clone(),
            ctx.session.id,
            ctx.interrupts.clone(),
            ID_APPROVE_SESSION,
            None,
        )
        .await;
    }

    async fn deny_next_path_prompt(ctx: &ToolCtx) {
        let iid = loop {
            let open = ctx.session.db.list_open_interrupts(ctx.session.id).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert!(ctx.interrupts.resolve(iid, ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn bash_child_receives_session_env_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        ctx.env_overlay.write().unwrap().insert(
            "COCKPIT_REFRESH_TEST_VALUE".to_string(),
            "sk-session".to_string(),
        );
        let out = BashTool::new()
            .call(
                serde_json::json!({ "command": "printf '%s' \"$COCKPIT_REFRESH_TEST_VALUE\"" }),
                &ctx,
            )
            .await
            .expect("bash call returns");
        assert!(out.content.contains("sk-session"));
        assert!(out.content.contains("exit: 0"));
    }

    #[tokio::test]
    async fn bash_child_does_not_receive_aws_access_key_from_parent_env() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let previous = std::env::var("AWS_ACCESS_KEY_ID").ok();
        unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", "AKIATESTSECRET");
        }
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "if [ -z \"${AWS_ACCESS_KEY_ID+x}\" ]; then printf scrubbed; else printf '%s' \"$AWS_ACCESS_KEY_ID\"; fi"
                }),
                &ctx,
            )
            .await
            .expect("bash call returns");
        match previous {
            Some(value) => unsafe {
                std::env::set_var("AWS_ACCESS_KEY_ID", value);
            },
            None => unsafe {
                std::env::remove_var("AWS_ACCESS_KEY_ID");
            },
        }
        assert!(out.content.contains("scrubbed"), "{}", out.content);
        assert!(!out.content.contains("AKIATESTSECRET"), "{}", out.content);
    }

    #[test]
    fn command_directory_escape_detects_literal_absolute_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        let inside = root.join("file");
        std::fs::write(&inside, "ok").unwrap();
        assert_eq!(
            command_directory_escape("cat /etc/passwd", &root, &root, None).as_deref(),
            Some(Path::new("/etc/passwd"))
        );
        assert!(
            command_directory_escape(&format!("cat {}", inside.display()), &root, &root, None)
                .is_none()
        );
    }

    #[test]
    fn command_directory_escape_detects_relative_path_operands() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let cwd = root.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, "secret").unwrap();

        assert_eq!(
            command_directory_escape("cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn command_directory_escape_detects_quoted_relative_path_operands() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let cwd = root.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        let outside = tmp.path().join("outside secret");
        std::fs::write(&outside, "secret").unwrap();

        assert_eq!(
            command_directory_escape(r#"cat "../../outside secret""#, &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn command_directory_escape_detects_symlink_dotdot_operands() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        let outside_parent = tempfile::tempdir().unwrap();
        let outside_child = outside_parent.path().join("child");
        std::fs::create_dir(&outside_child).unwrap();
        let outside = outside_parent.path().join("secret.txt");
        std::fs::write(&outside, "secret").unwrap();
        let link = root.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_child, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside_child, &link).unwrap();

        assert_eq!(
            command_directory_escape("cat link/../secret.txt", &root, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn shell_write_targets_detect_redirection_heredoc_tee_and_multiple_files() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            shell_write_targets("cat > scratch/staged/x.md <<EOF\nbody\nEOF", root),
            ShellWriteTargets::Concrete(vec![root.join("scratch/staged/x.md")])
        );
        assert_eq!(
            shell_write_targets("printf x > nested/x.txt", root),
            ShellWriteTargets::Concrete(vec![root.join("nested/x.txt")])
        );
        assert_eq!(
            shell_write_targets("tee scratch/staged/x.md", root),
            ShellWriteTargets::Concrete(vec![root.join("scratch/staged/x.md")])
        );
        assert_eq!(
            shell_write_targets("printf a > a.txt && printf b > b.txt", root),
            ShellWriteTargets::Concrete(vec![root.join("a.txt"), root.join("b.txt")])
        );
    }

    #[test]
    fn shell_write_targets_ignore_redirect_like_heredoc_body_lines() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            shell_write_targets("cat <<EOF\n> /etc/passwd\nEOF", root),
            ShellWriteTargets::None
        );
        assert_eq!(
            shell_write_targets(
                "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /tmp/x\n> /\n*** End Patch\nPATCH",
                root,
            ),
            ShellWriteTargets::None
        );
        assert_eq!(
            shell_write_targets("cat <<EOF > /real/file\n> /etc/passwd\nEOF", root),
            ShellWriteTargets::Concrete(vec![PathBuf::from("/real/file")])
        );
    }

    #[test]
    fn shell_write_tokens_handle_quoted_and_tab_stripped_heredocs() {
        assert_eq!(
            shell_write_content_preview_inner("cat <<'EOF' > out.txt\nbody > /\nEOF"),
            ShellWriteContentPreview::Literal("body > /\n".to_string())
        );
        assert_eq!(
            shell_write_content_preview_inner("cat <<-EOF > out.txt\n\tbody\n\tEOF"),
            ShellWriteContentPreview::Literal("body\n".to_string())
        );
        assert_eq!(
            shell_write_targets(
                "cat <<< hello > /real/path",
                Path::new("/workspace/project")
            ),
            ShellWriteTargets::Concrete(vec![PathBuf::from("/real/path")])
        );
    }

    #[test]
    fn shell_write_targets_do_not_fabricate_dynamic_paths() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            shell_write_targets(r#"cat > "$OUT""#, root),
            ShellWriteTargets::Dynamic
        );
        assert_eq!(
            shell_write_targets("printf x > logs/*.txt", root),
            ShellWriteTargets::Dynamic
        );
    }

    #[test]
    fn shell_write_content_preview_preserves_literal_words() {
        assert_eq!(
            shell_write_content_preview_inner(r#"echo "a > b" > out.txt"#),
            ShellWriteContentPreview::Literal("a > b\n".to_string())
        );
        assert_eq!(
            shell_write_content_preview_inner(r#"echo "a   b" > out.txt"#),
            ShellWriteContentPreview::Literal("a   b\n".to_string())
        );
        assert_eq!(
            shell_write_content_preview_inner("echo -n hello > out.txt"),
            ShellWriteContentPreview::Literal("hello".to_string())
        );
        assert_eq!(
            shell_write_content_preview_inner("echo hello > out.txt"),
            ShellWriteContentPreview::Literal("hello\n".to_string())
        );
    }

    #[test]
    fn shell_write_content_preview_keeps_printf_and_dynamic_fallback() {
        assert_eq!(
            shell_write_content_preview_inner("printf hello > out.txt"),
            ShellWriteContentPreview::Literal("hello".to_string())
        );
        assert_eq!(
            shell_write_content_preview("somecmd > out.txt"),
            crate::daemon::proto::WriteContentPreview {
                content: "(output of `somecmd`)".to_string(),
                dynamic: true,
            }
        );
    }

    // ---- bash cwd session-boundary gate ----------------------------------

    #[tokio::test]
    async fn default_cwd_runs_at_session_root() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let out = BashTool::new()
            .call(serde_json::json!({ "command": "pwd" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(out.content.contains(&tmp.path().display().to_string()));
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn explicit_inside_cwd_runs() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("src")).unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let out = BashTool::new()
            .call(serde_json::json!({ "command": "pwd", "cwd": "src" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(
            out.content
                .contains(&tmp.path().join("src").display().to_string())
        );
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn denied_outside_cwd_prevents_execution() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let marker = tmp.path().join("marker");
        let deny = {
            let ctx = ctx.clone();
            tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
        };
        let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": format!("touch '{}'", marker.display()),
                    "cwd": "..",
                }),
                &ctx,
            )
            .await
            .expect_err("denied outside cwd returns an error");
        deny.await.unwrap();
        assert!(
            out.to_string()
                .contains("command working directory resolves outside")
        );
        assert!(
            !marker.exists(),
            "command must not run after denied cwd approval"
        );
    }

    #[tokio::test]
    async fn approved_outside_cwd_executes() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let parent = tmp.path().parent().unwrap().to_path_buf();
        let approve = {
            let ctx = ctx.clone();
            tokio::spawn(async move { approve_next_path_prompt(&ctx).await })
        };
        let out = BashTool::new()
            .call(serde_json::json!({ "command": "pwd", "cwd": ".." }), &ctx)
            .await
            .expect("approved outside cwd runs");
        approve.await.unwrap();
        assert!(out.content.contains(&parent.display().to_string()));
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn cd_inside_root_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let out = BashTool::new()
            .call(serde_json::json!({ "command": "cd subdir && pwd" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(
            out.content
                .contains(&tmp.path().join("subdir").display().to_string())
        );
    }

    #[tokio::test]
    async fn cd_escape_triggers_approval_before_execution() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let marker = tmp.path().join("marker");
        let deny = {
            let ctx = ctx.clone();
            tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
        };
        let out = BashTool::new()
            .call(
                serde_json::json!({ "command": format!("cd .. && touch '{}'", marker.display()) }),
                &ctx,
            )
            .await
            .expect_err("denied cd escape returns an error");
        deny.await.unwrap();
        assert!(
            out.to_string()
                .contains("command working directory resolves outside")
        );
        assert!(
            !marker.exists(),
            "command must not run after denied cd approval"
        );
    }

    #[tokio::test]
    async fn pushd_escape_triggers_approval_before_execution() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let marker = tmp.path().join("marker");
        let deny = {
            let ctx = ctx.clone();
            tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
        };
        let out = BashTool::new()
            .call(
                serde_json::json!({ "command": format!("pushd .. && touch '{}'", marker.display()) }),
                &ctx,
            )
            .await
            .expect_err("denied pushd escape returns an error");
        deny.await.unwrap();
        assert!(
            out.to_string()
                .contains("command working directory resolves outside")
        );
        assert!(
            !marker.exists(),
            "command must not run after denied pushd approval"
        );
    }

    #[tokio::test]
    async fn dotdot_as_data_is_not_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let out = BashTool::new()
            .call(
                serde_json::json!({ "command": "printf '%s\\n' '../data'" }),
                &ctx,
            )
            .await
            .expect("data-only dotdot does not require approval");
        assert!(out.content.contains("../data"));
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn granted_broad_skips_the_box() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        let approver = ctx.approver.as_ref().unwrap();
        // Not yet granted → must run sandboxed.
        assert!(!command_granted_broad(&ctx, "cargo build --release").await);
        // Grant `cargo build` at Session scope.
        let info = SimpleCommandInfo {
            program: "cargo".into(),
            normalized_program: "cargo".into(),
            subcommand: Some("build".into()),
            key: crate::approval::classify::ApprovalKey {
                program: "cargo".into(),
                subcommand: Some("build".into()),
            },
            wrapper: false,
            risk: Default::default(),
            span: None,
        };
        approver
            .store()
            .record_command(&info, Scope::Session)
            .unwrap();
        // Now the same command is granted broad → skip the box.
        assert!(command_granted_broad(&ctx, "cargo build --release").await);
        // A different subcommand is still ungranted → run sandboxed.
        assert!(!command_granted_broad(&ctx, "cargo test").await);
    }

    #[tokio::test]
    async fn risky_grant_above_policy_cap_does_not_skip_the_box() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        let approver = ctx.approver.as_ref().unwrap();
        let info = crate::approval::classify::classify("rm foo").simple_commands()[0].clone();
        approver
            .store()
            .record_command(&info, Scope::Session)
            .unwrap();

        assert!(
            approver.store().is_command_granted(&info.key),
            "the legacy broad grant exists"
        );
        assert!(
            !command_granted_broad(&ctx, "rm foo").await,
            "destructive commands are capped to once by policy"
        );
    }

    #[tokio::test]
    async fn wrapper_never_skips_the_box() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        // A wrapper can't be persisted, so it can never be "granted
        // broad" -> always runs sandboxed (and re-prompts on failure).
        assert!(!command_granted_broad(&ctx, "bash -c 'echo hi'").await);
        assert!(
            !command_granted_broad(&ctx, r#"sh -c "printf permission""#).await,
            "quoted shell wrappers must not skip confinement"
        );
        assert!(
            !command_granted_broad(&ctx, r#"env FOO=bar bash -lc 'printf hi'"#).await,
            "dynamic env wrappers must not skip confinement"
        );
        assert!(!command_granted_broad(&ctx, "sudo rm x").await);
    }

    #[tokio::test]
    async fn no_approver_never_skips_the_box() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        // No approver → can't know any grant → run sandboxed.
        assert!(!command_granted_broad(&ctx, "ls").await);
    }

    // ---- Part B: tool_call `sandbox` sub-object across the four states ----

    /// Sandbox-OFF: `test_ctx` defaults sandboxing off, so a real command
    /// runs unconfined and the sub-object records the off state with no
    /// escalation. Model-facing body is the plain command output.
    #[tokio::test]
    async fn sandbox_meta_records_sandbox_off_state() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "printf hi" }), &ctx)
            .await
            .expect("bash call returns");
        let meta = out.sandbox.expect("bash always populates sandbox meta");
        assert!(!meta.enabled, "sandbox off → not enabled");
        assert!(!meta.confined);
        assert!(!meta.escalated);
        assert!(!meta.broad_grant_simple_commands);
        assert!(meta.approval_scope_recorded.is_none());
        // Model-facing body unchanged: only the command output, no note.
        assert!(out.content.contains("hi"));
        assert!(!out.content.to_lowercase().contains("sandbox"));
    }

    /// BROAD-GRANT-SKIP: sandboxing on, but every simple command is already
    /// granted broad, so the box is skipped and the command runs unconfined
    /// (no live confinement needed). The sub-object records
    /// `broad_grant_simple_commands = true`, `confined = false`, and (on a
    /// platform where the sandbox backend exists) `enabled = true`.
    #[tokio::test]
    async fn sandbox_meta_records_broad_grant_skip_state() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        let approver = ctx.approver.as_ref().unwrap();
        let command = "printf hi";
        // Pre-grant exactly the classified key for `command` so every simple
        // command is granted broad → `command_granted_broad` is true →
        // `confine` is false → the run is UNCONFINED (no live confined spawn,
        // which would re-exec the test binary as the zerobox helper). We
        // grant the parser's own key so the match is exact regardless of how
        // `printf hi` decomposes.
        let classification = crate::approval::classify::classify(command);
        for info in classification.simple_commands() {
            approver
                .store()
                .record_command(info, Scope::Session)
                .unwrap();
        }
        // Sanity: the grant makes the box skippable on a sandbox-supported
        // platform (so the live call below never confines).
        let supported = crate::tools::shell_sandbox::shell_sandbox_supported();
        if supported {
            assert!(
                command_granted_broad(&ctx, command).await,
                "granting the classified key makes the command broad-granted"
            );
        }

        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": command }), &ctx)
            .await
            .expect("bash call returns");
        let meta = out.sandbox.expect("bash always populates sandbox meta");
        // `enabled` mirrors sandbox_on (session-on AND platform supports it).
        assert_eq!(meta.enabled, supported, "enabled mirrors sandbox_on");
        // On a sandbox-supported platform the broad grant skips the box.
        if supported {
            assert!(
                meta.broad_grant_simple_commands,
                "every simple command granted broad → box skipped"
            );
        }
        // Either way the run was not confined (off → never; broad-grant → skip).
        assert!(!meta.confined, "broad-grant skip never confines");
        assert!(!meta.escalated);
        assert!(meta.approval_scope_recorded.is_none());
        assert!(out.content.contains("hi"));
    }

    // NOTE: the two CONFINED states (confined-success and
    // confined-fail→escalate) can't be exercised end-to-end through
    // `bash::call`: a live confined spawn re-execs this test binary as the
    // `zerobox-linux-sandbox` helper, which only works from a binary whose
    // `main` ran `arg0::dispatch_linux_sandbox_helper` first (the test
    // harness `main` does not). Per the existing convention we cover the
    // confined-fail→escalate APPROVAL/dialog flow at the approver layer
    // (`escalate_approve_*` / `escalate_deny_*` below) — the exact
    // `approve_command_escalated` call `bash::call` makes — and the
    // sub-object's `confined`/`escalated`/`approval_scope_recorded` mapping
    // is asserted there + in the bash-side state tests above.

    // ---- escalate→approve / escalate→deny dialog paths --------------------

    use crate::daemon::proto::{InterruptQuestion, SandboxEscalation};

    /// Pull the sandbox-escalation block off the open interrupt with `iid`.
    fn open_escalation(
        db: &crate::db::Db,
        sid: uuid::Uuid,
        iid: uuid::Uuid,
    ) -> Option<SandboxEscalation> {
        let open = db.list_open_interrupts(sid).unwrap();
        let row = open.iter().find(|r| r.interrupt_id == iid)?;
        let set = row.questions.as_ref()?;
        match set.questions.first()? {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => sandbox_escalation.clone(),
            _ => None,
        }
    }

    #[tokio::test]
    async fn defensive_human_escalation_offer_is_run_once_or_deny_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_store(tmp.path());
        ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
        ctx.session.set_sandbox_escalation_enabled(true);
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);

        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        let cwd = tmp.path().display().to_string();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let open = db.list_open_interrupts(sid).unwrap();
            let row = open
                .iter()
                .find(|row| row.interrupt_id == iid)
                .expect("open interrupt row");
            let set = row.questions.as_ref().expect("questions present");
            let InterruptQuestion::Single {
                options,
                command_detail,
                sandbox_escalation,
                ..
            } = &set.questions[0]
            else {
                panic!("expected single escalation question");
            };
            let ids = options
                .iter()
                .map(|option| option.id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                ids,
                vec![
                    crate::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE,
                    crate::approval::ID_REJECT,
                ]
            );
            let detail = command_detail.as_ref().expect("command detail");
            assert_eq!(detail.full_command, "printf confined");
            assert_eq!(detail.cwd.as_deref(), Some(cwd.as_str()));
            assert_eq!(detail.offered_scopes, vec!["once"]);
            assert_eq!(detail.policy_cap.as_deref(), Some("once"));
            let esc = sandbox_escalation.as_ref().expect("escalation detail");
            assert_eq!(esc.confined_exit, 17);
            assert_eq!(esc.confined_stderr, "permission denied");
            assert!(esc.suggested_paths.is_empty());
            assert!(esc.suggested_access.is_none());
            assert!(hub.resolve(
                iid,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_REJECT.into(),
                }
            ));
        });

        let decision = defensive_human_escalation_offer(
            serde_json::json!({ "command": "printf confined" }),
            "printf confined",
            tmp.path(),
            17,
            "permission denied".to_string(),
            &ctx,
        )
        .await
        .unwrap();
        resolver.await.unwrap();
        assert!(decision.is_none(), "deny leaves original failure in place");
    }

    #[tokio::test]
    async fn defensive_human_escalation_offer_yolo_runs_unconfined_once() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_store(tmp.path());
        ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
        ctx.session.set_sandbox_escalation_enabled(true);
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
        ctx.approver = None;

        let out = defensive_human_escalation_offer(
            serde_json::json!({ "command": "printf yolo" }),
            "printf yolo",
            tmp.path(),
            1,
            "sandbox unavailable".to_string(),
            &ctx,
        )
        .await
        .unwrap()
        .expect("yolo reruns");
        assert!(out.content.contains("yolo"), "got: {}", out.content);
        let meta = out.sandbox.expect("sandbox meta");
        assert!(meta.enabled);
        assert!(!meta.confined);
        assert!(meta.escalated);
    }

    #[tokio::test]
    async fn defensive_human_escalation_offer_auto_prompts_human() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_store(tmp.path());
        ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
        ctx.session.set_sandbox_escalation_enabled(true);
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Auto);

        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE.into(),
                }
            ));
        });

        let out = defensive_human_escalation_offer(
            serde_json::json!({ "command": "printf auto" }),
            "printf auto",
            tmp.path(),
            1,
            "sandbox unavailable".to_string(),
            &ctx,
        )
        .await
        .unwrap()
        .expect("auto prompts and approval reruns");
        resolver.await.unwrap();
        assert!(out.content.contains("auto"), "got: {}", out.content);
        assert!(out.sandbox.expect("sandbox meta").escalated);
    }

    /// escalate→APPROVE (session scope): the escalation prompt is the
    /// distinct variant (carries the confined exit + stderr), the user
    /// approves at session scope, and the decision returns that scope — the
    /// value `bash::call` records as `approval_scope_recorded`. The grant is
    /// persisted (the silent-skip cascade the dialog warns about).
    #[tokio::test]
    async fn escalate_approve_session_carries_confined_detail_and_records_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        let approver = ctx.approver.as_ref().unwrap().clone();
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();

        let resolver = tokio::spawn(async move {
            // The approval prompt carries the distinct escalation block and
            // resolves directly to a scoped action.
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let esc = open_escalation(&db, sid, iid).expect("escalation block present");
            assert_eq!(esc.confined_exit, 13);
            assert!(esc.confined_stderr.contains("Permission denied"));
            assert!(hub.resolve(
                iid,
                crate::daemon::proto::ResolveResponse::Single {
                    selected_id: crate::approval::ID_APPROVE_SESSION.into(),
                }
            ));
        });

        let decision = approver
            .approve_command_escalated("cat /etc/secret", 13, "cat: Permission denied".into())
            .await
            .unwrap();
        resolver.await.unwrap();
        assert_eq!(
            decision,
            crate::approval::Decision::Allow {
                scope: Scope::Session
            }
        );
        // The grant is now remembered → future runs skip the box silently.
        let key = crate::approval::classify::ApprovalKey {
            program: "cat".into(),
            subcommand: None,
        };
        assert!(approver.store().is_command_granted(&key));
    }

    /// escalate→DENY: the user rejects the unconfined re-run. The decision
    /// is `Deny`, so `bash::call` keeps the original confined failure and
    /// records `approval_scope_recorded = null` while still marking
    /// `escalated = true` / `confined = true` (asserted via the bash-side
    /// branch contract: a denied escalation never records a scope).
    #[tokio::test]
    async fn escalate_deny_keeps_confined_failure_and_records_no_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_store(tmp.path());
        let approver = ctx.approver.as_ref().unwrap().clone();
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();

        let resolver = tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(sid).unwrap();
                if let Some(row) = open.first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, crate::daemon::proto::ResolveResponse::Cancel));
        });

        let decision = approver
            .approve_command_escalated("cat /etc/secret", 13, "denied".into())
            .await
            .unwrap();
        resolver.await.unwrap();
        assert_eq!(decision, crate::approval::Decision::Deny);
        // Denied → nothing recorded; a later query still prompts.
        let key = crate::approval::classify::ApprovalKey {
            program: "cat".into(),
            subcommand: None,
        };
        assert!(!approver.store().is_command_granted(&key));
    }

    // NOTE: an end-to-end "runs confined and EPERMs an outside read" test
    // is deliberately omitted. On Linux the zerobox path re-execs THIS
    // test binary as the `zerobox-linux-sandbox` helper, which only works
    // from a binary whose `main` ran `arg0::dispatch_linux_sandbox_helper`
    // first — the test harness's `main` does not, so a confined spawn
    // hangs/errors on helper re-entry. Per the build spec we therefore
    // cover the Sandbox CONFIGURATION/command-building (see
    // `shell_sandbox::tests::builds_confined_command`) and the
    // run-fail-escalate DECISION logic (above) instead of live EPERM
    // enforcement. The unconfined cancel/timeout/pgid path stays fully
    // exercised by `cancel_kills_process_group_promptly` /
    // `normal_command_completes` (test_ctx defaults sandbox OFF).

    // ---- defensive routing nudge (defensive-tool-routing-behavioral-nudge) -

    /// In `Defensive` mode a `cat` run appends the `read` routing tip after the
    /// `exit:` line; the tip is model-facing body text, not a separate row.
    #[tokio::test]
    async fn defensive_cat_appends_read_tip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(
            out.content.contains("tip: use `read <file>`"),
            "defensive cat must append the read tip, got: {}",
            out.content
        );
        // The tip sits after the `exit:` line (outside compression).
        let exit_pos = out.content.find("exit:").expect("exit line present");
        let tip_pos = out.content.find("tip:").expect("tip present");
        assert!(tip_pos > exit_pos, "tip must follow the exit line");
    }

    /// In `Normal` mode the SAME `cat` run appends nothing — the nudge is
    /// defensive-mode-only (token economy §10).
    #[tokio::test]
    async fn normal_cat_appends_no_tip() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        // test_ctx defaults to Normal.
        assert!(matches!(
            ctx.llm_mode,
            crate::config::extended::LlmMode::Normal
        ));
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(
            !out.content.contains("tip:"),
            "normal mode must append no tip, got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn durable_shell_write_appends_writeunlock_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let out = BashTool::new()
            .call(
                serde_json::json!({ "command": "printf hello > durable.txt" }),
                &ctx,
            )
            .await
            .expect("bash call returns");

        assert!(
            out.content.contains(SHELL_WRITE_NATIVE_TOOL_HINT),
            "{}",
            out.content
        );
    }

    /// Self-suppression: once the model has successfully used `read` this
    /// session, a later defensive `cat` appends NO tip.
    #[tokio::test]
    async fn defensive_cat_tip_suppressed_after_read() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
        // The model already adopted `read` this session (recorded at the
        // dispatch site on a successful read call).
        ctx.session.record_tip_tool_used("read");
        let tool = BashTool::new();
        let out = tool
            .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
            .await
            .expect("bash call returns");
        assert!(
            !out.content.contains("tip:"),
            "the read tip must be suppressed after a successful read, got: {}",
            out.content
        );
    }

    // ---- empty-output annotation (implementation note) -

    /// exit 0 with both streams empty: the bare `exit: 0` line is preserved
    /// AND the complete-result annotation is appended.
    #[test]
    fn empty_exit_zero_is_annotated_complete() {
        let out = format_combined("", "", 0, false);
        assert!(out.contains("exit: 0"), "exit line preserved, got: {out}");
        assert!(
            out.contains("no output") && out.contains("complete result"),
            "expected complete-result annotation, got: {out}"
        );
    }

    /// Nonzero with both streams empty: annotated, but NEUTRAL — never
    /// labelled "failed"/"error" (grep/diff exit 1 = a valid answer).
    #[test]
    fn empty_nonzero_is_annotated_neutral() {
        let out = format_combined("", "", 1, false);
        assert!(out.contains("exit: 1"), "exit line preserved, got: {out}");
        assert!(out.contains("no output"), "expected annotation, got: {out}");
        let lower = out.to_lowercase();
        assert!(
            !lower.contains("fail") && !lower.contains("error"),
            "nonzero annotation must stay neutral, got: {out}"
        );
    }

    /// Any stdout means it is not the void case — no annotation.
    #[test]
    fn stdout_present_is_not_annotated() {
        let out = format_combined("hi\n", "", 0, false);
        assert!(out.contains("stdout:"), "stdout rendered, got: {out}");
        assert!(
            !out.contains("no output"),
            "stdout-present must not be annotated, got: {out}"
        );
    }

    /// Any stderr means it is not the void case — no annotation.
    #[test]
    fn stderr_present_is_not_annotated() {
        let out = format_combined("", "oops\n", 1, false);
        assert!(out.contains("stderr:"), "stderr rendered, got: {out}");
        assert!(
            !out.contains("no output"),
            "stderr-present must not be annotated, got: {out}"
        );
    }

    /// The signaled branch keeps its current rendering — never annotated.
    #[test]
    fn signaled_empty_is_not_annotated() {
        let out = format_combined("", "", 0, true);
        assert!(
            out.contains("exit: signaled"),
            "signaled rendering preserved, got: {out}"
        );
        assert!(
            !out.contains("no output"),
            "signaled must not be annotated, got: {out}"
        );
    }

    #[test]
    fn missing_binary_diagnostic_names_cockpit_environment() {
        let outcome = ShellOutcome {
            stdout: Vec::new(),
            stderr: b"sh: 1: npm: not found\n".to_vec(),
            exit: 127,
            signaled: false,
            success: false,
        };
        let body = render_output(
            &outcome,
            None,
            false,
            "npm run build",
            Path::new("/repo"),
            None,
            None,
        );
        assert!(body.contains("stderr:\nsh: 1: npm: not found\n"));
        assert!(body.contains("exit: 127\n"));
        assert!(body.contains("cockpit_command_environment:"));
        assert!(body.contains("attempted_command: npm run build"));
        assert!(body.contains("cwd: /repo"));
        assert!(body.contains("exit_code: 127"));
        assert!(body.contains("missing_binary: npm"));
        assert!(body.contains("not found in cockpit's command environment"));
        assert!(body.contains("does not establish that it is absent from the host system"));
    }

    #[test]
    fn nonzero_command_diagnostic_includes_attempted_command_and_cwd() {
        let outcome = ShellOutcome {
            stdout: Vec::new(),
            stderr: b"tests failed\n".to_vec(),
            exit: 2,
            signaled: false,
            success: false,
        };
        let body = render_output(
            &outcome,
            None,
            false,
            "cargo test",
            Path::new("/repo"),
            None,
            None,
        );
        assert!(body.contains("exit: 2\n"));
        assert!(body.contains("cockpit_command_environment:"));
        assert!(body.contains("attempted_command: cargo test"));
        assert!(body.contains("cwd: /repo"));
        assert!(body.contains("exit_code: 2"));
        assert!(!body.contains("missing_binary:"));
        assert!(body.contains("failure occurred while running in cockpit's command environment"));
    }

    #[test]
    fn spawn_error_diagnostic_includes_command_cwd_and_error() {
        let error = std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory");
        let body = render_spawn_error("cargo test", Path::new("/repo"), &error);
        assert!(body.contains("Error: could not start cockpit shell"));
        assert!(body.contains("cockpit_command_environment:"));
        assert!(body.contains("attempted_command: cargo test"));
        assert!(body.contains("cwd: /repo"));
        assert!(body.contains("spawn_error: No such file or directory"));
        assert!(body.contains("missing_binary: sh"));
        assert!(body.contains("not found in cockpit's command environment"));
    }
}
