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
use crate::engine::tool::{
    ResourceMeta, TOOL_PRESENTATION_SUMMARY_CHARS, Tool, ToolCtx, ToolOutput, ToolOutputSidecar,
    ToolPresentation, single_line_preview, string_field,
};
use crate::tools::common::{OUTPUT_BYTE_CAP, truncate_head_tail};

mod boundary;
pub use boundary::{command_directory_escape, outside_session_boundary};
use boundary::{dynamic_shell_path, outside_cwd_error};

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
                "resources": resources_schema("Optional resource permits for expensive commands, e.g. {\"cpu\":1,\"memory\":1}")
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
                "resources": resources_schema("Declare resource permits for expensive commands, e.g. {\"cpu\":1,\"memory\":1} for builds, tests, or other CPU/RAM-heavy work")
            },
            "required": ["command"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let cmd = string_field(args, "command").unwrap_or_default();
        ToolPresentation::with_parts(
            Some("🔧"),
            self.name(),
            single_line_preview(&cmd, TOOL_PRESENTATION_SUMMARY_CHARS),
            cmd,
        )
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        call_bash_inner(&self.prelude, args, ctx, BashRunOptions::default()).await
    }
}

fn resources_schema(description: &str) -> Value {
    let mut properties = serde_json::Map::new();
    for name in resource_permit_names() {
        properties.insert(name, serde_json::json!({ "type": "integer", "minimum": 0 }));
    }
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false,
        "description": description
    })
}

fn resource_permit_names() -> Vec<String> {
    crate::config::extended::ResourceSchedulerPoolsConfig::default()
        .as_map()
        .into_keys()
        .collect()
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
    let mut identity_write_targets = Vec::new();
    if let ShellWriteTargets::Concrete(targets) = shell_write_targets(command, &cwd) {
        for target in targets {
            match crate::assistants::identity::check_identity_write(ctx, &target).await? {
                crate::assistants::identity::IdentityWriteGate::Allow { note } => {
                    if let Some(note) = note {
                        tracing::info!(%note, path = %target.display(), "assistant identity bash write allowed");
                        identity_write_targets.push(target);
                    }
                }
                crate::assistants::identity::IdentityWriteGate::Refuse(message) => {
                    return Ok(crate::assistants::identity::tool_refusal(message));
                }
            }
        }
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

    let is_container_run = !options.force_unconfined && ctx.session.sandbox_mode().is_container();
    let mut session_env = ctx
        .env_overlay
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let jq_shim_paths =
        if should_prepare_jq_shim(options.force_unconfined, ctx.session.sandbox_mode()) {
            crate::tools::jq_shim::prepare_host_jq_shim(&ctx.session, &mut session_env)
        } else {
            Vec::new()
        };
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

    if is_container_run {
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
    let extra_sandbox_paths =
        merged_extra_sandbox_paths(&command_resource_plan.allow_paths, &jq_shim_paths);

    // First attempt: sandboxed (confined) or broadened/unconfined.
    let attempt = run_shell(
        &prefixed,
        &cwd,
        confine,
        tmp_dir.as_deref(),
        &scrub,
        &session_env,
        &extra_sandbox_paths,
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
                &extra_sandbox_paths,
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

    for target in &identity_write_targets {
        crate::assistants::identity::record_identity_write(ctx, target)?;
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

fn merged_extra_sandbox_paths(
    resource_paths: &[crate::tools::shell_sandbox::ExtraSandboxPath],
    jq_shim_paths: &[crate::tools::shell_sandbox::ExtraSandboxPath],
) -> Vec<crate::tools::shell_sandbox::ExtraSandboxPath> {
    let mut paths = resource_paths.to_vec();
    paths.extend_from_slice(jq_shim_paths);
    paths
}

fn should_prepare_jq_shim(
    force_unconfined: bool,
    sandbox_mode: crate::tools::sandbox_mode::SandboxMode,
) -> bool {
    force_unconfined || !sandbox_mode.is_container()
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
mod sandbox_escalation_signal_tests;

/// Windows-only: the shell-sandbox notice fires at most once per process
/// and only when the session wanted sandboxing on (sandboxing part 2).
#[cfg(all(test, windows))]
mod windows_tests;

#[cfg(all(test, unix))]
mod tests;
