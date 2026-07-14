//! Canonical ordinary-tool dispatch pipeline.
//!
//! Every path that executes an ordinary tool call must go through
//! [`execute_ordinary_call`]. The live driver delegates here after name repair
//! and structural-tool routing; `interrupt-park-core` reuses the same unit for
//! persisted parked-call replay so an approved command runs through the exact
//! same safety, audit, event, redaction, and history contract.

use std::sync::Arc;

use super::*;
use crate::db::needs_attention::{InterruptParkPayload, InterruptResumeAnchor};

pub(crate) struct DispatchEnv<'a> {
    pub(crate) agent: &'a Agent,
    pub(crate) session: &'a Arc<Session>,
    pub(crate) model: &'a Model,
    pub(crate) active_tools: &'a ToolBox,
    pub(crate) ctx: &'a ToolCtx,
    pub(crate) tx: &'a mpsc::Sender<TurnEvent>,
    pub(crate) hint_corrections: bool,
    pub(crate) loop_guard_threshold: u32,
    pub(crate) cwd: &'a std::path::Path,
}

pub(crate) async fn execute_ordinary_call(
    env: &DispatchEnv<'_>,
    history: &mut Vec<Message>,
    tc: &ToolCall,
    resolved_name: &str,
    name_recovery: Recovery,
    text_recovery_marker: Option<Recovery>,
) -> Result<()> {
    let mut args = tc.function.arguments.clone();
    // §14 wire-vs-user split for a text-recovered call: the user-facing
    // `original_input` is the model's exact text block (carried on the
    // recovery marker), not the lifted args — so the timeline shows the
    // text the model actually emitted with the recovery chip, while the
    // wire/model form is the structured call. For an ordinary structured
    // call `original` stays the args as before.
    let original = match &text_recovery_marker {
        Some(Recovery::TextEmbedded { original, .. }) => Value::String(original.clone()),
        _ => args.clone(),
    };

    // Validate-then-repair against the tool's own JSON Schema (§12).
    // Looked up by the NAME-repaired `resolved_name`, so a rebound junk
    // name finds the registered tool's schema and the args repair below
    // runs against it — name-repair strictly precedes args-repair. A
    // still-unknown name (no rebind, or a sanitized name) has no schema,
    // so it validates trivially and surfaces its "unknown tool" error in
    // `dispatch_one` as before — now with a provider-valid name.
    // Clean input is returned untouched; a repairable malformation is
    // fixed at the disagreeing path and re-validated; an unrecoverable
    // call short-circuits to a model-readable hard-fail *without*
    // dispatching the tool.
    let schema = env
        .agent
        .tools
        .get(resolved_name)
        .map(|t| t.parameters())
        .unwrap_or(Value::Null);
    let mut repair_outcome = repair(&mut args, &schema, resolved_name);
    // §12 repair telemetry (implementation note):
    // emit the shape fingerprint + issue codes + received-key summary +
    // fired rules WITH the active model/provider — the load-bearing
    // dimension (`repair()` itself is model-blind). Emitted here, where
    // `model` is in scope, on BOTH a recovered repair and an unrepairable
    // hard-fail; `None` on a clean pass (nothing malformed to fingerprint).
    // `shape_fingerprint` is also persisted on the audit row below so
    // `cockpit debug failed-calls` can group/count by model + fingerprint.
    // Telemetry must never alter dispatch — it is read-only here.
    let repair_fingerprint: Option<String> = repair_outcome.telemetry.as_ref().map(|t| {
        let model_id = env.model.model_id_ref();
        let provider_id = env.model.provider_id();
        if repair_outcome.valid {
            tracing::info!(
                target: "repair",
                tool = resolved_name,
                model = model_id,
                provider = provider_id,
                shape_fingerprint = %t.shape_fingerprint,
                issue_codes = %t.issue_codes_csv(),
                received_keys = %t.received_keys_csv(),
                rules_fired = %t.rules_fired_csv(),
                "tool_input_repaired"
            );
        } else {
            tracing::warn!(
                target: "repair",
                tool = resolved_name,
                model = model_id,
                provider = provider_id,
                shape_fingerprint = %t.shape_fingerprint,
                issue_codes = %t.issue_codes_csv(),
                received_keys = %t.received_keys_csv(),
                rules_fired = %t.rules_fired_csv(),
                error = repair_outcome.error.as_deref().unwrap_or(""),
                "tool_input_invalid"
            );
        }
        t.shape_fingerprint.clone()
    });
    // Model-facing §12 correction hints, captured before `repair_outcome`
    // is decomposed below. Surfaced as `<repair_note>` lines on the WIRE
    // tool_result only when `env.hint_corrections` is enabled
    // (implementation note); the user transcript is
    // never altered. Empty on a clean/unrecoverable call.
    let repair_hints: Vec<String> = if env.hint_corrections {
        std::mem::take(&mut repair_outcome.hints)
    } else {
        Vec::new()
    };
    // The recorded recovery for the row (single-Recovery invariant, §14).
    // A name repair is the primary correction when it fired — without it
    // the call wouldn't dispatch at all — so it stands as the row's
    // recovery; the args shape-repair / path-normalize below only fill in
    // when the name was clean. The args are still repaired in `args`
    // regardless; only the *recorded* recovery is gated.
    // Text-embedded recovery is the primary correction when it fired: the
    // call wouldn't have dispatched at all without it (same rationale as a
    // name repair), so the `TextEmbedded` marker stands as the row's
    // recovery — ahead of any args shape-repair the lifted block then
    // needed. The args are still repaired in `args` regardless.
    let mut recovery = if let Some(marker) = text_recovery_marker {
        marker
    } else if matches!(name_recovery, Recovery::Clean) {
        repair_outcome.recovery
    } else {
        name_recovery
    };

    // Fabricated-absolute-path normalization (§12). Runs only on a
    // schema-valid call (the path fields are strings), and *before* the
    // sandbox / native-tool cwd-confinement checks below — it salvages a
    // fabricated absolute prefix into the matching project-root-relative
    // path (recorded as a shape repair, so the §14 wire/user split shows
    // the canonical path with a recovery chip) or hard-fails an absolute
    // path that neither exists nor salvages, with a model-legible error.
    // A salvage only overwrites a `Clean` recovery — a shape repair the
    // catalog already recorded (or a name repair) stays the primary
    // recovery for the row.
    // Set when the §12 path-normalize pass turned the call away because an
    // `x-cockpit-kind: path` field pointed at a path that does not exist
    // (model path-hallucination, e.g. a guessed `README.md`). It earns its
    // OWN rejection reason (`path_not_found`) below so repair-layer
    // telemetry isn't polluted by hallucinated paths, distinct from a
    // genuine `schema_invalid_unrepairable`.
    let mut path_not_found = false;
    if repair_outcome.valid {
        let norm = repair::normalize_paths(&mut args, &schema, env.cwd);
        if let Some(err) = norm.error {
            repair_outcome.valid = false;
            path_not_found = norm.not_found;
            // Steer mid-turn: a nonexistent path is best recovered by
            // listing what actually exists. Point at `tree` when the agent
            // holds it (every file-capable primary/subagent does); fall
            // back to the generic repair-layer diagnostic otherwise.
            repair_outcome.error = Some(if path_not_found && env.ctx.has_tree {
                format!(
                    "Error: `{}` does not exist; run `tree` to see existing files before reading.",
                    args.get("path").and_then(Value::as_str).unwrap_or_default()
                )
            } else {
                err
            });
        } else if matches!(recovery, Recovery::Clean) {
            recovery = norm.recovery;
        }
    }

    // Liveness refresh (`readlock-wait-and-lock-expiry.md`): every tool
    // call by this `(session, agent)` pushes back the idle-expiry
    // deadline of the locks it holds, so an agent legitimately mid-task
    // never loses a lock to the sweeper. One central refresh here, not
    // per-tool — it covers every dispatched call uniformly.
    env.ctx
        .locks
        .touch_holder(&env.ctx.agent_id, env.ctx.session.id);

    let _ = env
        .tx
        .send(TurnEvent::ToolStart {
            agent: env.agent.name.clone(),
            call_id: tc.id.clone(),
            tool: resolved_name.to_string(),
            args: args.clone(),
        })
        .await;

    // Loop guard (GOALS §1/§12): block a back-to-back identical tool
    // call (same name + canonical post-repair `wire_input`) pending
    // approval. Only schema-valid calls are guarded — a malformed call
    // already short-circuits below, and isn't a "loop" worth
    // prompting on. The chain is maintained on `session` so it spans
    // turns; an intervening different call resets the count. When the
    // guard rejects (one-off, an always-reject rule, or headless), the
    // call is *not* dispatched and a guidance error stands in as the
    // tool result so the model changes course. With no approver wired
    // (seed-tool re-exec, tool tests) the guard is skipped — never
    // silently denied, matching the command/path approval contract.
    // `loop_guard_reject` gates dispatch; `loop_guard_count` is the live
    // consecutive-repeat count of the rejected `(tool, args)` run, carried
    // to the wire-history collapse site (`loop-collapse-structural-
    // dedup.md`) so the synthesized message can state "called N times".
    let mut loop_guard_count: u32 = 0;
    let call_signature = repair_outcome
        .valid
        .then(|| crate::approval::store::GrantStore::loop_signature(resolved_name, &args));
    let repeated_recoverable_tool_call = if let Some(signature) = call_signature.as_deref() {
        env.session
            .repeated_recoverable_tool_call_message(signature)
    } else {
        env.session.clear_recoverable_tool_call();
        None
    };
    let loop_guard_reject = if repeated_recoverable_tool_call.is_none()
        && repair_outcome.valid
        && let Some(approver) = env.ctx.approver.as_ref()
    {
        let signature = call_signature
            .as_deref()
            .expect("valid tool calls have a loop signature");
        let consecutive = env.session.bump_consecutive_call(signature);
        if consecutive >= env.loop_guard_threshold.max(1) {
            let interactive = env.ctx.interrupts.is_interactive_attached();
            let decision = approver
                .approve_repeat(resolved_name, &args, interactive)
                .await?;
            let reject = !decision.is_accept();
            if reject {
                loop_guard_count = consecutive;
            }
            reject
        } else {
            false
        }
    } else {
        false
    };

    // Command-safety gate (implementation note):
    // in `auto` approval mode each gated call (`bash`/`webfetch`/`mcp`)
    // is judged by the utility model — with NO history —
    // before it runs. `safe` → run; `unsafe` (or utility model
    // unavailable → fail CLOSED) → escalate to the user; a denial skips
    // dispatch. The verdict also says whether the result needs a
    // post-run injection re-check (handled after dispatch). Only
    // evaluated for schema-valid, non-loop-rejected gated calls.
    let mut recheck_result = false;
    let gate_block: Option<String> = if repair_outcome.valid && !loop_guard_reject {
        match safety_gate_decision(resolved_name, &args, env.ctx, env.tx).await {
            GateOutcome::Run { recheck } => {
                recheck_result = recheck;
                None
            }
            GateOutcome::Block(msg) => Some(msg),
        }
    } else {
        None
    };
    let guard = crate::config::extended::resolve_injection_guard(env.cwd);
    if should_scan_tool_result(
        resolved_name,
        env.agent.scan_tool_results,
        env.session.approval_mode(),
        guard.threshold,
    ) {
        recheck_result = true;
    }

    // Dispatch only when validate-then-repair produced a schema-valid
    // call AND the loop guard didn't reject it AND the safety gate
    // didn't block it. Otherwise skip dispatch and treat the
    // model-readable diagnostic as an invocation failure — same
    // downstream audit/telemetry/history path a tool's own
    // `invalid_input` takes.
    // Rejection classification (export-audit fidelity): a call that never
    // becomes a real `tool_call` because the validate-then-repair path
    // (§12) turned it away emits a distinct `tool_rejected` event so a
    // hallucinated / unrepairable call is directly queryable. Three reasons:
    // an unrepairable malformed call (`schema_invalid_unrepairable`), a
    // path-field pointing at a nonexistent file (`path_not_found` — model
    // path-hallucination, kept distinct so it doesn't pollute repair
    // telemetry), and a name not in the agent's advertised toolbox
    // (`not_in_advertised_set`) — structural tools (`task`/`handoff`/`done`/
    // `schedule`/`spawn`/`return`) already returned above, so any unknown name
    // here is a hallucination.
    // Loop-guard / safety-gate blocks are NOT rejections in this sense (the
    // call was valid and advertised) and are not classified.
    let rejection_reason: Option<&'static str> = if loop_guard_reject || gate_block.is_some() {
        None
    } else if !repair_outcome.valid {
        // A model-hallucinated nonexistent path gets its own reason so
        // path-hallucination telemetry stays separate from genuine
        // schema-repair failures (`defensive-tool-descriptions-
        // weak-model-routing.md`).
        if path_not_found {
            Some("path_not_found")
        } else {
            Some("schema_invalid_unrepairable")
        }
    } else if env.active_tools.get(resolved_name).is_none() {
        Some("not_in_advertised_set")
    } else {
        None
    };
    let lifecycle_started = repair_outcome.valid && env.active_tools.get(resolved_name).is_some();
    let mut assistant_seq = None;
    if lifecycle_started {
        let (start_recovery_kind, start_recovery_stage) = recovery.db_fields();
        let start_data = serde_json::json!({
            "tool": resolved_name,
            "original_input": original.clone(),
            "wire_input": args.clone(),
            "recovery_kind": start_recovery_kind,
            "recovery_stage": start_recovery_stage,
        });
        match env.session.record_event(
            crate::db::session_log::SessionEventKind::ToolCallStarted,
            Some(&env.agent.name),
            Some(&tc.id),
            &start_data,
        ) {
            Ok(seq) => {
                assistant_seq = Some(seq);
            }
            Err(e) => {
                tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_started event failed");
            }
        }
    }
    let gate_blocked = gate_block.is_some();
    let repeated_recoverable_tool_call_reject = repeated_recoverable_tool_call.is_some();
    let (result, duration_ms) = if let Some(msg) = repeated_recoverable_tool_call.clone() {
        (Err(invalid_input(msg)), 0)
    } else if loop_guard_reject {
        // Loop-collapse synthesized message (`loop-collapse-
        // structural-dedup.md`): the rejection the model reads back states
        // the repeated call + attempt count + the available tool-NAME list
        // (names only — schemas would bust token economy §10 / the cache
        // prefix). It is also the message the contiguous-run collapse below
        // dedups to exactly one. The `task` enum's structural tools aren't
        // in `agent.tools`, so the list is the agent's advertised toolbox —
        // the same set the model sees in its system prompt.
        (
            Err(invalid_input(loop_guard_message(
                resolved_name,
                &args,
                loop_guard_count,
                &env.active_tools.names(),
            ))),
            0,
        )
    } else if let Some(msg) = gate_block {
        (Err(invalid_input(msg)), 0)
    } else if repair_outcome.valid {
        let payload = InterruptParkPayload {
            tool: resolved_name.to_string(),
            args: args.clone(),
            call_id: tc.id.clone(),
            resume: InterruptResumeAnchor {
                agent_id: env.agent.name.clone(),
                call_id: tc.id.clone(),
                provider_call_id: tc.call_id.clone(),
                assistant_seq,
            },
        };
        crate::engine::interrupt::with_interrupt_park_payload(payload, async {
            dispatch_one_timed(env.active_tools, resolved_name, args.clone(), env.ctx).await
        })
        .await
    } else {
        let msg = repair_outcome
            .error
            .unwrap_or_else(|| format!("`{resolved_name}` arguments failed schema validation"));
        (Err(invalid_input(msg)), 0)
    };

    // Defensive bash-routing nudge self-suppression
    // (implementation note): a SUCCESSFUL
    // call to a dedicated file/search tool (`read`/`search`/`word`/
    // `symbol_find`/`tree`) marks that tip as adopted for the session, so a
    // later `bash` file/search command stops appending the corresponding
    // tip. Recorded once here at the single dispatch chokepoint; the `bash`
    // result-assembly site reads it. Non-tip tools record nothing.
    if result.is_ok() && crate::tools::shell_compress::tip_adopted_by(resolved_name).is_some() {
        env.session.record_tip_tool_used(resolved_name);
    }

    // Canonical-form history rewrite. Two layers can feed the model's
    // own corrected call back into `history` so its next inference sees
    // the shape that would have matched at stage 1:
    //
    //   - §13c tool recovery: a tool returns a recovery + canonical args
    //     (today only `editunlock`); this is authoritative because it
    //     derives the canonical form from the tool's *own execution* on
    //     already-repaired args. When present it supersedes everything —
    //     it sets the row's `wire_input_json` AND the in-history args.
    //   - §12 shape-repair fallback: when no tool recovery fired but the
    //     dispatcher's validate-then-repair pass produced a schema-valid
    //     call via a non-`Clean` stage (any of the four), we feed that
    //     repaired shape back too. Unlike §13c this fires regardless of
    //     dispatch outcome — a tool that failed for a *semantic* reason
    //     after a valid shape-repair still teaches the corrected shape,
    //     because the shape is derived purely from the schema, not from
    //     execution. `args` already holds the repaired form here.
    //
    // Tool recovery wins: the shape-repair rewrite is the fallback used
    // only when `wire_args` is `None`. Both run at the same point in the
    // turn — right after dispatch, on the just-produced assistant message
    // before it enters a cached prefix — so neither busts the prompt
    // cache beyond normal turn progression.
    let (tool_recovery, wire_args, repeat_guard) = match &result {
        Ok(out) => (
            out.recovery.clone(),
            out.canonical_args.clone(),
            out.repeat_guard.clone(),
        ),
        Err(_) => (None, None, None),
    };
    let output_sidecar = match &result {
        Ok(out) => out.output_sidecar.as_ref().map(|s| s.payload.clone()),
        Err(_) => None,
    };
    // Part B: `bash`'s sandbox-state sub-object for the tool_call event.
    // Only `bash` populates it; every other tool leaves it `None`, so the
    // event omits the `sandbox` key. Never model-facing (token economy).
    let sandbox_meta = match &result {
        Ok(out) => out.sandbox.clone(),
        Err(_) => None,
    };
    let resource_meta = match &result {
        Ok(out) => out.resource.clone(),
        Err(_) => None,
    };
    // Part (c): `bash`'s authoritative exit code for the tool_call event.
    // Only `bash` populates it; a hard-failed dispatch has no shell exit.
    let exit_code = match &result {
        Ok(out) => out.exit_code,
        Err(_) => None,
    };
    // Sandbox-unavailable detection (§6.5): when `bash` refused because the
    // sandbox can't initialize, it attached the diagnosed remedy out-of-
    // band on `unavailable_reason`. Emit a UI-only event so the daemon
    // raises a deterministic, persistent, user-facing indicator regardless
    // of what the model does. This text never enters history or any
    // inference request — it rides the event stream / broadcast bus only.
    // Per-session de-dupe lives daemon-side (the worker's forward seam), so
    // repeated failed calls don't spam the user.
    if let Some(remedy) = sandbox_meta
        .as_ref()
        .and_then(|m| m.unavailable_reason.clone())
    {
        let fix_command = crate::tools::shell_sandbox::fix_command_for_reason(&remedy);
        let _ = env
            .tx
            .send(TurnEvent::SandboxUnavailable {
                remedy,
                fix_command,
            })
            .await;
    }
    // §13c tool recovery additionally rebinds `args` so the audit row's
    // `wire_input_json` is the tool's canonical form; the shape-repair
    // fallback needs no rebind (`args` is already the repaired form).
    if wire_args.is_some() {
        args = wire_args.clone().unwrap();
    }
    if let Some(canonical) =
        history_rewrite_args(wire_args.as_ref(), &args, repair_outcome.valid, &recovery)
    {
        rewrite_assistant_tool_call(history, &tc.id, canonical);
    }
    if let Some(signature) = repair_outcome
        .valid
        .then(|| crate::approval::store::GrantStore::loop_signature(resolved_name, &args))
    {
        if let Some(RepeatGuard { message }) = repeat_guard.clone() {
            env.session
                .remember_recoverable_tool_call(signature, message);
        } else if let Some(message) = repeated_recoverable_tool_call.clone() {
            env.session
                .remember_recoverable_tool_call(signature, message);
        } else {
            env.session.clear_recoverable_tool_call();
        }
    } else {
        env.session.clear_recoverable_tool_call();
    }
    // Name-repair history rewrite (implementation note):
    // when the emitted NAME was rebound or charset-sanitized, rewrite the
    // just-pushed assistant tool_call so its replayed wire form carries the
    // resolved/provider-valid name. Without this, the malformed name would
    // re-enter the next inference request and 400 the provider (Anthropic/
    // Bedrock enforce `^[a-zA-Z0-9_-]{1,64}$`) and break tool_use↔
    // tool_result pairing on a later resume. The `tool` column already
    // recorded `resolved_name`; this keeps the live history consistent.
    if matches!(recovery, Recovery::NameRepair { .. }) {
        rewrite_assistant_tool_call_name(history, &tc.id, resolved_name);
    }
    let recovery = tool_recovery.unwrap_or(recovery);

    let (raw_output, hard_fail, fail_kind) = match &result {
        Ok(ToolOutput { content, .. }) => (content.clone(), false, None),
        Err(e) => {
            let msg = format!("Error: {e}");
            (msg, true, Some(crate::engine::tool::classify_failure(e)))
        }
    };

    // Post-result hint layer (`engine::bash_hints`, `bash-result-
    // hint-layer.md`). After a successful `bash` call, run the registered
    // codebase-agnostic rules over (exit_code, stdout-empty, command, recent
    // bash history); the first match (if any) appends a `--- hint(<id>)`
    // line to the WIRE tool_result and records `data.hint` on the event
    // (wire-vs-user split, GOALS §14). The recent-history window is read
    // BEFORE this call is pushed onto the ring, so the rules see only prior
    // calls. `bash`-only — every other tool leaves `bash_hint` `None`.
    let bash_hint: Option<crate::engine::bash_hints::Hint> =
        if !hard_fail && resolved_name == "bash" {
            let command = args.get("command").and_then(Value::as_str).unwrap_or("");
            // Split the assembled `bash` body back into its stdout/stderr
            // sections so the rules see accurate streams (the `exit:`/
            // annotation lines are excluded). An empty stdout section is the
            // authoritative "result is empty" signal the thrash rule keys on.
            let (stdout, stderr) = crate::engine::bash_hints::split_bash_body(&raw_output);
            let recent = env.session.recent_bash();
            let ctx = crate::engine::bash_hints::BashCallContext {
                command,
                exit_code,
                stdout: &stdout,
                stderr: &stderr,
                recent: &recent,
            };
            let hint = crate::engine::bash_hints::first_hint(&ctx);
            // Record this call into the recent-history ring AFTER reading the
            // window (so the next bash call sees it).
            env.session.push_recent_bash(command.to_string(), exit_code);
            hint
        } else {
            None
        };
    // The user-side `data.hint` JSON value, mirrored onto the DB row and the
    // export event. `None` when no rule fired / non-`bash` / hard-fail.
    let hint_value: Option<Value> = bash_hint.as_ref().map(|h| {
        serde_json::json!({
            "kind": h.kind,
            "text": h.user_chip.text,
            "severity": h.user_chip.severity.as_str(),
        })
    });

    // Keep tool output raw in history and the local audit row. Egress
    // redaction happens at model dispatch and at the client boundary.
    let mut output_str = raw_output;

    // Result injection re-check (implementation note):
    // when the safety gate flagged this call's result as pulling in
    // external/untrusted content, route the (scrubbed) output through
    // the shared injection-check mechanism. A `high` rating BLOCKS and
    // asks the user (allow through / drop / edit — same override UX as
    // the inbound prompt-injection block); `medium` delivers with a warn
    // chip; `low` (or unavailable → can't-recheck warn) delivers. The
    // recorded transcript keeps the post-recheck `output_str` (wire =
    // user, GOALS §14). Only fires on a successful, flagged call.
    if recheck_result && !hard_fail {
        let recheck_ctx = ResultRecheckCtx::from_tool_ctx(env.ctx);
        output_str = result_recheck(&output_str, &recheck_ctx, env.tx).await;
    }

    if !hard_fail
        && truncated_tool_result_is_retrievable(resolved_name)
        && matches!(
            &result,
            Ok(ToolOutput {
                truncated: true,
                ..
            })
        )
    {
        match store_compressed_tool_result(
            env.session,
            &env.agent.name,
            resolved_name,
            &tc.id,
            "truncated",
            &output_str,
            Some(output_str.len()),
        ) {
            Ok(hash) => {
                output_str.push_str(&format!(
                    "\n[compressed tool result: tool={} bytes={} hash={} retrieve with tool_result_retrieve]\n",
                    resolved_name,
                    output_str.len(),
                    hash
                ));
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tool = %resolved_name,
                    call_id = %tc.id,
                    "compressed tool result store failed"
                );
            }
        }
    }

    let truncated = matches!(
        &result,
        Ok(ToolOutput {
            truncated: true,
            ..
        })
    );

    // Surface the recovery split for the timeline event (Part B):
    // the wire-vs-user inputs + recovery kind/stage make tool-input
    // corrections auditable in the export.
    let (recovery_kind, recovery_stage) = recovery.db_fields();
    let tool_path = args.get("path").and_then(Value::as_str).map(str::to_string);

    // Persist the audit row (GOALS §14 wire-vs-user split). `original`
    // is the model's exact input; `args` is the wire form — equal to the
    // original on a `Clean` call, or the canonical post-repair form when
    // a §12 shape-repair or §13c tool recovery fired. The `recovery`
    // field records which (if any) stage fired.
    // The persisted `tool` is the wire/model form (`resolved_name`): a
    // rebound junk name records the registered tool it resolved to, and a
    // sanitized still-unknown name records its provider-valid form — so on
    // resume the rehydrated assistant turn carries a name that keeps
    // tool_use↔tool_result pairing valid and can't 400 the provider. The
    // original (malformed) name rides the `recovery` (`NameRepair.original`)
    // for the §14 wire-vs-user split.
    if let Err(e) = env.session.record_tool_call(ToolCallRow {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        agent: env.agent.name.clone(),
        call_id: tc.id.clone(),
        identity: crate::session::ToolCallProviderIdentity::from_provider_call(
            env.session.active_provider().as_deref().unwrap_or(""),
            env.session.active_model().as_deref().unwrap_or(""),
            tc.id.clone(),
            tc.call_id.clone(),
        ),
        tool: resolved_name.to_string(),
        path: tool_path,
        original_input_json: original.clone(),
        wire_input_json: args.clone(),
        recovery: recovery.clone(),
        hard_fail,
        exit_code,
        sandbox_enabled: sandbox_meta.as_ref().is_some_and(|m| m.enabled),
        sandboxed: sandbox_meta.as_ref().is_some_and(|m| m.confined),
        sandbox_unavailable_reason: sandbox_meta
            .as_ref()
            .and_then(|m| m.unavailable_reason.clone()),
        output: output_str.clone(),
        truncated,
        duration_ms,
        llm_mode: env.agent.llm_mode,
        shape_fingerprint: repair_fingerprint.clone(),
        hint: hint_value.clone(),
    }) {
        // Auditing must not break the live conversation. Log and
        // continue — the model still sees the tool result.
        tracing::warn!(error = %e, tool = %resolved_name, "persisting tool_call_event failed");
    }

    // Timeline event (Part B), sourced from / consistent with the
    // `tool_call_events` audit row above. The `call_id` here is the
    // model's per-tool-call id (`tc.id`), which is distinct from the
    // round-trip `call_id` (above) — both correlations matter. The
    // `sandbox` sub-object is present only for `bash` (Part B); it flows
    // verbatim into `events.json` on export with no exporter change.
    let mut event_data = serde_json::json!({
        "tool": resolved_name,
        "original_input": original,
        "wire_input": args,
        "recovery_kind": recovery_kind,
        "recovery_stage": recovery_stage,
        "hard_fail": hard_fail,
        "output": output_str.clone(),
        "truncated": truncated,
        "duration_ms": duration_ms,
    });
    // Name-repair surfacing (§14): when the emitted tool NAME was repaired
    // (rebound or charset-sanitized), `tool` above is the wire/model form;
    // the original malformed name (from `NameRepair.original`) rides here
    // so the user timeline can show it with the recovery chip. Present
    // only when a name repair actually fired — a clean exact name omits it.
    if let Recovery::NameRepair { original: orig, .. } = &recovery {
        event_data["original_tool"] = serde_json::json!(orig);
    }
    if let Some(meta) = &sandbox_meta
        && let Ok(meta_val) = serde_json::to_value(meta)
    {
        event_data["sandbox"] = meta_val;
    }
    if let Some(meta) = &resource_meta
        && let Ok(meta_val) = serde_json::to_value(meta)
    {
        event_data["resource"] = meta_val;
    }
    // `bash` exit code (export-audit fidelity): the authoritative structured
    // source for "which bash calls failed", so an auditor never has to regex
    // the human-readable `exit: N` line out of `output` (which is kept for
    // backward compatibility). Present only for `bash` calls that actually
    // ran a shell — `None` (key omitted) on spawn/timeout/cancel paths and
    // on every non-`bash` tool.
    if let Some(code) = exit_code {
        event_data["exit_code"] = serde_json::json!(code);
    }
    // Post-result hint (`engine::bash_hints`): the user-side `data.hint`
    // surface (`{ kind, text, severity }`), surfaced as a TUI chip and
    // ridden along on export with no schema change. Present only when a
    // rule fired on this `bash` call; the wire-side append lives on
    // `wire_output` below (wire-vs-user split, GOALS §14).
    if let Some(hint) = &hint_value {
        event_data["hint"] = hint.clone();
    }
    if let Some(sidecar) = &output_sidecar {
        event_data["output_sidecar"] = sidecar.clone();
    }
    // Rejected-call event (export-audit fidelity): emitted just BEFORE the
    // (hard-fail) `tool_call` row so a hallucinated / unrepairable call is a
    // one-query check on its own event type, not conflated with execution
    // failures. The `tool_call` row still records the diagnostic the model
    // saw; this names *why* it never dispatched.
    if let Some(reason) = rejection_reason
        && let Err(e) =
            env.session
                .record_tool_rejected(&env.agent.name, &tc.id, resolved_name, reason)
    {
        tracing::warn!(error = %e, tool = %resolved_name, "record tool_rejected event failed");
    }
    let tool_call_seq = match env.session.record_event(
        crate::db::session_log::SessionEventKind::ToolCall,
        Some(&env.agent.name),
        Some(&tc.id),
        &event_data,
    ) {
        Ok(seq) => Some(seq),
        Err(e) => {
            tracing::warn!(error = %e, tool = %resolved_name, "record tool_call event failed");
            None
        }
    };
    if hard_fail {
        let _ = env
            .tx
            .send(TurnEvent::ToolError {
                agent: env.agent.name.clone(),
                call_id: tc.id.clone(),
                tool: resolved_name.to_string(),
                error: event_data["output"].as_str().unwrap_or("").to_string(),
                kind: fail_kind.unwrap_or(crate::engine::tool::ToolFailKind::Execution),
                seq: tool_call_seq,
            })
            .await;
    } else {
        let _ = env
            .tx
            .send(TurnEvent::ToolEnd {
                agent: env.agent.name.clone(),
                call_id: tc.id.clone(),
                tool: resolved_name.to_string(),
                output: event_data["output"].as_str().unwrap_or("").to_string(),
                truncated,
                seq: tool_call_seq,
                hint: bash_hint.as_ref().map(|h| h.user_chip.text.clone()),
            })
            .await;
    }
    if lifecycle_started {
        let lifecycle_status = if repeated_recoverable_tool_call_reject {
            "blocked_recoverable_repeat_guard"
        } else if loop_guard_reject {
            "blocked_loop_guard"
        } else if gate_blocked {
            "blocked_safety_gate"
        } else if hard_fail {
            "failed"
        } else {
            "completed"
        };
        let dispatched =
            !(repeated_recoverable_tool_call_reject || loop_guard_reject || gate_blocked);
        let mut completed_data = serde_json::json!({
            "tool": resolved_name,
            "status": lifecycle_status,
            "dispatched": dispatched,
            "hard_fail": hard_fail,
            "output": event_data["output"].clone(),
            "truncated": truncated,
            "duration_ms": duration_ms,
        });
        if let Some(code) = exit_code {
            completed_data["exit_code"] = serde_json::json!(code);
        }
        if let Some(meta) = &sandbox_meta
            && let Ok(meta_val) = serde_json::to_value(meta)
        {
            completed_data["sandbox"] = meta_val;
        }
        if let Some(meta) = &resource_meta
            && let Ok(meta_val) = serde_json::to_value(meta)
        {
            completed_data["resource"] = meta_val;
        }
        if let Some(hint) = &hint_value {
            completed_data["hint"] = hint.clone();
        }
        if let Err(e) = env.session.record_event(
            crate::db::session_log::SessionEventKind::ToolCallCompleted,
            Some(&env.agent.name),
            Some(&tc.id),
            &completed_data,
        ) {
            tracing::warn!(error = %e, tool = %resolved_name, "record tool_call_completed event failed");
        }
    }

    // §12 correction hints → the WIRE tool_result the model reads
    // (implementation note). When hinting is enabled and
    // ≥1 rule fired, each hint is prepended as a terse
    // `<repair_note>…</repair_note>` line so a weak model learns the
    // correction it would otherwise repeat. This is a wire-vs-user split on
    // the OUTPUT (§14): the user-facing `output_str` was already emitted
    // (`ToolEnd`) and persisted unchanged above; only the model's history
    // copy carries the notes. Off / no-hint → `wire_output` == `output_str`,
    // byte-identical to today.
    let mut wire_output = if repair_hints.is_empty() {
        output_str
    } else {
        let mut prefixed = String::new();
        for hint in &repair_hints {
            prefixed.push_str("<repair_note>");
            prefixed.push_str(&repair::repair_note_for_prompt(hint));
            prefixed.push_str("</repair_note>\n");
        }
        prefixed.push_str(&output_str);
        prefixed
    };
    // Failed-command verification guard → the WIRE tool_result
    // (implementation note). When a `bash`
    // command exits NON-ZERO (or is signaled — `exit_code == None` on a
    // non-hard-failed bash run), make the failure unmistakable: a prominent
    // `FAILED (exit N)` / `FAILED (signaled)` marker at the TOP of the body
    // plus a one-line non-verification nudge at the tail. Exit-code-based
    // only (no cargo/test/git keywords, no stderr heuristics — an exit-0
    // command, even with non-empty stderr, gets nothing). WIRE-side only
    // (GOALS §14): the user-facing `output_str` was already emitted/persisted
    // unchanged, the structured `exit_code` field and approval/escalation
    // logic are untouched, and the existing trailing `exit:` line stays
    // (the marker is additive). DETERMINISTIC ORDER vs the bash-hint line
    // below: marker at the head, then the original body, then the nudge,
    // then (if a hint rule fired) the `--- hint(...)` line — the nudge and
    // the hint line both survive on a failing command that also trips a
    // rule, neither clobbering the other. The marker is a plain prefix line
    // and never a `stdout:`/`stderr:`/`exit:` line, so `split_bash_body`
    // (which already ran on the un-marked `raw_output` above) is unaffected.
    if !hard_fail && resolved_name == "bash" {
        wire_output = crate::engine::bash_hints::apply_failure_guard(wire_output, exit_code);
    }
    // Post-result bash hint → the WIRE tool_result (`bash-result-
    // hint-layer.md`). After the existing `stdout:`/`stderr:`/`exit:` block
    // (and the failure guard above, if any), one blank line, then a single
    // `--- hint(<rule_id>): <wire_text>` line the model can distinguish from
    // real output. User-facing `output_str` was already emitted/persisted
    // unchanged (wire-vs-user split §14); only the model's history copy
    // carries this line. The wire_text is itself codebase-agnostic and never
    // contains a secret, but it still flows through the §7 redaction
    // chokepoint via this history → next-request path, so no extra scrub is
    // needed.
    if let Some(hint) = &bash_hint {
        if !wire_output.ends_with('\n') {
            wire_output.push('\n');
        }
        wire_output.push_str(&format!("\n--- hint({}): {}\n", hint.kind, hint.wire_text));
    }
    // Loop-collapse on the WIRE history (`loop-collapse-structural-
    // dedup.md`). When the loop guard rejected this call, the contiguous run
    // of identical rejected `(tool, args)` calls is represented by exactly
    // ONE synthesized message — `wire_output` here — instead of N. Before
    // pushing it, strip the immediately-preceding collapse pair(s) for the
    // same signature so a fresh fire UPDATES the single message's count
    // rather than appending a second (idempotence). The USER timeline and
    // the session-DB rows are untouched — each attempt was already emitted
    // (`ToolError`) and persisted (`record_tool_call`) above; this rewrites
    // only the wire projection the request builder serializes (GOALS §14).
    // This busts the prompt-cache suffix from the collapse point on cache-
    // having providers, but a thrashing model busts it anyway — escaping the
    // loop and shrinking context wins, and it is pure savings for the
    // no-cache local cohort (priority #1).
    if loop_guard_reject {
        collapse_loop_run(history, &args, resolved_name);
    }
    history.push(tool_result_message(tc, wire_output));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{Approver, store::GrantStore};
    use crate::config::extended::ApprovalMode;
    use crate::engine::message::OneOrMany;
    use async_trait::async_trait;
    use rig::message::{AssistantContent, ToolFunction, ToolResultContent, UserContent};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct EchoTool;

    #[async_trait]
    impl crate::engine::tool::Tool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn description(&self) -> &str {
            "Echo test input."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "x-cockpit-aliases": ["message"]
                    }
                },
                "required": ["text"]
            })
        }

        async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text(
                args.get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ))
        }
    }

    struct FailTool;

    #[async_trait]
    impl crate::engine::tool::Tool for FailTool {
        fn name(&self) -> &str {
            "fail"
        }

        fn description(&self) -> &str {
            "Fail for dispatch tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            anyhow::bail!("intentional failure")
        }
    }

    struct TruncatedTool;

    #[async_trait]
    impl crate::engine::tool::Tool for TruncatedTool {
        fn name(&self) -> &str {
            "big"
        }

        fn description(&self) -> &str {
            "Return truncated test output."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::truncated_text("large output"))
        }
    }

    struct NeverCalledTool {
        name: &'static str,
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for NeverCalledTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "Fails the test if dispatch reaches the tool body."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "command": { "type": "string" },
                    "url": { "type": "string" }
                }
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.called.store(true, Ordering::SeqCst);
            anyhow::bail!("NeverCalledTool was dispatched")
        }
    }

    struct BashFixtureTool;

    #[async_trait]
    impl crate::engine::tool::Tool for BashFixtureTool {
        fn name(&self) -> &str {
            "bash"
        }

        fn description(&self) -> &str {
            "Synthetic bash output for dispatch assembly tests."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                },
                "required": ["command"]
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("stdout:\nbody\nstderr:\nerr\nexit: 1").with_exit_code(1))
        }
    }

    fn test_model() -> Arc<Model> {
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        Arc::new(
            Model::for_provider_with_env(
                &cfg,
                "local",
                "test-model",
                Arc::new(RedactionTable::empty()),
                |_| None,
            )
            .expect("test model builds without network"),
        )
    }

    fn test_agent(tools: ToolBox) -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools,
            model: test_model(),
            params: ModelParams::default(),
            scan_tool_results: false,
            llm_mode: crate::config::extended::LlmMode::Normal,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn tool_call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: "call-1".to_string(),
            call_id: Some("provider-call-1".to_string()),
            function: ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    fn tool_ctx(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> ToolCtx {
        ToolCtx {
            agent_id: "Build".to_string(),
            llm_mode: crate::config::extended::LlmMode::Normal,
            locks: Arc::new(crate::locks::LockManager::from_db(session.db.clone()).unwrap()),
            session,
            cwd: root.to_path_buf(),
            redact: Arc::new(RedactionTable::empty()),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: false,
            has_bash: false,
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: None,
        }
    }

    fn tool_ctx_with_approver(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> ToolCtx {
        let mut ctx = tool_ctx(session.clone(), root, tx);
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let store = GrantStore::new(session.db.clone(), session.id, root.to_path_buf());
        ctx.approver = Some(Arc::new(Approver::new(
            store,
            session.db.clone(),
            session.id,
            "Build",
            hub,
        )));
        ctx
    }

    fn test_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(Session::create(db, root.to_path_buf(), "Build").unwrap())
    }

    fn push_assistant_call(history: &mut Vec<Message>, call: &ToolCall) {
        history.push(Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(call.clone())),
        });
    }

    fn last_tool_result_text(history: &[Message]) -> String {
        let Some(Message::User { content }) = history.last() else {
            panic!("expected trailing tool result, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => result.content.iter().find_map(|result_part| {
                    if let ToolResultContent::Text(text) = result_part {
                        Some(text.text.clone())
                    } else {
                        None
                    }
                }),
                _ => None,
            })
            .expect("tool result text")
    }

    fn assistant_call_args(history: &[Message]) -> Value {
        let Some(Message::Assistant { content, .. }) = history.first() else {
            panic!("expected assistant call, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| {
                if let AssistantContent::ToolCall(call) = part {
                    Some(call.function.arguments.clone())
                } else {
                    None
                }
            })
            .expect("assistant tool call")
    }

    #[tokio::test]
    async fn execute_ordinary_call_happy_path_records_events_audit_and_history() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "hello" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(history.len(), 2);
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolEnd { tool, output, .. }) if tool == "echo" && output == "hello")
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "echo");
        assert_eq!(rows[0].output, "hello");
    }

    #[tokio::test]
    async fn execute_ordinary_call_unknown_tool_records_rejection_without_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new();
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call("missing", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "missing", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(history.len(), 2);
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "missing")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { tool, error, .. }) if tool == "missing" && error.contains("unknown tool"))
        );
        let rows = session
            .db
            .list_tool_calls_for_session(session.id)
            .expect("tool audit rows load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "missing");
        assert!(rows[0].hard_fail);
        let rejected = session
            .db
            .list_session_events(session.id)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_rejected")
            .expect("tool_rejected event");
        assert_eq!(rejected.data["reason"], "not_in_advertised_set");
    }

    #[tokio::test]
    async fn dispatch_loop_guard_reject_does_not_dispatch_and_collapses_wire_history() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "echo",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(16);
        let ctx = tool_ctx_with_approver(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 1,
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "text": "again" }));
        let mut history = Vec::new();

        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 2);

        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            !called.load(Ordering::SeqCst),
            "loop-guard rejection must synthesize a result without dispatching"
        );
        assert_eq!(
            history.len(),
            2,
            "second contiguous loop rejection replaces the prior collapse pair"
        );
        let wire = last_tool_result_text(&history);
        assert!(wire.contains("Loop blocked"), "{wire}");
        assert!(wire.contains("called 2 times"), "{wire}");
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("Loop blocked"))
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "echo")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("Loop blocked"))
        );
    }

    #[tokio::test]
    async fn dispatch_safety_gate_block_does_not_dispatch_and_uses_gate_result() {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NeverCalledTool {
            name: "bash",
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.set_approval_mode(ApprovalMode::Auto);
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call(
            "bash",
            serde_json::json!({ "command": "curl https://example.test" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        let _gate =
            set_safety_gate_test_override(GateOutcome::Block(gate_block_message("bash", true)));

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            !called.load(Ordering::SeqCst),
            "safety-gate block must not dispatch the gated tool"
        );
        let wire = last_tool_result_text(&history);
        assert!(
            wire.contains("command-safety gate could not reach"),
            "{wire}"
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.tool, "bash");
        let event = session
            .db
            .list_session_events(session.id)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "tool_call_completed")
            .expect("tool_call_completed event");
        assert_eq!(event.data["status"], "blocked_safety_gate");
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "bash")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("command-safety gate"))
        );
    }

    #[tokio::test]
    async fn dispatch_bash_wire_output_orders_failure_guard_body_nudge_then_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(BashFixtureTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        session.push_recent_bash("rg foo src".to_string(), Some(1));
        session.push_recent_bash("rg foo src | grep -v one".to_string(), Some(1));
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call(
            "bash",
            serde_json::json!({ "command": "rg foo src | grep -v one | grep -v two" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "bash", Recovery::Clean, None)
            .await
            .unwrap();

        let wire = last_tool_result_text(&history);
        let guard = wire.find("FAILED (exit 1)").expect("failure guard");
        let body = wire.find("stdout:\nbody").expect("bash body");
        let nudge = wire
            .find("This command FAILED (exit 1)")
            .expect("failure nudge");
        let hint = wire
            .find("--- hint(filter_refinement_loop):")
            .expect("bash hint");
        assert_eq!(guard, 0, "{wire}");
        assert!(guard < body && body < nudge && nudge < hint, "{wire}");
    }

    #[tokio::test]
    async fn execute_ordinary_call_shape_repair_rewrites_history_and_wire_note_only() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(EchoTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: true,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call("echo", serde_json::json!({ "message": "hello" }));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "echo", Recovery::Clean, None)
            .await
            .unwrap();

        assert_eq!(
            assistant_call_args(&history),
            serde_json::json!({ "text": "hello" })
        );
        let wire_result = last_tool_result_text(&history);
        assert!(wire_result.contains("<repair_note>"), "{wire_result}");
        assert!(wire_result.ends_with("hello"), "{wire_result}");
        assert!(matches!(rx.recv().await, Some(TurnEvent::ToolStart { .. })));
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolEnd { output, .. }) if output == "hello")
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            row.original_input_json,
            serde_json::json!({ "message": "hello" })
        );
        assert_eq!(row.wire_input_json, serde_json::json!({ "text": "hello" }));
        assert_eq!(row.output, "hello");
    }

    #[tokio::test]
    async fn execute_ordinary_call_hard_fail_records_tool_error_and_audit_row() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(FailTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call("fail", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "fail", Recovery::Clean, None)
            .await
            .unwrap();

        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolStart { tool, .. }) if tool == "fail")
        );
        assert!(
            matches!(rx.recv().await, Some(TurnEvent::ToolError { error, .. }) if error.contains("intentional failure"))
        );
        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(row.tool, "fail");
        assert!(row.hard_fail);
        assert!(row.output.contains("intentional failure"));
    }

    #[tokio::test]
    async fn execute_ordinary_call_truncated_result_gets_compressed_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = ToolBox::new().with(Arc::new(TruncatedTool));
        let agent = test_agent(tools.clone());
        let session = test_session(tmp.path());
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            cwd: tmp.path(),
        };
        let call = tool_call("big", serde_json::json!({}));
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);

        execute_ordinary_call(&env, &mut history, &call, "big", Recovery::Clean, None)
            .await
            .unwrap();

        let row = session
            .db
            .list_tool_calls_for_session(session.id)
            .unwrap()
            .pop()
            .unwrap();
        assert!(row.truncated);
        assert!(
            row.output.contains("[compressed tool result:"),
            "{}",
            row.output
        );
        assert!(
            last_tool_result_text(&history).contains("[compressed tool result:"),
            "{history:?}"
        );
    }
}
