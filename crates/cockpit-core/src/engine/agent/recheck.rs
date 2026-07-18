use super::*;

#[derive(Clone)]
pub(crate) struct ResultRecheckCtx {
    pub agent_id: String,
    pub session: Arc<Session>,
    pub cwd: std::path::PathBuf,
    pub redact: Arc<RedactionTable>,
    pub interrupts: Arc<crate::engine::interrupt::InterruptHub>,
}

impl ResultRecheckCtx {
    pub(super) fn from_tool_ctx(ctx: &ToolCtx) -> Self {
        Self {
            agent_id: ctx.agent_id.clone(),
            session: ctx.session.clone(),
            cwd: ctx.cwd.clone(),
            redact: ctx.redact.clone(),
            interrupts: ctx.interrupts.clone(),
        }
    }
}

/// What to do with a flagged tool result given its injection-check
/// outcome. Pure routing decision, split out so it's unit-testable without
/// a live utility model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecheckAction {
    /// Deliver the result unchanged (`low` rating).
    Pass,
    /// Deliver with a warn chip (`medium` rating).
    Warn,
    /// Block and ask the user — allow / drop / edit (`high` rating).
    Block,
    /// Ask before delivering a result that met the configured result threshold.
    Ask,
    /// Re-check could not run; deliver with a "could not re-check" chip.
    /// Never silently asserts the high-risk content is clean — surfaces it.
    Unavailable,
}

/// Map an injection-check outcome to the result-recheck action
/// (implementation note). `high` blocks, `medium`
/// warns, `low` (and the never-rated `off`) pass, and an unavailable check
/// surfaces a "could not re-check" chip.
pub(super) fn result_recheck_action(
    outcome: crate::engine::injection_check::CheckOutcome,
    threshold: crate::config::extended::InjectionThreshold,
    result_action: crate::config::extended::InjectionResultAction,
) -> RecheckAction {
    use crate::config::extended::{InjectionResultAction, InjectionThreshold};
    use crate::engine::injection_check::CheckOutcome;
    match outcome {
        CheckOutcome::Rated(rating) if threshold.blocks(rating) => match result_action {
            InjectionResultAction::Block => RecheckAction::Block,
            InjectionResultAction::Ask => RecheckAction::Ask,
        },
        CheckOutcome::Rated(InjectionThreshold::Medium) => RecheckAction::Warn,
        CheckOutcome::Rated(_) => RecheckAction::Pass,
        CheckOutcome::Unavailable => RecheckAction::Unavailable,
    }
}

/// Route a flagged tool result through the shared injection-check mechanism
/// (implementation note). Returns the text that should
/// enter history (and the audit row — wire = user, GOALS §14):
///
/// - `high` → BLOCK and ask the user (allow through / drop / edit), same
///   override UX as the inbound prompt-injection block.
/// - `medium` → deliver with a warn chip.
/// - `low` → deliver unchanged.
/// - unavailable → deliver with a "could not re-check" warn chip (the call
///   already passed the gate; mirror fail-safe by flagging it rather than
///   silently asserting it's clean).
pub(crate) async fn result_recheck(
    output: &str,
    ctx: &ResultRecheckCtx,
    tx: &mpsc::Sender<TurnEvent>,
) -> Result<String> {
    use crate::config::extended::resolve_injection_guard;
    use crate::engine::injection_check::check;

    let (extended, providers) = crate::auto_title::load_configs_for(&ctx.cwd);
    let guard = resolve_injection_guard(&ctx.cwd);
    if guard.threshold == crate::config::extended::InjectionThreshold::Off
        || ctx.session.approval_mode() == crate::config::extended::ApprovalMode::Yolo
    {
        return Ok(output.to_string());
    }
    let model_ref = extended.guard_model_ref();

    let outcome = check(
        model_ref,
        &providers,
        ctx.redact.clone(),
        ctx.session.trusted_only_flag(),
        None,
        &guard.check_prompt,
        output,
    )
    .await;
    match result_recheck_action(outcome, guard.threshold, guard.result_action) {
        RecheckAction::Block => result_injection_override(output, ctx, tx).await,
        RecheckAction::Ask => result_injection_ask(output, ctx, tx).await,
        RecheckAction::Warn => {
            let _ = tx
                .send(TurnEvent::Notice {
                    text:
                        "tool result rated `medium` for prompt injection — delivering with caution"
                            .to_string(),
                })
                .await;
            Ok(output.to_string())
        }
        RecheckAction::Pass => Ok(output.to_string()),
        RecheckAction::Unavailable => {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "tool result could not be re-checked for prompt injection (utility \
                           model unset or unavailable) — delivering unverified"
                        .to_string(),
                })
                .await;
            Ok(output.to_string())
        }
    }
}
