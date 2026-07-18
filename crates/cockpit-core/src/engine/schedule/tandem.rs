//! Model-comparison tandem (shadow) inference dispatch
//! (implementation note).
//!
//! Session-only "model comparison" mode shadows every SUBSTANTIVE inference
//! request (primary-agent turns AND `builder`/`explore`/`docs` subagent turns —
//! never utility calls) to one or more user-selected tandem `(provider,
//! model)` pairs on other providers. Each tandem request:
//!
//! - reuses the **exact same assembled, already-redaction-scrubbed body** the
//!   main model received ([`crate::engine::model::Model::complete_tandem`]),
//!   so redaction stays non-bypassable and the comparison is on identical
//!   input;
//! - runs as fire-and-forget background async work dispatched from the single
//!   `turn` chokepoint ([`crate::engine::agent::turn`]) — every substantive
//!   turn (driver-stack primary/interactive + leaf `builder`/`explore`/`docs`)
//!   funnels through `turn`, so one dispatch site covers them all, concurrent
//!   with the main call and with each other. This is **not** a second async-job
//!   authority: the single [`super::ScheduleAuthority`] owns loop/timer/background/
//!   swarm *scheduling* (jobs that inject into main context, count against
//!   caps, and emit `ScheduleEvent`s); tandem shadows do none of that — they are
//!   DB-only observers with no `ScheduleEvent`, no cap, and no main-context
//!   injection, so dispatching them from `turn` is consistent with the
//!   single-authority policy rather than a competing one;
//! - is a **pure observer**: its output is never executed and never enters any
//!   agent's history. Only the captured outcome is persisted to the session DB
//!   (a `pending` record at dispatch, settled to its terminal status), for
//!   `/export debug` to ship alongside the main model's request.
//!
//! Failure isolation: a tandem erroring / rate-limiting / timing out is
//! captured verbatim as that record's status (errors/timeouts are signal),
//! never retried, and never touches the main loop.

use std::sync::Arc;

use uuid::Uuid;

use crate::engine::message::{Message, ToolDefinition};
use crate::engine::model::{Model, ModelParams};
use crate::session::Session;

use super::DEFAULT_TANDEM_DISPATCH_CAP;

/// One selected tandem (shadow) model: the configured `(provider, model)`
/// identity plus the built completion model to dispatch against.
#[derive(Clone)]
pub struct TandemTarget {
    /// The configured provider id (a key in the `providers` map).
    pub provider: String,
    /// The model id (e.g. `glm-4.6`).
    pub model: String,
    /// The built completion model, sharing the daemon's shutdown gate.
    pub handle: Arc<Model>,
}

impl TandemTarget {
    /// The `provider/model` label used in the dialog + export filenames.
    pub fn label(&self) -> String {
        format!("{}/{}", self.provider, self.model)
    }
}

impl std::fmt::Debug for TandemTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Model` isn't `Debug`; the identity is all a debug view needs.
        f.debug_struct("TandemTarget")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// The session's in-memory tandem set (`/model-comparison`). **Empty = feature
/// off** — there is no separate enable flag. Session-only / in-memory: mutated
/// via a `DriverControl` variant, never written to config, reverts on restart.
#[derive(Clone, Default)]
pub struct TandemSet {
    targets: Vec<TandemTarget>,
}

fn cap_tandem_targets<T>(targets: Vec<T>) -> Vec<T> {
    targets
        .into_iter()
        .take(DEFAULT_TANDEM_DISPATCH_CAP)
        .collect()
}

impl TandemSet {
    /// Replace the whole set (the multiselect's resolved selection), capped
    /// so one turn cannot fan out unbounded detached shadow requests.
    pub fn set(&mut self, targets: Vec<TandemTarget>) {
        self.targets = cap_tandem_targets(targets);
    }

    /// `true` when at least one tandem model is selected — i.e. the feature is
    /// on for this session.
    pub fn is_enabled(&self) -> bool {
        !self.targets.is_empty()
    }

    /// The selected targets.
    pub fn targets(&self) -> &[TandemTarget] {
        &self.targets
    }
}

/// One substantive turn's inputs, captured inside [`crate::engine::agent::turn`]
/// right before the main call and handed to [`dispatch_turn`]. Owned clones so
/// each spawned tandem task is self-contained and the main loop is unaffected.
/// The
/// `(system, history, prompt, tools, params)` are the SAME post-redaction
/// values the main turn used, so [`Model::complete_tandem`] reassembles a
/// byte-identical body.
pub struct TandemDispatch {
    /// The main inference call this turn's tandems shadow (the driver's
    /// per-turn `call_id`).
    pub parent_call_id: String,
    /// The agent whose turn is shadowed (primary or `builder`/`explore`/`docs`).
    pub agent: String,
    pub system: String,
    pub history: Vec<Message>,
    pub prompt: Message,
    pub tools: Vec<ToolDefinition>,
    pub params: ModelParams,
}

/// Dispatch one substantive turn's tandem shadows. Called from the single
/// `turn` chokepoint ([`crate::engine::agent::turn`]) for every shadowed turn
/// (driver-stack primary/interactive + leaf `builder`/`explore`/`docs`), so all
/// dispatch funnels through here. A no-op when the set is empty (feature off).
pub fn dispatch_turn(session: &Arc<Session>, set: &TandemSet, dispatch: TandemDispatch) {
    spawn_all(session, set, dispatch);
}

/// Spawn one detached tandem task per target. Each task records a `pending`
/// row at dispatch (so an in-flight tandem unsettled at export time still
/// exports a `pending` record), runs the single-shot
/// [`Model::complete_tandem`], then updates the row to its terminal status +
/// captured response/usage. Fire-and-forget: tandem results go only to the DB,
/// never to main context, so these tasks emit no `ScheduleEvent` and are not
/// registered against the loop/swarm concurrency caps.
fn spawn_all(session: &Arc<Session>, set: &TandemSet, dispatch: TandemDispatch) {
    if !set.is_enabled() {
        return;
    }
    let TandemDispatch {
        parent_call_id,
        agent,
        system,
        history,
        prompt,
        tools,
        params,
    } = dispatch;

    // The tandem dispatch fires CONCURRENTLY with the main call (before its
    // `inference_request` event is recorded), so the parent's timeline `seq`
    // isn't known yet here. The export resolves it from the parent's
    // `inference_request` event via `parent_call_id` (the durable join key);
    // `parent_seq` is left `None` at the DB layer.
    let parent_seq: Option<i64> = None;

    for target in set.targets() {
        let session = session.clone();
        let target = target.clone();
        let parent_call_id = parent_call_id.clone();
        let agent = agent.clone();
        let system = system.clone();
        let history = history.clone();
        let prompt = prompt.clone();
        let tools = tools.clone();
        let params = params.clone();
        // A per-(parent call, tandem model) row id.
        let row_id = format!("tandem-{}", Uuid::new_v4().simple());

        tokio::spawn(async move {
            use crate::db::session_log::InferenceRequestStatus;

            // Dispatch-time pending record (no response yet). Best-effort —
            // auditing must never break anything (and there is nothing to
            // break: the main loop never observes this task).
            let pending_body = target
                .handle
                .assemble_dispatch_request(&system, &history, &prompt, &tools, &params);
            if let Err(e) = session.record_tandem_inference(
                &row_id,
                &parent_call_id,
                parent_seq,
                Some(&agent),
                &target.provider,
                &target.model,
                &pending_body,
                None,
                None,
                InferenceRequestStatus::Pending,
            ) {
                tracing::warn!(error = %e, "record tandem_inference (pending) failed");
            }

            // Single-shot, no retry, independent generous timeout. Captures the
            // first outcome verbatim (errors/timeouts included).
            let outcome = target
                .handle
                .complete_tandem(&system, &history, &prompt, &tools, &params)
                .await;

            if let Err(e) = session.record_tandem_inference(
                &row_id,
                &parent_call_id,
                parent_seq,
                Some(&agent),
                &target.provider,
                &target.model,
                &outcome.request,
                outcome.response.as_ref(),
                outcome.usage.as_ref(),
                outcome.status,
            ) {
                tracing::warn!(error = %e, "record tandem_inference (settle) failed");
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tandem_target_cap_defaults_to_four() {
        let capped = cap_tandem_targets(vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(capped, vec![1, 2, 3, 4]);
    }
}
