//! Interrupt wakeup hub — the bridge that lets a blocked structural
//! tool (`question`, GOALS §3b) wait on a human answer that arrives,
//! out of band, on the daemon's `ResolveInterrupt` path.
//!
//! ## Why this exists
//!
//! The `question` tool runs inside the driver's tool-dispatch loop. It
//! must *block* until the user answers. But the answer round-trips
//! daemon ↔ client over NDJSON and lands in the **session worker's**
//! work loop ([`crate::daemon::session_worker`]) as
//! `SessionWork::ResolveInterrupt` — a different task from the one the
//! tool call is suspended in. The two need a rendezvous.
//!
//! The hub is that rendezvous: a shared registry of
//! `interrupt_id -> oneshot::Sender<ResolveResponse>`. The tool
//! [`register`](InterruptHub::register)s a channel, persists the
//! interrupt, emits the `InterruptRaised` event, and awaits the
//! receiver. The worker, on `ResolveInterrupt`, persists the response
//! and calls [`resolve`](InterruptHub::resolve), which fires the
//! matching sender and wakes the tool.
//!
//! ## Headless / no client
//!
//! Nothing in the hub times out. If no interactive client is attached
//! (headless daemon, scheduled run), the interrupt simply parks in the
//! `needs_attention` table and the tool's `await` blocks indefinitely
//! until *some* client answers — the TUI today, the remote dashboard
//! later (GOALS north star). That is the intended behavior.
//!
//! ## Single authority, like the lock manager
//!
//! One hub per session worker; both the driver (which threads it into
//! every [`crate::engine::tool::ToolCtx`]) and the worker's resolve
//! handler hold an `Arc` to the same instance. The `Mutex` is held only
//! for map insert/remove — never across an `.await`.

use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::sync::lock_or_recover;
use anyhow::Context as _;

use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use crate::{
    daemon::{
        EventSender, SharedRedactionTable, current_redaction,
        proto::{self, InterruptQuestionSet, ResolveResponse},
        send_current_event, set_current_redaction,
    },
    db::needs_attention::InterruptParkPayload,
};

tokio::task_local! {
    static CURRENT_INTERRUPT_PARK_PAYLOAD: RefCell<InterruptParkPayload>;
}

tokio::task_local! {
    static CURRENT_PRE_RESOLVED_INTERRUPTS: RefCell<PreResolvedInterrupts>;
}

// An approved host operation is not a plain boolean.  The parked approval
// continuation hands a typed, exact operation capability to the enclosing
// production tool-effect boundary.  That boundary owns the definitive
// success/rejection receipt; dropping the scope because of cancellation,
// timeout, or a task panic records submission-unknown rather than leaving a
// replayable approval behind.
tokio::task_local! {
    static CURRENT_HOST_APPROVAL_HANDOFFS: RefCell<HostApprovalEffectScope>;
}

struct HostApprovalEffectScope {
    handoffs: Vec<HostApprovalEffectHandoff>,
    /// Stable name of the actual host-effect boundary that owns every
    /// capability registered in this task-local scope.  It is selected by the
    /// concrete dispatcher, never by the prompt or resolver, and becomes part
    /// of the durable completion receipt for audit/reconciliation.
    boundary: &'static str,
    /// Every cancellation generation that encloses this concrete effect.
    /// Nested effect wrappers are not independent host-effect owners: they
    /// share the same handoffs, so dropping an inner token used to let an
    /// outer successful result publish `succeeded` after the inner backend
    /// boundary had been cancelled. Keep *all* generations and make any one
    /// of them terminally win until the common outermost owner writes the
    /// receipt.
    cancellations: Vec<tokio_util::sync::CancellationToken>,
    /// The exact boundary can override the wrapper's result classifier when
    /// its public return type does not preserve the real effect outcome (for
    /// example ordinary dispatch records a `ToolOutput` before it returns its
    /// broader audit result). `None` is deliberately conservative: a dropped
    /// or erroring boundary becomes submission-unknown.
    outcome: Option<bool>,
}

#[derive(Debug)]
struct HostApprovalEffectHandoff {
    db: crate::db::Db,
    /// The same real QuestionTool continuation that settled the operation.
    /// A ready/dispatching database row alone is not sufficient authority to
    /// reach an effect boundary after recovery.
    authority: crate::agent_tree::HostApprovalAuthority,
    session_id: Uuid,
    agent_instance_id: Uuid,
    interrupt_id: Uuid,
    operation_id: Uuid,
    operation_kind: String,
    canonical_input_json: String,
    input_digest: String,
    /// Set only after the durable final-dispatch claim succeeds. Until then
    /// this is a ready capability, not permission to touch the host; dropping
    /// it records a known not-submitted rejection rather than an ambiguous
    /// external handoff.
    claimed: bool,
    terminalized: bool,
}

impl HostApprovalEffectHandoff {
    fn new(
        db: crate::db::Db,
        authority: crate::agent_tree::HostApprovalAuthority,
        session_id: Uuid,
        agent_instance_id: Uuid,
        interrupt_id: Uuid,
        operation: crate::agent_tree::HostApprovalOperation,
    ) -> Self {
        Self {
            db,
            authority,
            session_id,
            agent_instance_id,
            interrupt_id,
            operation_id: operation.operation_id,
            operation_kind: operation.operation_kind,
            canonical_input_json: operation.canonical_input_json,
            input_digest: operation.input_digest,
            claimed: false,
            terminalized: false,
        }
    }

    fn db_authority(
        &self,
    ) -> anyhow::Result<crate::db::agent_tree_decisions::HostApprovalAuthority> {
        self.authority.db_for_effect_handoff(
            self.session_id,
            self.agent_instance_id,
            self.interrupt_id,
        )
    }

    async fn claim_at_effect_boundary(
        &mut self,
        concrete_effects_json: String,
    ) -> crate::db::agent_tree_decisions::HostApprovalEffectFence {
        if self.claimed {
            // A single selected operation can contain an ordered persistent
            // mutation plus its external execution. The first one already
            // made this operation irrevocable, but a later concrete boundary
            // must still prove it is another exact member of that *same*
            // selected candidate; a claimed path grant cannot become generic
            // permission for an unrelated command in the shared scope.
            let Ok(authority) = self.db_authority() else {
                return crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive;
            };
            return if self
                .db
                .claimed_host_approval_effect_handoff_matches_candidate(
                    authority,
                    self.interrupt_id,
                    self.session_id,
                    self.agent_instance_id,
                    self.operation_id,
                    self.operation_kind.clone(),
                    self.canonical_input_json.clone(),
                    self.input_digest.clone(),
                    concrete_effects_json,
                )
                .await
                .unwrap_or(false)
            {
                crate::db::agent_tree_decisions::HostApprovalEffectFence::Claimed
            } else {
                crate::db::agent_tree_decisions::HostApprovalEffectFence::DifferentCandidate
            };
        }
        let Ok(authority) = self.db_authority() else {
            return crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive;
        };
        let claim = self
            .db
            .claim_host_approval_effect_handoff(
                authority,
                self.interrupt_id,
                self.session_id,
                self.agent_instance_id,
                self.operation_id,
                self.operation_kind.clone(),
                self.canonical_input_json.clone(),
                self.input_digest.clone(),
                concrete_effects_json,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
            .unwrap_or(crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive);
        if claim == crate::db::agent_tree_decisions::HostApprovalEffectFence::Claimed {
            self.claimed = true;
        }
        claim
    }

    async fn reject_if_unclaimed(mut self) {
        if self.claimed {
            Box::pin(self.mark_submission_unknown()).await;
            return;
        }
        let Ok(authority) = self.db_authority() else {
            return;
        };
        let _ = self
            .db
            .reject_unclaimed_host_approval_final_operation(
                authority,
                self.interrupt_id,
                self.session_id,
                self.agent_instance_id,
                self.operation_id,
                self.operation_kind.clone(),
                self.canonical_input_json.clone(),
                self.input_digest.clone(),
                crate::agent_tree::system_now_unix_ms(),
            )
            .await;
        self.terminalized = true;
    }

    async fn complete_at_effect_boundary(
        mut self,
        boundary: &'static str,
        succeeded: bool,
        cancellations: &[tokio_util::sync::CancellationToken],
    ) {
        if !self.claimed {
            self.reject_if_unclaimed().await;
            return;
        }
        // This is the final in-process fence before publishing success or
        // rejection.  The claim already crossed the irreversible dispatch
        // boundary, so a cancellation observed here is necessarily ambiguous
        // and must be submission-unknown rather than a late success receipt.
        if cancellations
            .iter()
            .any(tokio_util::sync::CancellationToken::is_cancelled)
        {
            self.mark_submission_unknown().await;
            return;
        }
        let receipt = serde_json::json!({
            "boundary": boundary,
            "outcome": if succeeded { "completed" } else { "rejected" },
        })
        .to_string();
        let Ok(authority) = self.db_authority() else {
            self.mark_submission_unknown().await;
            return;
        };
        let completed = self
            .db
            .complete_host_approval_final_operation(
                authority,
                self.interrupt_id,
                self.session_id,
                self.agent_instance_id,
                self.operation_id,
                self.operation_kind.clone(),
                self.canonical_input_json.clone(),
                self.input_digest.clone(),
                succeeded,
                receipt,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await;
        if !matches!(completed, Ok(true)) {
            let Ok(authority) = self.db_authority() else {
                self.terminalized = true;
                return;
            };
            let _ = self
                .db
                .mark_host_approval_final_operation_submission_unknown(
                    authority,
                    self.interrupt_id,
                    self.session_id,
                    self.agent_instance_id,
                    self.operation_id,
                    self.operation_kind.clone(),
                    self.canonical_input_json.clone(),
                    self.input_digest.clone(),
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await;
        }
        self.terminalized = true;
    }

    async fn mark_submission_unknown(mut self) {
        if !self.claimed {
            Box::pin(self.reject_if_unclaimed()).await;
            return;
        }
        let Ok(authority) = self.db_authority() else {
            self.terminalized = true;
            return;
        };
        let _ = self
            .db
            .mark_host_approval_final_operation_submission_unknown(
                authority,
                self.interrupt_id,
                self.session_id,
                self.agent_instance_id,
                self.operation_id,
                self.operation_kind.clone(),
                self.canonical_input_json.clone(),
                self.input_digest.clone(),
                crate::agent_tree::system_now_unix_ms(),
            )
            .await;
        self.terminalized = true;
    }
}

impl Drop for HostApprovalEffectHandoff {
    fn drop(&mut self) {
        if self.terminalized {
            return;
        }
        let db = self.db.clone();
        let authority = self.authority;
        let session_id = self.session_id;
        let agent_instance_id = self.agent_instance_id;
        let interrupt_id = self.interrupt_id;
        let operation_id = self.operation_id;
        let operation_kind = self.operation_kind.clone();
        let canonical_input_json = self.canonical_input_json.clone();
        let input_digest = self.input_digest.clone();
        let claimed = self.claimed;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let Ok(db_authority) =
                    authority.db_for_effect_handoff(session_id, agent_instance_id, interrupt_id)
                else {
                    return;
                };
                if claimed {
                    let _ = db
                        .mark_host_approval_final_operation_submission_unknown(
                            db_authority,
                            interrupt_id,
                            session_id,
                            agent_instance_id,
                            operation_id,
                            operation_kind,
                            canonical_input_json,
                            input_digest,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await;
                } else {
                    let _ = db
                        .reject_unclaimed_host_approval_final_operation(
                            db_authority,
                            interrupt_id,
                            session_id,
                            agent_instance_id,
                            operation_id,
                            operation_kind,
                            canonical_input_json,
                            input_digest,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await;
                }
            });
        } else {
            tracing::error!(
                %session_id,
                %agent_instance_id,
                %operation_id,
                "host approval effect handoff escaped without a runtime for submission-unknown reconciliation"
            );
        }
    }
}

/// Runs one concrete host-effect `boundary` as the owner of all host-approval
/// handoffs raised beneath it. `is_success` translates that boundary's own
/// result shape into a durable success/rejection receipt; `None` preserves the
/// conservative submission-unknown outcome. An exact boundary whose broader
/// result type hides its effect result may instead call
/// [`record_host_approval_effect_boundary_outcome`].
///
/// This is generic rather than tied to `ToolOutput`: ordinary tools use their
/// exit code, while direct host boundaries such as schedule's background
/// launcher use their own successful completion signal. Keeping both under
/// this single scope means an approval can never be consumed by a helper and
/// escape without a concrete owner recording its terminal state.
pub(crate) async fn with_host_approval_effect_scope<T, F, S>(
    boundary: &'static str,
    cancelled: tokio_util::sync::CancellationToken,
    future: F,
    is_success: S,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send,
    T: Send,
    S: Fn(&T) -> Option<bool>,
{
    let future: std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<T>> + Send + '_>,
    > = Box::pin(future);
    // A nested timeout/native-tool wrapper is not a second host effect.  If
    // it installed a fresh task-local scope, an approval raised by the outer
    // pre-dispatch gate would be invisible to the concrete dispatcher and
    // could cross the boundary without its cancellation/revision recheck.
    // Reuse the enclosing capability set and upgrade its receipt boundary to
    // this more concrete owner instead.
    if CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            scope.cancellations.push(cancelled.clone());
        })
        .is_ok()
    {
        // This is an inner, *more concrete* effect boundary.  Reusing the
        // outer handoff collection is correct, but merely returning its
        // future used to discard the inner result classifier.  In the common
        // ordinary-tool shape the outer authorization gate has an opaque
        // `Result<()>` classifier while the timeout dispatcher below it owns
        // the definitive `ToolOutput`; losing that classifier downgraded a
        // successfully claimed operation to `submission_unknown`.
        //
        // Publish the exact inner result into the shared scope.  The outermost
        // scope remains the single terminalizer (so there is no double finish
        // if several wrappers nest), and its cancellation token still wins
        // over a result observed after cancellation.  `None` remains
        // intentionally ambiguous and lets the outer scope use a later,
        // more-specific classifier if one exists.
        let result = future.await;
        if !current_host_approval_effect_scope_is_cancelled()
            && let Some(succeeded) = result.as_ref().ok().and_then(|output| is_success(output))
        {
            record_host_approval_effect_boundary_outcome(succeeded);
        }
        return result;
    }
    CURRENT_HOST_APPROVAL_HANDOFFS
        .scope(
            RefCell::new(HostApprovalEffectScope {
                handoffs: Vec::new(),
                boundary,
                cancellations: vec![cancelled.clone()],
                outcome: None,
            }),
            async move {
                let result = future.await;
                let scope = CURRENT_HOST_APPROVAL_HANDOFFS.with(|slot| {
                    let mut scope = slot.borrow_mut();
                    HostApprovalEffectScope {
                        handoffs: std::mem::take(&mut scope.handoffs),
                        boundary: scope.boundary,
                        cancellations: std::mem::take(&mut scope.cancellations),
                        outcome: scope.outcome.take(),
                    }
                });
                let definitive = if scope
                    .cancellations
                    .iter()
                    .any(tokio_util::sync::CancellationToken::is_cancelled)
                {
                    None
                } else {
                    scope
                        .outcome
                        .or_else(|| result.as_ref().ok().and_then(|output| is_success(output)))
                };
                for handoff in scope.handoffs {
                    if !handoff.claimed {
                        // The enclosing dispatcher returned before any exact
                        // host boundary claimed this ready capability. No
                        // effect was submitted, so this is a known rejection,
                        // not an ambiguous handoff.
                        handoff.reject_if_unclaimed().await;
                    } else if let Some(succeeded) = definitive {
                        handoff
                            .complete_at_effect_boundary(
                                scope.boundary,
                                succeeded,
                                &scope.cancellations,
                            )
                            .await;
                    } else {
                        // Cancellation, timeout, panic, or an opaque error
                        // happened after the final claim. The host may already
                        // have accepted the effect, so recovery must not replay
                        // it and records submission-unknown instead.
                        handoff.mark_submission_unknown().await;
                    }
                }
                result
            },
        )
        .await
}

fn current_host_approval_effect_scope_is_cancelled() -> bool {
    CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            slot.borrow()
                .cancellations
                .iter()
                .any(tokio_util::sync::CancellationToken::is_cancelled)
        })
        // No active scope has no registered approval capability, so it is not
        // a cancellation signal for the standalone/no-op paths.
        .unwrap_or(false)
}

fn register_host_approval_effect_handoff(handoff: HostApprovalEffectHandoff) -> bool {
    CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| slot.borrow_mut().handoffs.push(handoff))
        .is_ok()
}

/// Publish the definitive result of the currently-active host effect boundary.
/// The helper is intentionally scoped, not a global completion API: only the
/// code executing inside a typed handoff scope can settle the capabilities it
/// owns. Nested wrappers share one scope so the innermost concrete dispatcher
/// rechecks and settles the capability that an outer authorization gate
/// obtained; only the outermost scope publishes a terminal receipt.
pub(crate) fn record_host_approval_effect_boundary_outcome(succeeded: bool) {
    let _ = CURRENT_HOST_APPROVAL_HANDOFFS.try_with(|slot| {
        slot.borrow_mut().outcome = Some(succeeded);
    });
}

/// Revalidate every approval capability owned by the current concrete effect
/// scope immediately before the host crosses its real dispatch boundary.
///
/// `consume_host_approval_final_operation` proves the user answered the
/// exact prompt, but it intentionally happens before the caller returns from
/// an async approval helper.  A cancellation or agent revision transition can
/// win in the small interval before a shell, MCP, harness, or filesystem call
/// begins.  This boundary check is the second fence: stale capabilities are
/// terminalized as known rejections and never reach the host effect.
pub(crate) async fn recheck_host_approval_effect_boundary(
    boundary: &'static str,
    cancelled: &tokio_util::sync::CancellationToken,
    concrete_effects: &[serde_json::Value],
) -> anyhow::Result<()> {
    // A concrete boundary sometimes contributes its own generation in
    // addition to the enclosing tool/effect scope (the computer coordinator
    // is the canonical case).  Do not replace the task-local generations
    // with that one token: preserve and bind it into the common terminal
    // scope so an outer cancellation that races this second recheck still
    // wins over a later success receipt.
    let cancellations = CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            scope.cancellations.push(cancelled.clone());
            scope.cancellations.clone()
        })
        .unwrap_or_else(|_| vec![cancelled.clone()]);
    recheck_host_approval_effect_boundary_for_generations(
        boundary,
        &cancellations,
        concrete_effects,
    )
    .await
}

async fn recheck_host_approval_effect_boundary_for_generations(
    boundary: &'static str,
    cancellations: &[tokio_util::sync::CancellationToken],
    concrete_effects: &[serde_json::Value],
) -> anyhow::Result<()> {
    let concrete_effects_json = serde_json::to_string(concrete_effects)
        .context("serializing concrete host approval effects")?;
    let handoffs = CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            std::mem::take(&mut scope.handoffs)
        })
        .map_err(|_| anyhow::anyhow!("host approval capability escaped its effect scope"))?;
    if handoffs.is_empty() {
        return Ok(());
    }
    let mut retained = Vec::with_capacity(handoffs.len());
    let mut rejected = Vec::new();
    // A scope can legitimately carry more than one *ready* capability. The
    // first connect to an external MCP tool is the important example: the
    // tool-call approval is retained for `tools/call`, while the distinct
    // server-connect approval crosses the earlier connection boundary.
    let mut matched_exact_capability = false;
    for mut handoff in handoffs {
        let was_claimed = handoff.claimed;
        let fence = if cancellations
            .iter()
            .any(tokio_util::sync::CancellationToken::is_cancelled)
        {
            crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive
        } else {
            handoff
                .claim_at_effect_boundary(concrete_effects_json.clone())
                .await
        };
        match fence {
            crate::db::agent_tree_decisions::HostApprovalEffectFence::Claimed => {
                // Both a newly claimed ready handoff and a prior submission
                // whose selected candidate contains this next effect prove
                // the exact boundary.  Any sibling handoffs that do not
                // match stay reserved for their own later boundary.
                matched_exact_capability = true;
                retained.push(handoff);
            }
            crate::db::agent_tree_decisions::HostApprovalEffectFence::DifferentCandidate => {
                if was_claimed
                    && !cancellations
                        .iter()
                        .any(tokio_util::sync::CancellationToken::is_cancelled)
                {
                    // A scope can own more than one sequential operation
                    // (for example the gitignore shape selection followed by
                    // its separately-approved persistence mutation). An
                    // already-submitted operation is retained for completion,
                    // but it is not counted as authority for this boundary.
                    retained.push(handoff);
                } else {
                    // Do not consume or reject a different live ready
                    // capability just because a composed operation reaches
                    // an earlier boundary first. We still fail closed below
                    // unless some handoff exactly matches this boundary.
                    // `NotLive` remains terminal, so cancellation/revision
                    // and stale handoffs cannot hide behind a matching
                    // sibling capability.
                    retained.push(handoff);
                }
            }
            crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive => {
                rejected.push(handoff);
            }
        }
    }
    let rejected_any = !rejected.is_empty();
    for handoff in rejected {
        handoff.reject_if_unclaimed().await;
    }
    if cancellations
        .iter()
        .any(tokio_util::sync::CancellationToken::is_cancelled)
    {
        for handoff in retained {
            handoff.reject_if_unclaimed().await;
        }
        anyhow::bail!("host approval effect was cancelled before dispatch");
    }
    // If an approval was rejected by the revision/state fence, do not let a
    // mixed scope dispatch another effect under an unrelated handoff.
    if rejected_any {
        for handoff in retained {
            handoff.reject_if_unclaimed().await;
        }
        anyhow::bail!("host approval capability is no longer live at effect boundary");
    }
    // Every concrete boundary needs one exact selected candidate. A live
    // mismatch is retained only when a sibling matched this boundary
    // (connect, then later `tools/call`). A mismatched-only scope fails
    // closed and terminalizes the unused ready capability.
    if !matched_exact_capability {
        for handoff in retained {
            handoff.reject_if_unclaimed().await;
        }
        anyhow::bail!("no live host approval capability authorizes this effect boundary");
    }
    CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| slot.borrow_mut().handoffs.extend(retained))
        .map_err(|_| anyhow::anyhow!("host approval effect scope disappeared during recheck"))?;
    Ok(())
}

/// Recheck using the cancellation generation bound to the active opaque
/// capability. Low-level concrete effect code uses this rather than accepting
/// an arbitrary token. A standalone utility/test call has no capability to
/// recheck and remains a no-op.
pub(crate) async fn recheck_current_host_approval_effect_boundary(
    boundary: &'static str,
    concrete_effects: &[serde_json::Value],
) -> anyhow::Result<()> {
    let Some(cancellations) = CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            scope.cancellations.clone()
        })
        .ok()
    else {
        return Ok(());
    };
    recheck_host_approval_effect_boundary_for_generations(
        boundary,
        &cancellations,
        concrete_effects,
    )
    .await
}

/// Revalidate only already-claimed capabilities at a read-only stability
/// boundary, without consuming a different ready capability that is reserved
/// for a later irreversible effect.
///
/// A write/edit first claims its native path before the initial content read.
/// It can then await a content approval and a lock before checking that the
/// source bytes still match.  That stability read must reject a cancelled or
/// revised *path* approval, but claiming the ready exact-content approval
/// there would reopen the forbidden claim-to-mutation window.  This helper
/// keeps the two fences separate: it verifies the claimed access candidate
/// and leaves unclaimed content candidates for the immediately-adjacent write
/// boundary.
pub(crate) async fn recheck_current_claimed_host_approval_effect_boundary(
    boundary: &'static str,
    concrete_effects: &[serde_json::Value],
) -> anyhow::Result<()> {
    let Some(cancellations) = CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            scope.cancellations.clone()
        })
        .ok()
    else {
        return Ok(());
    };
    let concrete_effects_json = serde_json::to_string(concrete_effects)
        .context("serializing concrete host approval effects")?;
    let handoffs = CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| {
            let mut scope = slot.borrow_mut();
            scope.boundary = boundary;
            std::mem::take(&mut scope.handoffs)
        })
        .map_err(|_| anyhow::anyhow!("host approval capability escaped its effect scope"))?;
    if handoffs.is_empty() {
        return Ok(());
    }
    let cancelled = cancellations
        .iter()
        .any(tokio_util::sync::CancellationToken::is_cancelled);
    let mut retained = Vec::with_capacity(handoffs.len());
    let mut rejected = Vec::new();
    let mut had_claimed = false;
    let mut matched_claimed = false;
    for mut handoff in handoffs {
        if !handoff.claimed {
            // The later write-content approval must remain ready until its
            // exact mutation boundary. Do not turn this stability check into
            // a claim or reject it merely because its candidate is different.
            retained.push(handoff);
            continue;
        }
        had_claimed = true;
        let fence = if cancelled {
            crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive
        } else {
            handoff
                .claim_at_effect_boundary(concrete_effects_json.clone())
                .await
        };
        match fence {
            crate::db::agent_tree_decisions::HostApprovalEffectFence::Claimed => {
                matched_claimed = true;
                retained.push(handoff);
            }
            crate::db::agent_tree_decisions::HostApprovalEffectFence::DifferentCandidate => {
                // This may be a prior sequential submission in the same tool
                // scope. Retain it for its terminal receipt, but never treat
                // it as authority for this stability read.
                retained.push(handoff);
            }
            crate::db::agent_tree_decisions::HostApprovalEffectFence::NotLive => {
                rejected.push(handoff);
            }
        }
    }
    let rejected_any = !rejected.is_empty();
    for handoff in rejected {
        handoff.reject_if_unclaimed().await;
    }
    CURRENT_HOST_APPROVAL_HANDOFFS
        .try_with(|slot| slot.borrow_mut().handoffs.extend(retained))
        .map_err(|_| anyhow::anyhow!("host approval effect scope disappeared during recheck"))?;
    if cancelled {
        anyhow::bail!("host approval effect was cancelled before stability read");
    }
    if rejected_any {
        anyhow::bail!("claimed host approval capability is no longer live at stability read");
    }
    if had_claimed && !matched_claimed {
        anyhow::bail!("claimed host approval capability does not authorize this stability read");
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PreResolvedInterruptQuestion {
    /// Exact durable executor identity for AgentTree-owned QuestionTool
    /// replays. This is deliberately distinct from `agent`, which remains a
    /// human-readable display label and may be shared by recursive children.
    /// `None` is only for legacy isolated interrupt compatibility.
    pub agent_instance_id: Option<Uuid>,
    pub agent: String,
    pub description: String,
    pub questions: InterruptQuestionSet,
    pub occurrence: usize,
}

#[derive(Debug, Clone)]
pub struct PreResolvedInterrupt {
    pub interrupt_id: Uuid,
    pub response: ResolveResponse,
    pub question: Option<PreResolvedInterruptQuestion>,
}

#[derive(Debug, Default)]
struct PreResolvedInterrupts {
    answers: HashMap<Uuid, PreResolvedInterrupt>,
    seen_questions: HashMap<String, usize>,
}

pub async fn with_interrupt_park_payload<F>(payload: InterruptParkPayload, fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send + '_>> =
        Box::pin(fut);
    CURRENT_INTERRUPT_PARK_PAYLOAD
        .scope(RefCell::new(payload), fut)
        .await
}

pub fn current_interrupt_park_payload() -> Option<InterruptParkPayload> {
    CURRENT_INTERRUPT_PARK_PAYLOAD
        .try_with(|payload| payload.borrow().clone())
        .ok()
}

pub fn set_current_interrupt_gate_memo(gate: crate::db::needs_attention::InterruptGateMemo) {
    let _ = CURRENT_INTERRUPT_PARK_PAYLOAD.try_with(|payload| {
        payload.borrow_mut().gate = Some(gate);
    });
}

pub async fn with_pre_resolved_interrupt<F>(
    interrupt_id: Uuid,
    response: ResolveResponse,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    with_pre_resolved_interrupts(
        vec![PreResolvedInterrupt {
            interrupt_id,
            response,
            question: None,
        }],
        fut,
    )
    .await
}

pub async fn with_pre_resolved_interrupt_question<F>(
    interrupt_id: Uuid,
    response: ResolveResponse,
    question: PreResolvedInterruptQuestion,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    with_pre_resolved_interrupts(
        vec![PreResolvedInterrupt {
            interrupt_id,
            response,
            question: Some(question),
        }],
        fut,
    )
    .await
}

pub async fn with_pre_resolved_interrupts<F>(
    interrupts: Vec<PreResolvedInterrupt>,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    let answers = interrupts
        .into_iter()
        .map(|entry| (entry.interrupt_id, entry))
        .collect();
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .scope(
            RefCell::new(PreResolvedInterrupts {
                answers,
                seen_questions: HashMap::new(),
            }),
            async {
                let output = fut.await;
                discard_unconsumed_pre_resolved_interrupts();
                output
            },
        )
        .await
}

fn take_matching_pre_resolved_interrupt(
    agent_instance_id: Option<Uuid>,
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<(Uuid, ResolveResponse)> {
    let interrupt_id =
        matching_pre_resolved_interrupt_id(agent_instance_id, agent, description, questions)?;
    take_pre_resolved_interrupt(interrupt_id).map(|response| (interrupt_id, response))
}

fn matching_pre_resolved_interrupt_id(
    agent_instance_id: Option<Uuid>,
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<Uuid> {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| {
            let mut state = slot.borrow_mut();
            let key = question_key(agent_instance_id, agent, description, questions)?;
            let occurrence = {
                let seen = state.seen_questions.entry(key.clone()).or_default();
                *seen += 1;
                *seen
            };
            state.answers.iter().find_map(|(interrupt_id, entry)| {
                let question = entry.question.as_ref()?;
                (question.occurrence == occurrence
                    && question_key(
                        question.agent_instance_id,
                        &question.agent,
                        &question.description,
                        &question.questions,
                    )
                    .as_deref()
                        == Some(key.as_str()))
                .then_some(*interrupt_id)
            })
        })
        .ok()
        .flatten()
}

fn take_pre_resolved_interrupt(interrupt_id: Uuid) -> Option<ResolveResponse> {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| {
            slot.borrow_mut()
                .answers
                .remove(&interrupt_id)
                .map(|entry| entry.response)
        })
        .ok()
        .flatten()
}

fn question_key(
    agent_instance_id: Option<Uuid>,
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<String> {
    // An AgentTree UUID is the stable replay identity. Do not include the
    // display name in that branch: an executor may be renamed between park
    // and recovery, and recursive siblings are allowed to share a name.
    // Legacy isolated rows intentionally retain their historical
    // display-name key while no typed owner exists.
    let identity = match agent_instance_id {
        Some(agent_instance_id) => serde_json::json!({
            "agent_instance_id": agent_instance_id,
        }),
        None => serde_json::json!({
            "legacy_agent": agent,
        }),
    };
    serde_json::to_string(&serde_json::json!({
        "identity": identity,
        "description": description,
        "questions": questions,
    }))
    .ok()
}

fn discard_unconsumed_pre_resolved_interrupts() {
    let _ = CURRENT_PRE_RESOLVED_INTERRUPTS.try_with(|slot| {
        let mut state = slot.borrow_mut();
        for interrupt_id in state.answers.keys() {
            tracing::warn!(
                %interrupt_id,
                "pre-resolved interrupt answer was not consumed during replay"
            );
        }
        state.answers.clear();
    });
}

/// Whether the current tool invocation is replaying a previously parked
/// interrupt. Tools with config-controlled gates must still consume this
/// decision even if their configuration changed while the call was parked.
pub fn pre_resolved_interrupt_pending() -> bool {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| !slot.borrow().answers.is_empty())
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub enum InterruptOutcome {
    Resolved(ResolveResponse),
    Parked,
}

impl InterruptOutcome {
    pub fn into_response(self) -> std::result::Result<ResolveResponse, InterruptParked> {
        match self {
            Self::Resolved(response) => Ok(response),
            Self::Parked => Err(InterruptParked),
        }
    }
}

/// Sentinel for a parked interrupt. Downstream dispatch code must stop the
/// turn without fabricating a user answer or a tool result.
#[derive(Debug, thiserror::Error)]
#[error("interrupt parked")]
pub struct InterruptParked;

pub fn is_parked(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InterruptParked>().is_some()
}

/// Terminal outcome of awaiting a worker's shutdown park-commit
/// (`daemon-lifecycle-replay-timing-robustness.md`). The drain path awaits
/// this **before** releasing the daemon's pid/socket, so a graceful restart
/// never reports success while a registered interrupt waiter's park is still
/// un-committed. Distinguishing `Committed` from the two forced terminals is
/// what keeps `metadata_guard.cleanup()` truthful on the success path while
/// still allowing a wedged/failed park to release the process for a
/// successor (see the terminal-state table in the prompt).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParkCommitTerminal {
    /// Every registered park landed durably (or there were none to park).
    Committed,
    /// A `park_interrupt` write returned `Err` — a real DB failure, not a
    /// scheduling delay. Shutdown proceeds (`drained_clean = false`) so a
    /// successor can bind, but this is not a clean park success.
    KnownFailedWrite,
    /// The park-commit signal did not resolve within
    /// `INTERRUPT_PARK_COMMIT_DEADLINE`. Shutdown still proceeds (same
    /// process-replacement reason) but is not a clean park success.
    DeadlineUnresolved,
}

impl ParkCommitTerminal {
    /// A clean park success — the only terminal that may take the
    /// clean-`"daemon: restarted"` path and leave pid/socket released as a
    /// truthful signal that every registered park committed.
    pub fn is_clean(self) -> bool {
        matches!(self, ParkCommitTerminal::Committed)
    }
}

/// Internal shutdown-park state published by the worker task and observed by
/// the drain path. `Pending` until the worker's `SessionWork::Shutdown` arm
/// runs `park_all_registered`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShutdownParkState {
    Pending,
    Committed,
    FailedWrite,
}

/// Shared park-commit rendezvous for a single session worker
/// (`daemon-lifecycle-replay-timing-robustness.md`). Created in
/// [`crate::daemon::session_worker::spawn`], stored on the worker handle, and
/// wired into that worker's [`InterruptHub`]. It carries **two** independent
/// happens-before edges, both about the same "an interrupt park committed to
/// SQLite" fact, consumed at two lifecycle sites:
///
/// 1. **Shutdown drain** ([`Self::await_shutdown_commit`]): the drain path
///    waits for every worker that has a registered interrupt waiter to durably
///    park before `metadata_guard.cleanup()` releases pid/socket. This closes
///    the confirmed production race where a starved worker task was aborted at
///    the grace deadline before its `park_interrupt` write landed, silently
///    downgrading the settled "zero-grace instant park" of
///    `daemon-drain-grace-and-activity-state` into an `Open` row.
/// 2. **Attach reconciliation** ([`Self::await_startup_reconciled`]): a
///    resumed worker flips a crash-surviving `Open` interrupt to `Parked` in
///    its startup pass; the attach path waits for that pass before returning,
///    so a client cannot observe a stale `Open` row (the same
///    missing-synchronization class as (1), settled as in scope by the prompt).
///
/// The deadline caps only guarantee shutdown/attach cannot hang forever on a
/// wedged worker; the normal path resolves as soon as the park commits, so
/// this is a completion signal, not a widened timeout.
#[derive(Clone)]
pub struct ParkCommit {
    inner: Arc<ParkCommitInner>,
}

struct ParkCommitInner {
    /// Count of currently-registered interrupt waiters (live
    /// [`PendingInterrupt`] guards). Read once at drain start to decide
    /// whether this worker owes a shutdown park-commit.
    registered: AtomicUsize,
    shutdown: watch::Sender<ShutdownParkState>,
    startup_reconciled: watch::Sender<bool>,
}

impl Default for ParkCommit {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkCommit {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ParkCommitInner {
                registered: AtomicUsize::new(0),
                shutdown: watch::channel(ShutdownParkState::Pending).0,
                startup_reconciled: watch::channel(false).0,
            }),
        }
    }

    /// Bump the registered-waiter count. Called from [`InterruptHub::register`]
    /// exactly once per waiter; balanced by [`Self::on_unregister`] in the
    /// guard's `Drop`.
    fn on_register(&self) {
        self.inner.registered.fetch_add(1, Ordering::SeqCst);
    }

    /// Drop one registered-waiter count. Saturating so a double-drop (which
    /// cannot happen — one guard, one `Drop`) can never underflow.
    fn on_unregister(&self) {
        let _ = self
            .inner
            .registered
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_sub(1))
            });
    }

    /// Whether this worker currently has at least one interrupt waiter blocked
    /// on a human decision — i.e. whether it owes a shutdown park-commit. Read
    /// lock-free at drain start (after `begin_drain` has closed new dispatch).
    pub fn has_registered_waiters(&self) -> bool {
        self.inner.registered.load(Ordering::SeqCst) > 0
    }

    /// Producer (worker `SessionWork::Shutdown` arm): every registered park
    /// landed durably (or there were none). `send_replace` always updates the
    /// stored value (even if the drain path has not subscribed yet — the worker
    /// can report before or after the drain awaits), so a later subscriber sees
    /// the terminal via `borrow`, never a lost update.
    pub fn report_shutdown_committed(&self) {
        let _ = self
            .inner
            .shutdown
            .send_replace(ShutdownParkState::Committed);
    }

    /// Producer: at least one park write returned `Err`.
    pub fn report_shutdown_failed_write(&self) {
        let _ = self
            .inner
            .shutdown
            .send_replace(ShutdownParkState::FailedWrite);
    }

    /// Producer (worker startup): the crash-reconciliation pass finished; any
    /// stale `Open` interrupt has been flipped to `Parked` (or none needed it).
    pub fn report_startup_reconciled(&self) {
        let _ = self.inner.startup_reconciled.send_replace(true);
    }

    /// Consumer (drain): await the shutdown park-commit, bounded by `deadline`.
    /// Resolves the instant the worker reports a terminal state; the deadline
    /// only bounds a wedged worker (→ [`ParkCommitTerminal::DeadlineUnresolved`])
    /// so shutdown can still release pid/socket for a successor.
    pub async fn await_shutdown_commit(&self, deadline: std::time::Duration) -> ParkCommitTerminal {
        let mut rx = self.inner.shutdown.subscribe();
        match *rx.borrow_and_update() {
            ShutdownParkState::Committed => return ParkCommitTerminal::Committed,
            ShutdownParkState::FailedWrite => return ParkCommitTerminal::KnownFailedWrite,
            ShutdownParkState::Pending => {}
        }
        let resolved = tokio::time::timeout(deadline, async {
            loop {
                if rx.changed().await.is_err() {
                    // Sender dropped without a terminal report: treat as
                    // unresolved so shutdown does not claim a clean success.
                    return ShutdownParkState::Pending;
                }
                match *rx.borrow_and_update() {
                    ShutdownParkState::Pending => continue,
                    other => return other,
                }
            }
        })
        .await;
        match resolved {
            Ok(ShutdownParkState::Committed) => ParkCommitTerminal::Committed,
            Ok(ShutdownParkState::FailedWrite) => ParkCommitTerminal::KnownFailedWrite,
            Ok(ShutdownParkState::Pending) | Err(_) => ParkCommitTerminal::DeadlineUnresolved,
        }
    }

    /// Consumer (attach): await the worker's startup reconciliation pass,
    /// bounded by `deadline`. Returns `true` if the pass committed within the
    /// deadline, `false` if the worker wedged (attach then proceeds anyway —
    /// the reconciliation is idempotent and re-runs on the next attach).
    pub async fn await_startup_reconciled(&self, deadline: std::time::Duration) -> bool {
        let mut rx = self.inner.startup_reconciled.subscribe();
        if *rx.borrow_and_update() {
            return true;
        }
        let resolved = tokio::time::timeout(deadline, async {
            loop {
                if rx.changed().await.is_err() {
                    return false;
                }
                if *rx.borrow_and_update() {
                    return true;
                }
            }
        })
        .await;
        matches!(resolved, Ok(true))
    }

    /// Test-only: simulate a worker registering an interrupt waiter without a
    /// full [`InterruptHub`], so drain-path tests can mark a worker as owing a
    /// park-commit. Balanced by [`Self::test_drop_registered`].
    #[cfg(test)]
    pub(crate) fn test_add_registered(&self) {
        self.on_register();
    }

    #[cfg(test)]
    pub(crate) fn test_registered_count(&self) -> usize {
        self.inner.registered.load(Ordering::SeqCst)
    }
}

/// Shared interrupt rendezvous. Cheap to clone via `Arc`.
pub struct InterruptHub {
    /// Pending wakeups keyed by interrupt id. A sender is inserted by
    /// [`Self::register`] and removed when [`Self::resolve`] fires it
    /// (or when the [`PendingInterrupt`] guard drops on cancellation).
    waiters: Mutex<HashMap<Uuid, oneshot::Sender<InterruptOutcome>>>,
    /// Outbound event channel to attached clients. `None` in
    /// non-daemon paths (tool unit tests, the standalone run shim) where
    /// no client is listening — raising still works; the event is just
    /// not broadcast. Cloned from the session worker's fan-out sender.
    events: Option<EventSender>,
    redaction: Option<SharedRedactionTable>,
    db: Option<crate::db::Db>,
    session_id: Option<Uuid>,
    /// Count of attached *interactive* clients — ones that can answer an
    /// interrupt (the TUI; later the remote dashboard). A `cockpit run`
    /// event pump attaches but cannot answer, so it does not count. The
    /// server bumps this on interactive attach and decrements on detach
    /// via the shared `Arc`. Read by the loop guard (GOALS §1/§12) to
    /// decide headless behavior: 0 means "no human to prompt → don't
    /// block, auto-reject the repeat."
    interactive_clients: Arc<AtomicUsize>,
    /// Serializes EVERY read-modify-write of the live redaction table for this
    /// session (H1) — sealed adoption ([`Self::seal_redaction_with_identity`]),
    /// approved-secret-file registration ([`Self::register_approved_secret_file`]),
    /// and the per-turn refresh union (the driver's refresh via
    /// [`Self::refresh_union_redaction`]; the session-worker refresh, which owns
    /// the [`SharedRedactionTable`] directly, via [`Self::lock_redaction_table_write`]).
    /// A sealed
    /// adoption snapshots the current table, then `await`s key load + AEAD + the
    /// journal transaction before swapping in `snapshot + literal`. Any writer
    /// that reads the table, unions its delta, persists, and swaps OUTSIDE this
    /// lock could snapshot the pre-adoption table and swap its stale union AFTER
    /// the sealed transaction commits — dropping the just-adopted sealed literal
    /// from both the live and the durable table while its history row stays
    /// committed, so a later egress of that literal bypasses live redaction
    /// (decision 10.1 adopted-table invariant). Holding this async mutex across
    /// each writer's whole read→union→persist→swap makes every writer union onto
    /// the previous one's committed result, so no committed union is ever lost.
    /// Every critical section reads the LATEST table under the lock; no `.await`
    /// that could touch the table happens outside it. All writers are async, so
    /// they all serialize on this one `tokio` mutex without a sync/async split.
    redaction_table_write_lock: tokio::sync::Mutex<()>,
    /// Shared park-commit rendezvous for the worker that owns this hub, or
    /// `None` for the many non-daemon hubs (tests, standalone shims) that have
    /// no drain/attach lifecycle. Only the daemon session worker installs one
    /// (via [`Self::with_park_commit`]); when present, `register`/`park`
    /// maintain its registered-waiter count and shutdown park-commit signal.
    park_commit: Option<ParkCommit>,
}

impl InterruptHub {
    /// Install the shared [`ParkCommit`] created by
    /// [`crate::daemon::session_worker::spawn`] so this hub's waiter
    /// registration and shutdown park land the drain/attach synchronization
    /// signals. Consumed at construction (before the hub is wrapped in `Arc`).
    #[must_use]
    pub fn with_park_commit(mut self, park_commit: ParkCommit) -> Self {
        self.park_commit = Some(park_commit);
        self
    }
    /// Build a hub wired to the worker's client event fan-out, sharing an
    /// externally-owned interactive-client counter so the daemon's attach
    /// lifecycle and the hub read the same cell. The session worker owns
    /// the counter and exposes it on its handle for the server to bump as
    /// interactive clients attach/detach; the loop guard reads it via
    /// [`Self::is_interactive_attached`].
    pub fn new(
        events: EventSender,
        redaction: SharedRedactionTable,
        interactive_clients: Arc<AtomicUsize>,
        db: crate::db::Db,
        session_id: Uuid,
    ) -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: Some(events),
            redaction: Some(redaction),
            db: Some(db),
            session_id: Some(session_id),
            interactive_clients,
            redaction_table_write_lock: tokio::sync::Mutex::new(()),
            park_commit: None,
        }
    }

    /// Build a detached hub with no client fan-out. Used where no client
    /// is attached (tests, the standalone shim): wakeups still work via
    /// [`Self::resolve`], but no `InterruptRaised` event is emitted.
    pub fn detached() -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: None,
            redaction: None,
            db: None,
            session_id: None,
            interactive_clients: Arc::new(AtomicUsize::new(0)),
            redaction_table_write_lock: tokio::sync::Mutex::new(()),
            park_commit: None,
        }
    }

    /// Whether at least one interactive client (one that can answer an
    /// interrupt) is currently attached. `false` means headless: the loop
    /// guard must not block on a prompt and instead auto-rejects the
    /// repeat. A detached hub (tests / standalone shim) is always headless.
    pub fn is_interactive_attached(&self) -> bool {
        self.interactive_clients.load(Ordering::SeqCst) > 0
    }

    /// Register a sealed literal in the worker's live egress redaction table,
    /// persist that table, and journal the adoption into protected redaction
    /// history — all under the literal's TYPED canonical identity.
    ///
    /// Sealedness is carried by the typed [`SealedRedactionIdentity`] the whole
    /// way through — it is registered directly via `with_forced_sealed_literal`,
    /// never by serializing the identity to a `sealed:<id>` origin string and
    /// reparsing it here to reconstruct classification. `parse_sealed_redaction_origin`
    /// is kept off this live registration path entirely. This is the single
    /// place where a sealed literal becomes redacted; the legacy
    /// `sealed:<value_id>` wrapper is gone along with the agent-facing sealed
    /// write paths that were its only callers.
    ///
    /// This is the LIVE production sealed-adoption route (via
    /// [`crate::sealed::runtime::SessionRedactionSink`]). Adoption journals a
    /// `Sealed` protected-history row **atomically** with the redaction-table
    /// persist (decision 10.1): the encrypted append is prepared off the DB
    /// thread, then the table persist and the journal append commit in one
    /// transaction. If either the prepare or the transaction fails, the whole
    /// adoption rolls back and the live table is left untouched — a sealed
    /// literal is never adopted half-journaled. Re-adopting the same literal
    /// dedups to an attach (no duplicate row). Sessions carrying the
    /// unjournaled-inference opt-out (scratch / daemon-less) skip journaling.
    ///
    /// The protected-history key resolver is reached from the `Session` this
    /// method already holds ([`crate::session::Session::redaction_key_resolver`]).
    pub async fn seal_redaction_with_identity(
        &self,
        session: &crate::session::Session,
        value: String,
        identity: crate::sealed::identity::SealedRedactionIdentity,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        // H1: serialize the read-modify-write below against ALL redaction-table
        // writers for this session (other sealed adoptions, approved-secret-file
        // registration, the per-turn refresh union). The snapshot→await→swap
        // spans a `.await` (key load + AEAD + journal transaction), so any writer
        // that reads the same `base` and swaps its own union afterwards would drop
        // this adoption's literal from the live and durable table even though the
        // history row committed. Holding the async mutex across
        // read→prepare→persist→swap makes each writer see the previous one's
        // committed table as its `base`, so every committed union survives.
        let _adopt_guard = self.redaction_table_write_lock.lock().await;
        // Take the sealed identity ids from the TYPED identity, never from a
        // parsed origin display string. A legacy/unversioned session entry has
        // no record id, so both the record id and the version are `None`.
        let sealed_record_id = identity.record_id.map(|record| record.to_string());
        let sealed_version = identity.record_id.map(|_| i64::from(identity.version));

        let base = current_redaction(redaction);
        let table = Arc::new(base.with_forced_sealed_literal(value.clone(), identity)?);

        if session.unjournaled_inference_allowed() {
            // Opt-out: scratch / daemon-less sessions persist the table without
            // journaling (fail-safe, mirrors the inference path).
            session.persist_redaction_table(&table)?;
        } else {
            // Journal the adoption atomically with the table persist. On any
            // failure this returns Err having persisted nothing, so the live
            // table below is only swapped once the adoption is durable.
            session
                .adopt_sealed_literal_journaled(&table, value, sealed_record_id, sealed_version)
                .await?;
        }
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Install a **contained-leak** literal into the worker's live egress
    /// redaction table and persist it, BEFORE the provider turn that reported the
    /// leak is acknowledged, so subsequent output for this and every later turn is
    /// scrubbed of the reported secret (the leak-report Contained transition —
    /// `provider-sensitive-turn barrier`, AC2).
    ///
    /// This is the live-session redaction install the leak-report handler
    /// deliberately does NOT perform: [`crate::leak_report::LeakReportHandler`]
    /// commits the encrypted protected-history row and the leak record, and this
    /// method installs the forced literal so the *live* table scrubs it. The
    /// encrypted protected-history journal is written by the handler, so — unlike
    /// sealed adoption — this path only persists the redaction table and swaps the
    /// live `Arc`; it never re-journals (mirroring
    /// [`Self::register_approved_secret_file`]).
    ///
    /// H1: takes the same [`Self::redaction_table_write_lock`] as sealed adoption
    /// and the per-turn refresh union, and reads the LATEST table under it, so a
    /// concurrent refresh can neither read a stale table nor swap over the
    /// just-installed contained literal. Fail-closed: a failed persist returns
    /// `Err` with the previously-committed table still live — the live table is
    /// never advanced ahead of the durable one, and the caller must then NOT ack
    /// the report as contained. Detached hubs (tests / standalone shim) that own
    /// no shared table return `Ok(None)`; the barrier's own module tests cover the
    /// install-before-ack ordering directly.
    pub async fn install_contained_leak_literal(
        &self,
        session: &crate::session::Session,
        value: String,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        // `with_forced_literal` is the leak-containment adoption seam (decision
        // 11): its literals classify as `ContainedLeak`.
        let table = current_redaction(redaction)
            .with_forced_literal(value, "$leak:contained".to_string())?;
        let table = Arc::new(table);
        // Persist BEFORE swapping the live table (fail-closed): a persist failure
        // must not leave the live table advanced ahead of the durable one.
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Register parsed values from an approved secret-bearing file in the
    /// worker's live redaction table before its contents return to a model.
    /// Detached hubs return `None`; callers then retain a local table.
    ///
    /// H1: async so it serializes on the same [`Self::redaction_table_write_lock`]
    /// as sealed adoption — a plain sync writer here could snapshot the
    /// pre-adoption table and swap its stale union after a concurrent sealed
    /// adoption commits, dropping the sealed literal from the live+durable table.
    /// Taking the lock and re-reading the LATEST table under it makes this
    /// registration union onto any concurrently-committed adoption instead of
    /// clobbering it. Fail-closed: a failed persist returns `Err` before the
    /// live table is swapped.
    pub async fn register_approved_secret_file(
        &self,
        session: &crate::session::Session,
        cfg: &crate::config::extended::RedactConfig,
        path: &std::path::Path,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        let table = current_redaction(redaction).with_approved_secret_file(cfg, path)?;
        let table = Arc::new(table);
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Union a freshly-built disk-scan table onto the session's LIVE redaction
    /// table under the serialized write lock, persisting the result BEFORE it is
    /// swapped live, and return the committed table.
    ///
    /// This is the per-turn refresh route for a caller that does NOT own the
    /// [`SharedRedactionTable`] directly — namely the engine driver, whose own
    /// `self.redact` is a COPY that a mid-turn sealed adoption never updates.
    /// Routing the driver's refresh through here makes it read the LATEST shared
    /// table (which may already hold a sealed literal adopted this turn via
    /// [`Self::seal_redaction_with_identity`]) under the SAME
    /// [`Self::redaction_table_write_lock`], so the driver can neither read a
    /// stale table nor persist a union that drops a committed adoption from the
    /// durable table (decision 10.1 adopted-table invariant).
    ///
    /// H1 ordering, identical to sealed adoption: read the latest table, union,
    /// **persist, then swap**. A persist failure returns `Err` with the
    /// previously-committed table still live — the live table is never advanced
    /// ahead of the durable one. A union failure keeps the committed table live
    /// unchanged (deferring the disk delta to the next refresh) rather than
    /// clobbering a committed adoption with a bare disk scan.
    ///
    /// Returns `Ok(None)` for a detached hub (tests / standalone shim) that owns
    /// no shared table; the caller then unions onto its own local copy.
    pub async fn refresh_union_redaction(
        &self,
        session: &crate::session::Session,
        new_table: &crate::redact::RedactionTable,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        let base = current_redaction(redaction);
        let table = match base.union(new_table) {
            Ok(table) => Arc::new(table),
            Err(error) => {
                // Never overwrite the committed table (which may hold a sealed
                // literal) with a bare disk scan on a union error: keep the
                // committed table live and defer the disk delta to the next
                // refresh.
                tracing::warn!(error = %error, "unioning redaction table failed; keeping committed table");
                return Ok(Some(base));
            }
        };
        // Persist BEFORE swapping the live table: a persist failure must not
        // leave the live table advanced ahead of the durable one (a restart
        // would then lose the accumulated entry). `?` surfaces the failure with
        // the previously-committed table still live and durable.
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Acquire the per-session redaction-table write lock for a caller that owns
    /// the read→union→persist→swap itself (the session-worker per-turn refresh,
    /// which holds the [`SharedRedactionTable`] directly rather than through this
    /// hub). Holding this guard across that whole sequence serializes the refresh
    /// against sealed adoption and approved-secret-file registration on the SAME
    /// lock, so a refresh can neither read a stale table nor swap over a
    /// concurrently-committed adoption. The caller must, under this guard, read
    /// the LATEST table via `current_redaction`, union its delta, persist, then
    /// swap — see [`Self::redaction_table_write_lock`] for the full invariant.
    pub async fn lock_redaction_table_write(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.redaction_table_write_lock.lock().await
    }

    /// Register a wakeup for `interrupt_id` and return the guard the
    /// caller awaits. The guard removes its registry entry on drop, so a
    /// tool whose future is cancelled (e.g. the worker shuts down) never
    /// leaves a dangling sender.
    pub fn register(&self, interrupt_id: Uuid) -> PendingInterrupt<'_> {
        let (tx, rx) = oneshot::channel();
        lock_or_recover(&self.waiters).insert(interrupt_id, tx);
        if let Some(park_commit) = &self.park_commit {
            park_commit.on_register();
        }
        PendingInterrupt {
            hub: self,
            interrupt_id,
            rx: Some(rx),
        }
    }

    /// Emit `InterruptRaised` to attached clients (no-op when detached).
    /// The `question` tool calls this right after persisting the
    /// interrupt and registering the wakeup, so a client can render the
    /// answering dialog.
    pub async fn emit_raised(
        &self,
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: &str,
        description: &str,
        questions: InterruptQuestionSet,
    ) {
        let open = match (&self.db, self.session_id) {
            (Some(db), Some(owned_session_id)) if owned_session_id == session_id => {
                db.list_open_interrupts(owned_session_id).await.ok()
            }
            _ => None,
        };
        if let Some(open) = &open {
            let active = open.first().map(|row| row.interrupt_id);
            if active != Some(interrupt_id) {
                self.emit_queue_changed(active, open.len().saturating_sub(1));
                return;
            }
        }
        if let (Some(events), Some(redaction)) = (&self.events, &self.redaction) {
            let pending_count = open
                .as_ref()
                .map(|open| open.len().saturating_sub(1))
                .unwrap_or(0);
            // `send` errors only when there are no subscribers — fine,
            // the interrupt still parks in the DB for the next client.
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptRaised {
                    session_id,
                    interrupt_id,
                    agent: agent.to_string(),
                    description: description.to_string(),
                    question: None,
                    questions: Some(questions),
                    pending_count,
                    reason: proto::InterruptRaiseReason::Initial,
                },
            );
        }
    }

    pub async fn emit_active_from_db(&self) {
        let (Some(db), Some(session_id)) = (&self.db, self.session_id) else {
            return;
        };
        let Ok(open) = db.list_open_interrupts(session_id).await else {
            return;
        };
        let Some(active) = open.first() else {
            self.emit_queue_changed(None, 0);
            return;
        };
        let pending_count = open.len().saturating_sub(1);
        self.emit_queue_changed(Some(active.interrupt_id), pending_count);
        let questions = active.questions.clone().or_else(|| {
            active
                .question
                .clone()
                .map(|question| InterruptQuestionSet {
                    questions: vec![question],
                })
        });
        if let (Some(events), Some(redaction), Some(questions)) =
            (&self.events, &self.redaction, questions)
        {
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptRaised {
                    session_id,
                    interrupt_id: active.interrupt_id,
                    agent: active.agent_id.clone(),
                    description: active.description.clone(),
                    question: None,
                    questions: Some(questions),
                    pending_count,
                    reason: proto::InterruptRaiseReason::Advance,
                },
            );
        }
    }

    pub async fn emit_queue_state(&self) {
        let (Some(db), Some(session_id)) = (&self.db, self.session_id) else {
            return;
        };
        if let Ok(open) = db.list_open_interrupts(session_id).await {
            self.emit_queue_changed(
                open.first().map(|row| row.interrupt_id),
                open.len().saturating_sub(1),
            );
        }
    }

    fn emit_queue_changed(&self, active_interrupt_id: Option<Uuid>, pending_count: usize) {
        if let (Some(events), Some(redaction), Some(session_id)) =
            (&self.events, &self.redaction, self.session_id)
        {
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptQueueChanged {
                    session_id,
                    active_interrupt_id,
                    pending_count,
                },
            );
        }
    }

    /// Broadcast the session's current gitignore read-allowlist to attached
    /// clients (no-op when detached). Called right after a "Approve for this
    /// session" outcome lands a new glob, so the TUI `@`-tag popup re-includes
    /// the session-approved entry without a restart
    /// (implementation note). Carries the full set
    /// (replace, not delta); only the allow-set is ever sent. Reuses the same
    /// per-session event fan-out the worker uses for `RedactionState`.
    pub fn emit_gitignore_allow(&self, session_id: Uuid, allow: Vec<String>) {
        if let (Some(events), Some(redaction)) = (&self.events, &self.redaction) {
            // `send` errors only when there are no subscribers — fine; an
            // attaching client re-hydrates the set via the attach broadcast.
            send_current_event(
                events,
                redaction,
                proto::Event::GitignoreAllow { session_id, allow },
            );
        }
    }

    /// Deliver a resolution to whoever is blocked on `interrupt_id`.
    /// Returns `true` if a waiter was woken. `false` means no tool was
    /// blocked on it locally — e.g. the worker restarted and the
    /// in-flight tool future was dropped, or the resolution targets a
    /// `schedule` needs-attention nudge that nobody awaits. The DB row has
    /// already been updated by the caller regardless.
    pub fn resolve(&self, interrupt_id: Uuid, response: ResolveResponse) -> bool {
        let Some(tx) = lock_or_recover(&self.waiters).remove(&interrupt_id) else {
            return false;
        };
        tx.send(InterruptOutcome::Resolved(response)).is_ok()
    }

    #[cfg(test)]
    pub fn has_waiter(&self, interrupt_id: Uuid) -> bool {
        lock_or_recover(&self.waiters).contains_key(&interrupt_id)
    }

    pub async fn park(&self, interrupt_id: Uuid) -> bool {
        self.park_inner(interrupt_id).await.woke
    }

    /// Park one interrupt, reporting both whether a local waiter was woken
    /// (`woke`, the historical [`Self::park`] return) and whether the durable
    /// `park_interrupt` write committed (`write_committed`). The two are
    /// distinct: a waiter is always woken with `Parked` for correctness even
    /// when the DB write fails, but a failed write must be surfaced to the
    /// shutdown park-commit signal as [`ParkCommitTerminal::KnownFailedWrite`]
    /// rather than impersonating a clean commit.
    async fn park_inner(&self, interrupt_id: Uuid) -> ParkOutcome {
        let write_committed = match self.db.as_ref() {
            Some(db) => db.park_interrupt(interrupt_id).await.is_ok(),
            None => false,
        };
        let Some(tx) = lock_or_recover(&self.waiters).remove(&interrupt_id) else {
            // No live waiter: preserve the historical `park` contract of
            // returning the write result as `woke`.
            return ParkOutcome {
                woke: write_committed,
                write_committed,
            };
        };
        let _ = tx.send(InterruptOutcome::Parked);
        ParkOutcome {
            woke: true,
            write_committed,
        }
    }

    /// Park every currently-registered interrupt waiter WITHOUT publishing the
    /// shutdown park-commit terminal. The worker's `SessionWork::Shutdown` drain
    /// calls this repeatedly — re-parking any interrupt the in-flight turn
    /// registered after an earlier sweep (`daemon-lifecycle-replay-timing-
    /// robustness.md`, finding 2) — and only reports once, via
    /// [`Self::report_shutdown_commit`], after the driver task has exited and no
    /// further registration is possible. Returns the woken count and whether
    /// every `park_interrupt` write in this sweep committed.
    pub async fn park_all_registered_collect(&self) -> ParkSweep {
        let interrupt_ids = {
            let guard = lock_or_recover(&self.waiters);
            guard.keys().copied().collect::<Vec<_>>()
        };
        let mut count = 0;
        let mut all_committed = true;
        for interrupt_id in interrupt_ids {
            let outcome = self.park_inner(interrupt_id).await;
            if outcome.woke {
                count += 1;
            }
            if !outcome.write_committed {
                all_committed = false;
            }
        }
        ParkSweep {
            count,
            all_committed,
        }
    }

    /// Park every currently-registered interrupt waiter and publish the
    /// shutdown park-commit terminal in one shot. Retained for non-drain
    /// callers (loop/skill runners, tests) whose hubs carry no [`ParkCommit`]
    /// so the report is a no-op; the worker's graceful drain instead uses
    /// [`Self::park_all_registered_collect`] + a deferred
    /// [`Self::report_shutdown_commit`].
    pub async fn park_all_registered(&self) -> usize {
        let sweep = self.park_all_registered_collect().await;
        self.report_shutdown_commit(sweep.all_committed);
        sweep.count
    }

    /// Publish the shutdown park-commit terminal for this worker (no-op when no
    /// [`ParkCommit`] is installed): `Committed` when every registered park has
    /// landed durably (or there were none), `FailedWrite` when a `park_interrupt`
    /// write returned `Err`. Called once, after the driver task has quiesced.
    pub fn report_shutdown_commit(&self, all_committed: bool) {
        if let Some(park_commit) = &self.park_commit {
            if all_committed {
                park_commit.report_shutdown_committed();
            } else {
                park_commit.report_shutdown_failed_write();
            }
        }
    }
}

/// Result of [`InterruptHub::park_inner`] — see its doc comment.
struct ParkOutcome {
    woke: bool,
    write_committed: bool,
}

/// Result of [`InterruptHub::park_all_registered_collect`]: how many waiters
/// were woken this sweep and whether every durable park write committed.
pub struct ParkSweep {
    pub count: usize,
    pub all_committed: bool,
}

/// Guard returned by [`InterruptHub::register`]. Awaiting it (via
/// [`Self::wait`]) blocks until [`InterruptHub::resolve`] fires for this
/// id; dropping it without resolving removes the registry entry so no
/// stale sender lingers.
pub struct PendingInterrupt<'a> {
    hub: &'a InterruptHub,
    interrupt_id: Uuid,
    /// `Option` so [`Self::wait`] can take the receiver out of `self`
    /// without fighting the `Drop` guard (a `Drop` type can't be moved
    /// out of field-by-field).
    rx: Option<oneshot::Receiver<InterruptOutcome>>,
}

impl PendingInterrupt<'_> {
    /// Issue the host-approval capability from this live waiter.  The opaque
    /// capability therefore cannot be created from a durable operation UUID
    /// alone: the caller must hold the actual registered QuestionTool
    /// continuation that will receive the approval result.
    pub(crate) fn host_approval_authority(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> anyhow::Result<crate::agent_tree::HostApprovalAuthority> {
        crate::agent_tree::HostApprovalAuthority::for_registered_interrupt(
            session_id,
            agent_instance_id,
            self.interrupt_id,
        )
    }

    /// Block until resolved or parked. A closed wakeup channel is treated
    /// as parked: teardown must never auto-answer or auto-cancel a row.
    pub async fn wait(mut self) -> InterruptOutcome {
        let rx = self.rx.take().expect("wait called once");
        match rx.await {
            Ok(outcome) => outcome,
            Err(_) => InterruptOutcome::Parked,
        }
    }
}

impl Drop for PendingInterrupt<'_> {
    fn drop(&mut self) {
        // Idempotent: `resolve`/`park` already removed it on the happy path.
        let _ = lock_or_recover(&self.hub.waiters).remove(&self.interrupt_id);
        // Balance the `on_register` bump: one guard, one drop, so the
        // registered-waiter count tracks live waiters regardless of whether
        // this interrupt was resolved, parked, or cancelled.
        if let Some(park_commit) = &self.hub.park_commit {
            park_commit.on_unregister();
        }
    }
}

/// The selected option id from a resolved single-select interrupt
/// (unwrapping a one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn selected_id_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Single { selected_id } => Some(selected_id.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => Some(selected_id.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The free-text answer from a resolved free-text interrupt (unwrapping a
/// one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn freetext_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Freetext { text } => Some(text.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Freetext { text }) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Persist → register → emit → wait: raise an interrupt with `set` and
/// block until the user answers (or dismisses). On a DB failure (can't
/// persist) returns [`ResolveResponse::Cancel`] so the caller treats it as
/// a dismissal rather than hanging. `log_label` prefixes the warn on that
/// failure. Shared by the driver and in-turn raise wrappers.
pub async fn raise_and_wait(
    db: &crate::db::Db,
    interrupts: &InterruptHub,
    session_id: Uuid,
    agent: &str,
    description: &str,
    set: InterruptQuestionSet,
    log_label: &str,
) -> InterruptOutcome {
    // This is the compatibility entry point used by older engine surfaces.
    // In a daemon-owned session it must not silently create a second,
    // interrupt-only decision path.  Prefer the exact task-local executor
    // identity; the root lookup covers driver controls that run outside the
    // turn task-local scope. Isolated helpers intentionally keep
    // the legacy implementation below.
    let owner = crate::engine::agent::current_agent_instance_id().or(db
        .session_root_agent(session_id)
        .await
        .ok()
        .flatten()
        .map(|root| root.agent_instance_id));
    match owner {
        Some(agent_instance_id) => {
            raise_and_wait_with_agent_tree(
                db,
                interrupts,
                session_id,
                agent,
                Some(agent_instance_id),
                description,
                set,
                crate::agent_tree::HostDecisionSubject::UserQuestion,
                log_label,
            )
            .await
        }
        None => {
            raise_and_wait_legacy(
                db,
                interrupts,
                session_id,
                agent,
                description,
                set,
                log_label,
            )
            .await
        }
    }
}

/// Legacy isolated implementation. Production callers enter
/// [`raise_and_wait`] and are promoted to the typed AgentTree bridge when a
/// durable executor exists; this stays available only for helpers that have
/// deliberately not established a daemon-owned session root.
async fn raise_and_wait_legacy(
    db: &crate::db::Db,
    interrupts: &InterruptHub,
    session_id: Uuid,
    agent: &str,
    description: &str,
    set: InterruptQuestionSet,
    log_label: &str,
) -> InterruptOutcome {
    if let Some((_interrupt_id, response)) =
        take_matching_pre_resolved_interrupt(None, agent, description, &set)
    {
        return InterruptOutcome::Resolved(response);
    }
    let payload = current_interrupt_park_payload();
    let interrupt_id = match db
        .raise_interrupt_questions_with_payload(
            session_id,
            agent,
            description,
            &set,
            payload.as_ref(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "{log_label}: raising interrupt failed");
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    let pending = interrupts.register(interrupt_id);
    interrupts
        .emit_raised(session_id, interrupt_id, agent, description, set.clone())
        .await;
    pending.wait().await
}

/// Resolve a failed dedicated refresh attempt before its real interrupt,
/// decision, and operation can be bound. The storage transaction owns the
/// child, descriptor, and raw QuestionTool row together; in particular, a
/// late error must never use the ordinary operation cancellation API, because
/// there is no bound operation yet to finalise.
async fn abort_unbound_host_capability_refresh_initialization(
    db: &crate::db::Db,
    session_id: Uuid,
    agent_instance_id: Option<Uuid>,
    operation: crate::agent_tree::HostCapabilitiesRefreshOperation,
    raw_interrupt_id: Option<Uuid>,
    failure_stage: &'static str,
) {
    if !operation.requires_dedicated_child_initialization() {
        // Isolated lifecycle fixtures retain the old no-child shape. There
        // cannot be an initialization descriptor to atomically clean up, but
        // an accidentally reserved operation/interrupt must still be closed.
        let _ = db
            .cancel_host_capability_refresh_operation(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session_id,
                operation.operation_id,
                "host capability refresh decision could not be created".to_string(),
                crate::agent_tree::system_now_unix_ms(),
            )
            .await;
        if let Some(raw_interrupt_id) = raw_interrupt_id {
            let _ = db.mark_interrupt_interrupted(raw_interrupt_id).await;
        }
        return;
    }
    let Some(agent_instance_id) = agent_instance_id else {
        tracing::error!(
            %session_id,
            operation_id = %operation.operation_id,
            request_id = %operation.request_id,
            %failure_stage,
            "dedicated host capability refresh lost its child identity before pre-bind cleanup"
        );
        return;
    };
    match db
        .abort_host_capability_refresh_initialization(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session_id,
            operation.operation_id,
            operation.request_id,
            agent_instance_id,
            raw_interrupt_id,
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        Ok(crate::db::agent_tree_decisions::HostCapabilityRefreshInitializationAbort::Aborted) => {}
        Ok(
            crate::db::agent_tree_decisions::HostCapabilityRefreshInitializationAbort::AlreadyBound,
        ) => {
            // An ambiguous storage failure may be reported after the bind
            // committed. Preserve that exact bound operation and let its
            // durable terminalizer/recovery path decide its outcome; a stale
            // prompt failure must never cancel an already-authorized probe.
            tracing::warn!(
                %session_id,
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                %failure_stage,
                "pre-bind cleanup observed an already-bound host capability refresh; preserving exact operation finalization"
            );
        }
        Ok(outcome) => {
            tracing::warn!(
                %session_id,
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                ?outcome,
                %failure_stage,
                "pre-bind cleanup did not find a live matching host capability refresh initialization"
            );
        }
        Err(error) => {
            // A failed cleanup transaction leaves every pre-existing durable
            // fact untouched, so boot recovery remains able to repair the
            // descriptor atomically. Do not split the child/raw-attention
            // writes into best-effort follow-ups here.
            tracing::error!(
                %error,
                %session_id,
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                %failure_stage,
                "atomically aborting pre-bind host capability refresh initialization failed"
            );
        }
    }
}

/// The QuestionTool's production bridge.  It persists the existing interrupt
/// first, registers the existing continuation before any lifecycle delivery can
/// settle it, binds that *same* Attention row to the requesting agent's durable
/// decision, and then emits through the unchanged InterruptHub continuation.
/// Tests and non-daemon helpers may not have a lifecycle instance; those retain
/// the historical interrupt-only path.
pub(crate) async fn raise_and_wait_with_agent_tree(
    db: &crate::db::Db,
    interrupts: &InterruptHub,
    session_id: Uuid,
    agent: &str,
    agent_instance_id: Option<Uuid>,
    description: &str,
    set: InterruptQuestionSet,
    decision_subject: crate::agent_tree::HostDecisionSubject,
    log_label: &str,
) -> InterruptOutcome {
    let host_capability_refresh_operation = decision_subject
        .host_capabilities_refresh_operation()
        .copied();
    // Resolve the durable owner before probing the recovery map. Some host
    // callers (notably approval helpers) run outside the executor task-local
    // scope but still belong to the session root; matching them as legacy
    // first would miss the typed parked answer and issue a duplicate prompt.
    let agent_instance_id = match agent_instance_id {
        Some(agent_instance_id) => Some(agent_instance_id),
        None => match db.session_root_agent(session_id).await {
            Ok(Some(root)) => Some(root.agent_instance_id),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, %session_id, "loading question root lifecycle owner failed");
                if let Some(operation) = host_capability_refresh_operation {
                    abort_unbound_host_capability_refresh_initialization(
                        db,
                        session_id,
                        agent_instance_id,
                        operation,
                        None,
                        "loading the refresh decision owner",
                    )
                    .await;
                }
                return InterruptOutcome::Resolved(ResolveResponse::Cancel);
            }
        },
    };
    if let Some(agent_instance_id) = agent_instance_id
        && let Some((interrupt_id, response)) =
            take_matching_pre_resolved_interrupt(Some(agent_instance_id), agent, description, &set)
    {
        if let Some(operation) = decision_subject.host_approval_operation() {
            // A restart must consume the original persisted approval operation,
            // not manufacture a new prompt identity (and never silently turn
            // an already-approved effect into Cancel). The caller-provided
            // facts are recomputed from the actual effect input and must match
            // the stored kind/digest before the one-use CAS succeeds.
            let replayed = match db
                .decision_request_for_interrupt(session_id, interrupt_id)
                .await
            {
                Ok(Some(decision))
                    if decision.decision_class == "host_approval"
                        && crate::approval::host_approval_response_allows(&response, &set) =>
                {
                    let authority = match db.get_interrupt(interrupt_id).await {
                        Ok(Some(interrupt)) => match crate::agent_tree::HostApprovalAuthority::for_durable_interrupt_binding(
                            session_id,
                            &decision,
                            &interrupt,
                        ) {
                            Ok(authority) => authority,
                            Err(_) => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
                        },
                        Ok(None) | Err(_) => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
                    };
                    let db_authority = match authority.db_for_effect_handoff(
                        session_id,
                        decision.agent_instance_id,
                        interrupt_id,
                    ) {
                        Ok(authority) => authority,
                        Err(_) => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
                    };
                    let Some(operation_id) = decision.host_approval_operation_id else {
                        return InterruptOutcome::Resolved(ResolveResponse::Cancel);
                    };
                    // `operation` was freshly derived from the concrete
                    // replayed effect.  Only after that kind/digest proof do
                    // we restore the durable operation UUID; handing the
                    // newly allocated prompt UUID to the effect scope would
                    // strand the actual dispatching record on restart.
                    let operation =
                        match operation.clone().with_persisted_operation_id(operation_id) {
                            Ok(operation) => operation,
                            Err(_) => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
                        };
                    let dispatched = db
                        .consume_host_approval_final_operation(
                            db_authority,
                            interrupt_id,
                            session_id,
                            decision.agent_instance_id,
                            operation_id,
                            operation.operation_kind.clone(),
                            operation.canonical_input_json.clone(),
                            operation.input_digest.clone(),
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await;
                    match dispatched {
                        Ok(true)
                            if register_host_approval_effect_handoff(
                                HostApprovalEffectHandoff::new(
                                    db.clone(),
                                    authority,
                                    session_id,
                                    decision.agent_instance_id,
                                    interrupt_id,
                                    operation.clone(),
                                ),
                            ) =>
                        {
                            response
                        }
                        Ok(true) => {
                            // There is no production effect boundary in this
                            // task (for example a test-only direct caller).
                            // The capability is still ready, not submitted,
                            // so record a known rejection rather than an
                            // ambiguous external handoff.
                            let _ = db
                                .reject_unclaimed_host_approval_final_operation(
                                    db_authority,
                                    interrupt_id,
                                    session_id,
                                    decision.agent_instance_id,
                                    operation_id,
                                    operation.operation_kind.clone(),
                                    operation.canonical_input_json.clone(),
                                    operation.input_digest.clone(),
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await;
                            ResolveResponse::Cancel
                        }
                        // A pre-resolved replay that observes an existing
                        // dispatch is deliberately denied.  We cannot prove
                        // whether a non-idempotent shell/MCP/harness/fs
                        // operation crossed its external boundary before the
                        // crash, so replaying the response would authorize a
                        // duplicate effect.  Promote a still-dispatching
                        // handoff to the explicit audit state when possible;
                        // completed/rejected rows make this a fenced no-op.
                        Ok(false) => {
                            // A concurrent replay can observe either a
                            // still-ready capability (no submission happened)
                            // or an already-claimed dispatch. Reject the former
                            // first; only the latter is promoted to unknown.
                            let _ = db
                                .reject_unclaimed_host_approval_final_operation(
                                    db_authority,
                                    interrupt_id,
                                    session_id,
                                    decision.agent_instance_id,
                                    operation_id,
                                    operation.operation_kind.clone(),
                                    operation.canonical_input_json.clone(),
                                    operation.input_digest.clone(),
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await;
                            let _ = db
                                .mark_host_approval_final_operation_submission_unknown(
                                    db_authority,
                                    interrupt_id,
                                    session_id,
                                    decision.agent_instance_id,
                                    operation_id,
                                    operation.operation_kind.clone(),
                                    operation.canonical_input_json.clone(),
                                    operation.input_digest.clone(),
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await;
                            ResolveResponse::Cancel
                        }
                        Err(_) => ResolveResponse::Cancel,
                    }
                }
                // A denied/cancelled replay preserves that outcome; it never
                // consumes an operation. Any missing/mismatched durable
                // binding fails closed.
                Ok(Some(decision)) if decision.decision_class == "host_approval" => response,
                Ok(_) | Err(_) => ResolveResponse::Cancel,
            };
            return InterruptOutcome::Resolved(replayed);
        }
        return InterruptOutcome::Resolved(response);
    }
    // The normal turn dispatcher is intentionally usable by lightweight
    // helpers too. An isolated caller has no typed owner, so only that
    // explicit legacy case can use the historical name-keyed path.
    let Some(agent_instance_id) = agent_instance_id else {
        // An isolated helper has no tree to own. Do not make the compatibility
        // path affect normal production behavior. Unit tests exercise
        // historical Approver prompt shapes without a daemon tree, so retain
        // their isolated interrupt-only path; production host effects still
        // fail closed below.
        #[cfg(test)]
        {
            return raise_and_wait_legacy(
                db,
                interrupts,
                session_id,
                agent,
                description,
                set,
                log_label,
            )
            .await;
        }
        #[cfg(not(test))]
        {
            if matches!(
                &decision_subject,
                crate::agent_tree::HostDecisionSubject::UserQuestion
            ) {
                return raise_and_wait_legacy(
                    db,
                    interrupts,
                    session_id,
                    agent,
                    description,
                    set,
                    log_label,
                )
                .await;
            }
            tracing::warn!(%session_id, "host effect has no durable lifecycle owner");
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    let owner = match db.agent_instance(session_id, agent_instance_id).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            tracing::warn!(%session_id, %agent_instance_id, "question owner is not authorized for this session");
            if let Some(operation) = host_capability_refresh_operation {
                abort_unbound_host_capability_refresh_initialization(
                    db,
                    session_id,
                    Some(agent_instance_id),
                    operation,
                    None,
                    "loading the refresh decision owner",
                )
                .await;
            }
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
        Err(error) => {
            tracing::warn!(%error, %session_id, %agent_instance_id, "loading question lifecycle owner failed");
            if let Some(operation) = host_capability_refresh_operation {
                abort_unbound_host_capability_refresh_initialization(
                    db,
                    session_id,
                    Some(agent_instance_id),
                    operation,
                    None,
                    "loading the refresh decision owner",
                )
                .await;
            }
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    // The public event and durable row retain the human-readable agent label.
    // The exact AgentTree UUID is persisted beside it as a typed continuation
    // key; never overload a display name (or a UUID-shaped display string)
    // as replay authority.
    let payload = current_interrupt_park_payload();
    let interrupt_id = match db
        .raise_interrupt_questions_with_agent_instance_and_payload(
            session_id,
            agent,
            Some(agent_instance_id),
            description,
            &set,
            payload.as_ref(),
        )
        .await
    {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(%error, "{log_label}: raising lifecycle interrupt failed");
            if let Some(operation) = host_capability_refresh_operation {
                abort_unbound_host_capability_refresh_initialization(
                    db,
                    session_id,
                    Some(agent_instance_id),
                    operation,
                    None,
                    "raising the refresh QuestionTool interrupt",
                )
                .await;
            }
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    // A live automatic resolver can settle immediately after the decision is
    // committed. Register the real QuestionTool continuation *before* that
    // binding exists, so its terminal projection can never beat this waiter
    // and strand the original tool call. Every failure below drops this guard,
    // which removes the registry entry and leaves no synthetic continuation.
    let pending = interrupts.register(interrupt_id);
    let host_operation = decision_subject.host_approval_operation().cloned();
    let host_operation_id = host_operation
        .as_ref()
        .map(|operation| operation.operation_id);
    // The capability is created only after the real interrupt has been
    // raised and registered. It is carried through both reservation and the
    // atomic decision bind; a durable operation UUID alone is never enough.
    let host_approval_authority = match host_operation.as_ref() {
        Some(_) => match pending.host_approval_authority(session_id, agent_instance_id) {
            Ok(authority) => Some(authority),
            Err(error) => {
                tracing::warn!(
                    %error,
                    %session_id,
                    %interrupt_id,
                    "refusing host approval without a non-nil registered interrupt authority"
                );
                let _ = db.mark_interrupt_interrupted(interrupt_id).await;
                return InterruptOutcome::Resolved(ResolveResponse::Cancel);
            }
        },
        None => None,
    };
    if let Some(operation) = host_operation.as_ref() {
        let authority = match host_approval_authority
            .expect("host approval authority follows operation")
            .db_for_reservation(session_id, agent_instance_id)
        {
            Ok(authority) => authority,
            Err(error) => {
                tracing::warn!(
                    %error,
                    %session_id,
                    %interrupt_id,
                    "registered interrupt did not own host approval reservation"
                );
                let _ = db.mark_interrupt_interrupted(interrupt_id).await;
                return InterruptOutcome::Resolved(ResolveResponse::Cancel);
            }
        };
        if let Err(error) = db
            .reserve_host_approval_final_operation(
                session_id,
                agent_instance_id,
                operation.operation_id,
                operation.operation_kind.clone(),
                operation.canonical_input_json.clone(),
                operation.input_digest.clone(),
                authority,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
        {
            tracing::warn!(
                %error,
                %session_id,
                %interrupt_id,
                "reserving final host approval operation failed"
            );
            let _ = db.mark_interrupt_interrupted(interrupt_id).await;
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    }
    let contract = match crate::agent_tree::NewDecisionContract::user_question_interrupt(
        agent_instance_id,
        owner.revision,
        &set,
        owner.workspace_ref.clone(),
    ) {
        Ok(contract) => match (host_operation.clone(), host_approval_authority) {
            (Some(operation), Some(authority)) => {
                contract.with_host_approval_subject(operation, authority)
            }
            (None, None) => contract.with_host_subject(decision_subject),
            _ => unreachable!("host approval operation and authority are paired"),
        },
        Err(error) => {
            tracing::warn!(%error, %session_id, %interrupt_id, "building redacted QuestionTool contract failed");
            if let Some(operation_id) = host_operation_id {
                let _ = db
                    .cancel_unbound_host_approval_final_operation(
                        session_id,
                        agent_instance_id,
                        operation_id,
                        crate::agent_tree::system_now_unix_ms(),
                    )
                    .await;
            }
            if let Some(operation) = host_capability_refresh_operation {
                abort_unbound_host_capability_refresh_initialization(
                    db,
                    session_id,
                    Some(agent_instance_id),
                    operation,
                    Some(interrupt_id),
                    "building the refresh decision contract",
                )
                .await;
            } else {
                let _ = db.mark_interrupt_interrupted(interrupt_id).await;
            }
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    let _decision = match crate::agent_tree::AgentTreeLifecycle::new(db.clone())
        .request_decision_for_interrupt(
            session_id,
            contract,
            interrupt_id,
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        Ok(decision) => decision,
        Err(error) => {
            tracing::warn!(%error, %session_id, %interrupt_id, "binding QuestionTool interrupt to durable decision failed");
            if let Some(operation_id) = host_operation_id {
                let _ = db
                    .cancel_unbound_host_approval_final_operation(
                        session_id,
                        agent_instance_id,
                        operation_id,
                        crate::agent_tree::system_now_unix_ms(),
                    )
                    .await;
            }
            if let Some(operation) = host_capability_refresh_operation {
                abort_unbound_host_capability_refresh_initialization(
                    db,
                    session_id,
                    Some(agent_instance_id),
                    operation,
                    Some(interrupt_id),
                    "binding the refresh decision to its QuestionTool interrupt",
                )
                .await;
            } else {
                let _ = db.mark_interrupt_interrupted(interrupt_id).await;
            }
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    interrupts
        .emit_raised(session_id, interrupt_id, agent, description, set.clone())
        .await;
    let outcome = pending.wait().await;
    let InterruptOutcome::Resolved(response) = &outcome else {
        return outcome;
    };
    let Some(operation_id) = host_operation_id else {
        return outcome;
    };
    let Some(operation) = host_operation else {
        return InterruptOutcome::Resolved(ResolveResponse::Cancel);
    };
    if !crate::approval::host_approval_response_allows(response, &set) {
        return outcome;
    }
    let authority = match host_approval_authority {
        Some(authority) => authority,
        None => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
    };
    let db_authority =
        match authority.db_for_effect_handoff(session_id, agent_instance_id, interrupt_id) {
            Ok(authority) => authority,
            Err(_) => return InterruptOutcome::Resolved(ResolveResponse::Cancel),
        };
    match db
        .consume_host_approval_final_operation(
            db_authority,
            interrupt_id,
            session_id,
            agent_instance_id,
            operation.operation_id,
            operation.operation_kind.clone(),
            operation.canonical_input_json.clone(),
            operation.input_digest.clone(),
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        Ok(true)
            if register_host_approval_effect_handoff(HostApprovalEffectHandoff::new(
                db.clone(),
                authority,
                session_id,
                agent_instance_id,
                interrupt_id,
                operation.clone(),
            )) =>
        {
            outcome
        }
        Ok(true) => {
            let _ = db
                .reject_unclaimed_host_approval_final_operation(
                    db_authority,
                    interrupt_id,
                    session_id,
                    agent_instance_id,
                    operation.operation_id,
                    operation.operation_kind,
                    operation.canonical_input_json,
                    operation.input_digest,
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await;
            InterruptOutcome::Resolved(ResolveResponse::Cancel)
        }
        Ok(false) | Err(_) => InterruptOutcome::Resolved(ResolveResponse::Cancel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    use crate::{
        daemon::proto::{InterruptOption, InterruptQuestion},
        redact::RedactionTable,
    };

    fn question_set() -> InterruptQuestionSet {
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Continue?".into(),
                options: vec![InterruptOption {
                    id: "yes".into(),
                    label: "Yes".into(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        }
    }

    fn attached_hub(
        db: crate::db::Db,
        session_id: Uuid,
    ) -> (InterruptHub, crate::daemon::EventReceiver) {
        let (events, receiver) = tokio::sync::broadcast::channel(16);
        let redaction = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
        (
            InterruptHub::new(
                events,
                redaction,
                Arc::new(AtomicUsize::new(1)),
                db,
                session_id,
            ),
            receiver,
        )
    }

    async fn running_host_effect_agent() -> (crate::db::Db, Uuid, Uuid, i64) {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/repo", "builder")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let agent = match db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                2,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected running transition: {outcome:?}"),
        };
        (
            db,
            session.session_id,
            agent.agent_instance_id,
            agent.revision,
        )
    }

    async fn insert_ready_host_effect_handoff(
        db: &crate::db::Db,
        session_id: Uuid,
        agent_instance_id: Uuid,
        agent_revision: i64,
        operation: &crate::agent_tree::HostApprovalOperation,
    ) {
        let candidate = serde_json::from_str::<serde_json::Value>(&operation.canonical_input_json)
            .unwrap()["candidate_effects"][0]
            .clone();
        let selected_candidate_json =
            String::from_utf8(crate::agent_tree::canonical_json_bytes(&candidate).unwrap())
                .unwrap();
        let operation_id = operation.operation_id.to_string();
        let operation_kind = operation.operation_kind.clone();
        let canonical_input_json = operation.canonical_input_json.clone();
        let input_digest = operation.input_digest.clone();
        let operation_id_for_handoff = operation_id.clone();
        let operation_kind_for_handoff = operation_kind.clone();
        let canonical_input_for_handoff = canonical_input_json.clone();
        let input_digest_for_handoff = input_digest.clone();
        let selected_candidate_for_handoff = selected_candidate_json.clone();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, state, approved_agent_revision,
                     selected_response_json, selected_candidate_json, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'approved', ?7, ?8, ?9, 3)",
                rusqlite::params![
                    operation_id,
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    agent_revision,
                    r#"{"kind":"single","data":{"selected_id":"approve"}}"#,
                    selected_candidate_json,
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, selected_candidate_json,
                     idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ready', 3)",
                rusqlite::params![
                    operation_id_for_handoff.clone(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind_for_handoff,
                    canonical_input_for_handoff,
                    input_digest_for_handoff,
                    selected_candidate_for_handoff,
                    operation_id_for_handoff,
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn resolve_wakes_a_registered_waiter() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(
            id,
            ResolveResponse::Single {
                selected_id: "y".into(),
            }
        ));
        let got = pending.wait().await;
        assert!(
            matches!(got, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "y")
        );
    }

    #[test]
    fn resolve_unknown_id_returns_false() {
        let hub = InterruptHub::detached();
        assert!(!hub.resolve(Uuid::new_v4(), ResolveResponse::Cancel));
    }

    #[test]
    fn dropping_pending_clears_the_registry() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        drop(pending);
        // No waiter remains, so a late resolve finds nothing.
        assert!(!hub.resolve(id, ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn poisoned_waiter_mutex_recovers_without_panicking() {
        let hub = InterruptHub::detached();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = hub.waiters.lock().unwrap();
            panic!("poison waiter mutex");
        }));

        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(id, ResolveResponse::Cancel));
        assert!(matches!(
            pending.wait().await,
            InterruptOutcome::Resolved(ResolveResponse::Cancel)
        ));
    }

    #[tokio::test]
    async fn dropped_sender_resolves_to_parked() {
        // Worker teardown: the registry is cleared (sender dropped)
        // while a tool is still awaiting. `wait` must yield `Parked`.
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        lock_or_recover(&hub.waiters).clear();
        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
    }

    #[tokio::test]
    async fn explicit_park_wakes_waiter_as_parked() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let pending = hub.register(id);

        assert!(hub.park(id).await);
        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
        assert_eq!(
            db.get_interrupt(id).await.unwrap().unwrap().state,
            crate::db::needs_attention::InterruptState::Parked
        );
    }

    #[tokio::test]
    async fn dedicated_host_refresh_prebind_binding_failure_is_aborted_without_restart() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = db
            .create_agent_instance(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                10,
            )
            .await
            .unwrap();
        let parent = match db
            .transition_agent_instance(
                session.session_id,
                parent.agent_instance_id,
                parent.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                11,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected parent transition: {outcome:?}"),
        };
        let operation = crate::agent_tree::HostCapabilitiesRefreshOperation::for_dedicated_child();
        let child = db
            .create_host_capability_refresh_initialization(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                operation.operation_id,
                operation.request_id,
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                12,
            )
            .await
            .unwrap();

        // Leave the child in `created` so the real typed bind rejects it.
        // The raw QuestionTool row is nevertheless durably raised first,
        // exercising the ordinary runtime error path rather than boot
        // reconciliation.
        let outcome = raise_and_wait_with_agent_tree(
            &db,
            &InterruptHub::detached(),
            session.session_id,
            "host-capability-refresh",
            Some(child.agent_instance_id),
            "host capability refresh",
            InterruptQuestionSet {
                questions: vec![InterruptQuestion::Single {
                    prompt: "Refresh this daemon's locally probed host-capability snapshot?".into(),
                    options: vec![
                        InterruptOption {
                            id: "refresh".into(),
                            label: "Refresh local capabilities".into(),
                            description: None,
                            secondary: false,
                        },
                        InterruptOption {
                            id: "cancel".into(),
                            label: "Not now".into(),
                            description: None,
                            secondary: true,
                        },
                    ],
                    allow_freetext: false,
                    command_detail: None,
                    permission: false,
                    approval_class: None,
                    sandbox_escalation: None,
                }],
            },
            crate::agent_tree::HostDecisionSubject::HostCapabilitiesRefresh { operation },
            "pre-bind cleanup test",
        )
        .await;
        assert!(matches!(
            outcome,
            InterruptOutcome::Resolved(ResolveResponse::Cancel)
        ));

        let child_after = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .expect("initialization child remains auditable after abort");
        assert_eq!(
            child_after.state,
            crate::db::agent_tree_decisions::AgentInstanceState::Cancelled
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0,
            "the raw pre-bind interrupt is resolved in the same abort transaction"
        );
        let operation_id = operation.operation_id;
        let request_id = operation.request_id;
        let child_id = child.agent_instance_id;
        let session_id = session.session_id;
        let (descriptor_state, raw_state, operation_count, terminal_receipts) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM host_capability_refresh_initializations
                          WHERE operation_id = ?1 AND request_id = ?2
                            AND session_id = ?3 AND agent_instance_id = ?4",
                        rusqlite::params![
                            operation_id.to_string(),
                            request_id.to_string(),
                            session_id.to_string(),
                            child_id.to_string(),
                        ],
                        |row| row.get::<_, String>(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM needs_attention
                          WHERE session_id = ?1 AND agent_instance_id = ?2",
                        rusqlite::params![session_id.to_string(), child_id.to_string()],
                        |row| row.get::<_, String>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM host_capability_refresh_operations
                          WHERE operation_id = ?1 AND request_id = ?2
                            AND session_id = ?3 AND agent_instance_id = ?4",
                        rusqlite::params![
                            operation_id.to_string(),
                            request_id.to_string(),
                            session_id.to_string(),
                            child_id.to_string(),
                        ],
                        |row| row.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM agent_transition_receipts
                          WHERE session_id = ?1 AND agent_instance_id = ?2",
                        rusqlite::params![session_id.to_string(), child_id.to_string()],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(descriptor_state, "cancelled");
        assert_eq!(raw_state, "resolved");
        assert_eq!(operation_count, 0);
        assert_eq!(terminal_receipts, 1);
        assert_eq!(
            db.reconcile_host_capability_refresh_operations(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.session_id,
                20,
            )
            .await
            .unwrap(),
            0,
            "the live pre-bind abort leaves no work for a restart to repair"
        );
        assert_eq!(
            db.abort_host_capability_refresh_initialization(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.session_id,
                operation.operation_id,
                operation.request_id,
                child.agent_instance_id,
                None,
                21,
            )
            .await
            .unwrap(),
            crate::db::agent_tree_decisions::HostCapabilityRefreshInitializationAbort::AlreadyTerminal,
            "a duplicate runtime cleanup cannot create a second terminal receipt"
        );
    }

    #[tokio::test]
    async fn interrupt_replay_answer_requires_matching_id() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    resolver_db
                        .resolve_interrupt(
                            row.interrupt_id,
                            &ResolveResponse::Single {
                                selected_id: "first-live".into(),
                            },
                        )
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(
                        row.interrupt_id,
                        ResolveResponse::Single {
                            selected_id: "first-live".into(),
                        }
                    ));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let stored_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let (first, second) = with_pre_resolved_interrupt_question(
            stored_id,
            ResolveResponse::Single {
                selected_id: "second-stored".into(),
            },
            PreResolvedInterruptQuestion {
                agent_instance_id: None,
                agent: "builder".into(),
                description: "second".into(),
                questions: question_set(),
                occurrence: 1,
            },
            async {
                assert!(
                    take_pre_resolved_interrupt(wrong_id).is_none(),
                    "a different interrupt id must not consume the stored answer"
                );
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "first",
                    question_set(),
                    "test",
                )
                .await;
                assert!(
                    pre_resolved_interrupt_pending(),
                    "the non-matching live raise must leave the stored answer available"
                );
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "second",
                    question_set(),
                    "test",
                )
                .await;
                (first, second)
            },
        )
        .await;

        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-live")
        );
        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn recovered_question_uses_typed_agent_instance_identity_not_display_name() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "root").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let agent_instance_id = Uuid::new_v4();
        let question = question_set();

        let replayed = with_pre_resolved_interrupt_question(
            Uuid::new_v4(),
            ResolveResponse::Single {
                selected_id: "stored-answer".into(),
            },
            PreResolvedInterruptQuestion {
                agent_instance_id: Some(agent_instance_id),
                // Recovery reads the persisted display label. It deliberately
                // differs from the live executor's human-facing name: only
                // the typed UUID may identify this replay.
                agent: "persisted-worker-label".into(),
                description: "same durable question".into(),
                questions: question.clone(),
                occurrence: 1,
            },
            async {
                raise_and_wait_with_agent_tree(
                    &db,
                    &hub,
                    session.session_id,
                    "renamed-live-worker",
                    Some(agent_instance_id),
                    "same durable question",
                    question,
                    crate::agent_tree::HostDecisionSubject::UserQuestion,
                    "typed replay identity test",
                )
                .await
            },
        )
        .await;

        assert!(
            matches!(replayed, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "stored-answer"),
            "same-named or renamed recursive executors must consume only their own recovered answer"
        );
    }

    #[tokio::test]
    async fn recovered_recursive_questions_consume_only_the_exact_typed_owner_once() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "root").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let first_agent_instance_id = Uuid::new_v4();
        let second_agent_instance_id = Uuid::new_v4();
        let questions = question_set();
        let description = "shared recursive question";

        let (second, first) = with_pre_resolved_interrupts(
            vec![
                PreResolvedInterrupt {
                    interrupt_id: Uuid::new_v4(),
                    response: ResolveResponse::Single {
                        selected_id: "first-answer".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent_instance_id: Some(first_agent_instance_id),
                        // Recursive siblings intentionally share this display
                        // name; it is not part of their recovery identity.
                        agent: "worker".into(),
                        description: description.into(),
                        questions: questions.clone(),
                        occurrence: 1,
                    }),
                },
                PreResolvedInterrupt {
                    interrupt_id: Uuid::new_v4(),
                    response: ResolveResponse::Single {
                        selected_id: "second-answer".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent_instance_id: Some(second_agent_instance_id),
                        agent: "worker".into(),
                        description: description.into(),
                        questions: questions.clone(),
                        occurrence: 1,
                    }),
                },
            ],
            async {
                let second = raise_and_wait_with_agent_tree(
                    &db,
                    &hub,
                    session.session_id,
                    "renamed-live-worker",
                    Some(second_agent_instance_id),
                    description,
                    questions.clone(),
                    crate::agent_tree::HostDecisionSubject::UserQuestion,
                    "recursive typed replay identity test",
                )
                .await;
                // The other parked continuation remains available only to
                // its exact UUID, even though it has the same display text.
                let first = take_matching_pre_resolved_interrupt(
                    Some(first_agent_instance_id),
                    "another-live-name",
                    description,
                    &questions,
                );
                (second, first)
            },
        )
        .await;

        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-answer")
        );
        assert!(
            matches!(first, Some((_interrupt_id, ResolveResponse::Single { selected_id })) if selected_id == "first-answer"),
            "one recovered recursive answer must never be consumed by a sibling or reissued"
        );
    }

    #[tokio::test]
    async fn interrupt_replay_multiple_parked_answers_keyed_by_id() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();

        let (second, first) = with_pre_resolved_interrupts(
            vec![
                PreResolvedInterrupt {
                    interrupt_id: first_id,
                    response: ResolveResponse::Single {
                        selected_id: "first-stored".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent_instance_id: None,
                        agent: "builder".into(),
                        description: "first".into(),
                        questions: question_set(),
                        occurrence: 1,
                    }),
                },
                PreResolvedInterrupt {
                    interrupt_id: second_id,
                    response: ResolveResponse::Single {
                        selected_id: "second-stored".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent_instance_id: None,
                        agent: "builder".into(),
                        description: "second".into(),
                        questions: question_set(),
                        occurrence: 1,
                    }),
                },
            ],
            async {
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "second",
                    question_set(),
                    "test",
                )
                .await;
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "first",
                    question_set(),
                    "test",
                )
                .await;
                (second, first)
            },
        )
        .await;

        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-stored")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn interrupt_replay_duplicate_prompt_shape_uses_persisted_occurrence() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    let response = ResolveResponse::Single {
                        selected_id: "first-live".into(),
                    };
                    resolver_db
                        .resolve_interrupt(row.interrupt_id, &response)
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(row.interrupt_id, response));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let stored_id = Uuid::new_v4();
        let (first, second) = with_pre_resolved_interrupt_question(
            stored_id,
            ResolveResponse::Single {
                selected_id: "second-stored".into(),
            },
            PreResolvedInterruptQuestion {
                agent_instance_id: None,
                agent: "builder".into(),
                description: "same prompt".into(),
                questions: question_set(),
                occurrence: 2,
            },
            async {
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "same prompt",
                    question_set(),
                    "test",
                )
                .await;
                assert!(
                    pre_resolved_interrupt_pending(),
                    "first identical raise must not consume the second occurrence answer"
                );
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "same prompt",
                    question_set(),
                    "test",
                )
                .await;
                (first, second)
            },
        )
        .await;

        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-live")
        );
        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
    }

    #[tokio::test]
    async fn interrupt_replay_unconsumed_answer_discarded() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    let response = ResolveResponse::Single {
                        selected_id: "live".into(),
                    };
                    resolver_db
                        .resolve_interrupt(row.interrupt_id, &response)
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(row.interrupt_id, response));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let resolved = with_pre_resolved_interrupt_question(
            Uuid::new_v4(),
            ResolveResponse::Single {
                selected_id: "stale".into(),
            },
            PreResolvedInterruptQuestion {
                agent_instance_id: None,
                agent: "builder".into(),
                description: "never raised".into(),
                questions: question_set(),
                occurrence: 1,
            },
            async {
                raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "live prompt",
                    question_set(),
                    "test",
                )
                .await
            },
        )
        .await;

        assert!(
            matches!(resolved, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "live")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn concurrent_raises_keep_fifo_active_and_rehydrate_with_counter() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        hub.emit_raised(session.session_id, first, "a", "first", set.clone())
            .await;
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        hub.emit_raised(session.session_id, second, "b", "second", set)
            .await;

        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 0,
                reason: proto::InterruptRaiseReason::Initial,
                ..
            }
                if interrupt_id == first
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 1, ..
            } if interrupt_id == first
        ));

        hub.emit_active_from_db().await;
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 1, ..
            } if interrupt_id == first
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 1,
                reason: proto::InterruptRaiseReason::Advance,
                ..
            }
                if interrupt_id == first
        ));

        db.resolve_interrupt(first, &ResolveResponse::Cancel)
            .await
            .unwrap();
        hub.emit_active_from_db().await;
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 0, ..
            } if interrupt_id == second
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 0,
                reason: proto::InterruptRaiseReason::Advance,
                ..
            }
                if interrupt_id == second
        ));
    }

    #[tokio::test]
    async fn dropping_active_waiter_leaves_row_open_without_advancing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        let pending = hub.register(first);

        drop(pending);

        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].interrupt_id, first);
        assert_eq!(open[1].interrupt_id, second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn park_all_registered_delegates_to_park_marks_row_and_wakes_waiter() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let interrupt_id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &question_set())
            .await
            .unwrap();
        let pending = hub.register(interrupt_id);

        assert_eq!(hub.park_all_registered().await, 1);

        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].interrupt_id, interrupt_id);
        assert_eq!(
            open[0].state,
            crate::db::needs_attention::InterruptState::Parked
        );
    }

    #[tokio::test]
    async fn dropping_queued_waiter_leaves_fifo_unchanged() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        let pending = hub.register(second);
        drop(pending);

        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].interrupt_id, first);
        assert_eq!(open[1].interrupt_id, second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    // --- ParkCommit (daemon-lifecycle-replay-timing-robustness.md) ---

    #[tokio::test]
    async fn park_commit_registered_count_tracks_live_waiters() {
        // A hub with an installed ParkCommit bumps the registered count on
        // `register` and drops it when the guard drops — so the drain path can
        // read `has_registered_waiters()` to tell which workers owe a park.
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let park_commit = ParkCommit::new();
        let hub = InterruptHub::with_park_commit(hub, park_commit.clone());
        assert!(!park_commit.has_registered_waiters());

        let interrupt_id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &question_set())
            .await
            .unwrap();
        let pending = hub.register(interrupt_id);
        assert!(park_commit.has_registered_waiters());
        assert_eq!(park_commit.test_registered_count(), 1);

        drop(pending);
        assert!(!park_commit.has_registered_waiters());
    }

    #[tokio::test]
    async fn park_all_registered_reports_committed_to_park_commit() {
        // The real shutdown path: `park_all_registered` on a hub with a
        // ParkCommit publishes `Committed` once every registered park has
        // landed durably, which the drain path then observes.
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let park_commit = ParkCommit::new();
        let hub = InterruptHub::with_park_commit(hub, park_commit.clone());
        let interrupt_id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &question_set())
            .await
            .unwrap();
        let _pending = hub.register(interrupt_id);

        assert_eq!(hub.park_all_registered().await, 1);
        assert_eq!(
            park_commit
                .await_shutdown_commit(std::time::Duration::from_secs(1))
                .await,
            ParkCommitTerminal::Committed
        );
    }

    #[tokio::test]
    async fn park_all_registered_collect_reparks_late_registration_without_reporting() {
        // The worker's graceful-drain park-drain loop (finding 2) relies on a
        // fresh sweep catching an interrupt registered AFTER an earlier sweep,
        // and on `collect` NOT publishing the park-commit (that is deferred to
        // `report_shutdown_commit`, called only once the driver has quiesced).
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let park_commit = ParkCommit::new();
        let hub = InterruptHub::with_park_commit(hub, park_commit.clone());

        // Initial sweep: nothing is registered yet.
        assert_eq!(hub.park_all_registered_collect().await.count, 0);

        // A turn registers an interrupt AFTER that initial sweep.
        let interrupt_id = db
            .raise_interrupt_questions(session.session_id, "a", "late", &question_set())
            .await
            .unwrap();
        let _pending = hub.register(interrupt_id);

        // A subsequent sweep catches the late registration and parks it durably,
        // still WITHOUT publishing the shutdown park-commit.
        let sweep = hub.park_all_registered_collect().await;
        assert_eq!(sweep.count, 1);
        assert!(sweep.all_committed);
        assert_eq!(
            park_commit
                .await_shutdown_commit(std::time::Duration::ZERO)
                .await,
            ParkCommitTerminal::DeadlineUnresolved,
            "collect must not publish the commit; it stays Pending until the deferred report"
        );
        assert_eq!(
            db.get_interrupt(interrupt_id)
                .await
                .unwrap()
                .expect("row")
                .state,
            crate::db::needs_attention::InterruptState::Parked
        );

        // The deferred report (after the driver quiesces) publishes Committed.
        hub.report_shutdown_commit(true);
        assert_eq!(
            park_commit
                .await_shutdown_commit(std::time::Duration::from_secs(1))
                .await,
            ParkCommitTerminal::Committed
        );
    }

    #[tokio::test]
    async fn await_shutdown_commit_resolves_only_after_report() {
        // The consumer blocks until the producer reports a terminal state —
        // this is the happens-before the drain path relies on to gate
        // metadata cleanup, not a widened timeout.
        let park_commit = ParkCommit::new();
        park_commit.test_add_registered();
        let consumer = {
            let park_commit = park_commit.clone();
            tokio::spawn(async move {
                park_commit
                    .await_shutdown_commit(std::time::Duration::from_secs(5))
                    .await
            })
        };
        // Give the consumer a chance to observe `Pending` and block.
        tokio::task::yield_now().await;
        assert!(!consumer.is_finished(), "must block until a report lands");
        park_commit.report_shutdown_committed();
        assert_eq!(consumer.await.unwrap(), ParkCommitTerminal::Committed);
    }

    #[tokio::test]
    async fn await_shutdown_commit_surfaces_failed_write() {
        let park_commit = ParkCommit::new();
        park_commit.report_shutdown_failed_write();
        assert_eq!(
            park_commit
                .await_shutdown_commit(std::time::Duration::from_secs(1))
                .await,
            ParkCommitTerminal::KnownFailedWrite
        );
        assert!(!ParkCommitTerminal::KnownFailedWrite.is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn await_shutdown_commit_unresolved_at_expired_deadline() {
        // An expired/zero deadline yields `DeadlineUnresolved` with no
        // real-time sleep — the injectable deadline criterion 5b relies on.
        let park_commit = ParkCommit::new();
        assert_eq!(
            park_commit
                .await_shutdown_commit(std::time::Duration::ZERO)
                .await,
            ParkCommitTerminal::DeadlineUnresolved
        );
    }

    #[tokio::test]
    async fn await_startup_reconciled_gates_on_report() {
        let park_commit = ParkCommit::new();
        let consumer = {
            let park_commit = park_commit.clone();
            tokio::spawn(async move {
                park_commit
                    .await_startup_reconciled(std::time::Duration::from_secs(5))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!consumer.is_finished());
        park_commit.report_startup_reconciled();
        assert!(consumer.await.unwrap());
    }

    #[tokio::test]
    async fn cancelled_host_approval_effect_recheck_rejects_before_dispatch() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/repo", "builder")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let agent = match db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                2,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected agent transition: {outcome:?}"),
        };
        let operation = crate::agent_tree::HostApprovalOperation::new(
            "test_effect_handoff",
            serde_json::json!({
                "operation": "effect-handoff",
                "candidate_effects": [{
                    "selection": "approve",
                    "execute": {"operation": "effect-handoff"},
                }],
            }),
        )
        .unwrap();
        let operation_id = operation.operation_id;
        let operation_kind = operation.operation_kind.clone();
        let canonical_input_json = operation.canonical_input_json.clone();
        let input_digest = operation.input_digest.clone();
        let operation_kind_for_insert = operation_kind.clone();
        let canonical_input_for_insert = canonical_input_json.clone();
        let input_digest_for_insert = input_digest.clone();
        let selected_response_json =
            r#"{"data":{"selected_id":"approve"},"kind":"single"}"#.to_owned();
        let selected_candidate_json = String::from_utf8(
            crate::agent_tree::canonical_json_bytes(&serde_json::json!({
                "selection": "approve",
                "execute": {"operation": "effect-handoff"},
            }))
            .unwrap(),
        )
        .unwrap();
        let selected_response_for_insert = selected_response_json.clone();
        let selected_candidate_for_insert = selected_candidate_json.clone();
        let session_id = session.session_id.to_string();
        let agent_id = agent.agent_instance_id.to_string();
        let operation_id_text = operation_id.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_response_json, selected_candidate_json, state, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'dispatching', 3)",
                rusqlite::params![
                    operation_id_text,
                    session_id.clone(),
                    agent_id.clone(),
                    operation_kind_for_insert,
                    canonical_input_for_insert,
                    input_digest_for_insert,
                    selected_response_for_insert,
                    selected_candidate_for_insert.clone(),
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_candidate_json, idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'dispatching', 3)",
                rusqlite::params![
                    operation_id.to_string(),
                    session_id,
                    agent_id,
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    selected_candidate_for_insert,
                    operation_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let cancelled = tokio_util::sync::CancellationToken::new();
        cancelled.cancel();
        with_host_approval_effect_scope(
            "test_effect_boundary",
            cancelled,
            async {
                assert!(register_host_approval_effect_handoff(
                    HostApprovalEffectHandoff::new(
                        db.clone(),
                        crate::agent_tree::HostApprovalAuthority::trusted_host(),
                        session.session_id,
                        agent.agent_instance_id,
                        Uuid::nil(),
                        operation,
                    ),
                ));
                assert!(
                    recheck_current_host_approval_effect_boundary(
                        "test_effect_boundary",
                        &[serde_json::json!({
                            "execute": {"operation": "effect-handoff"},
                        })],
                    )
                    .await
                    .is_err()
                );
                Ok::<(), anyhow::Error>(())
            },
            |_: &()| Some(true),
        )
        .await
        .unwrap();

        let states: (String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(states, ("rejected".into(), "rejected".into()));
    }

    #[tokio::test]
    async fn composed_ready_handoffs_claim_connect_then_retain_external_mcp_tool() {
        let (db, session_id, agent_instance_id, revision) = running_host_effect_agent().await;
        let tool_operation = crate::agent_tree::HostApprovalOperation::new(
            "external_mcp_tool",
            serde_json::json!({
                "server": "calendar",
                "tool": "create_event",
                "candidate_effects": [{
                    "selection": "approve",
                    "execute": {"server": "calendar", "tool": "create_event", "wire_input": {"title": "Planning"}}
                }],
            }),
        )
        .unwrap();
        let connect_operation = crate::agent_tree::HostApprovalOperation::new(
            "mcp_server_connect",
            serde_json::json!({
                "server": "calendar",
                "identity": "https://calendar.example.invalid/mcp",
                "candidate_effects": [{
                    "selection": "approve",
                    "connect": {"server": "calendar", "identity": "https://calendar.example.invalid/mcp"}
                }],
            }),
        )
        .unwrap();
        let tool_operation_id = tool_operation.operation_id;
        let connect_operation_id = connect_operation.operation_id;
        insert_ready_host_effect_handoff(
            &db,
            session_id,
            agent_instance_id,
            revision,
            &tool_operation,
        )
        .await;
        insert_ready_host_effect_handoff(
            &db,
            session_id,
            agent_instance_id,
            revision,
            &connect_operation,
        )
        .await;

        with_host_approval_effect_scope(
            "external_mcp_tools_call",
            tokio_util::sync::CancellationToken::new(),
            async {
                // This is the real first-time ordering: external tool
                // authorization is already ready, then connection reaches
                // its own host boundary. The tool handoff must remain ready
                // for the later `tools/call` request.
                assert!(register_host_approval_effect_handoff(
                    HostApprovalEffectHandoff::new(
                        db.clone(),
                        crate::agent_tree::HostApprovalAuthority::trusted_host(),
                        session_id,
                        agent_instance_id,
                        Uuid::nil(),
                        tool_operation,
                    ),
                ));
                assert!(register_host_approval_effect_handoff(
                    HostApprovalEffectHandoff::new(
                        db.clone(),
                        crate::agent_tree::HostApprovalAuthority::trusted_host(),
                        session_id,
                        agent_instance_id,
                        Uuid::nil(),
                        connect_operation,
                    ),
                ));
                recheck_current_host_approval_effect_boundary(
                    "mcp_initialize_request",
                    &[serde_json::json!({
                        "connect": {"server": "calendar", "identity": "https://calendar.example.invalid/mcp"}
                    })],
                )
                .await?;
                let states: (String, String) = db
                    .read(move |conn| {
                        Ok((
                            conn.query_row(
                                "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                                [tool_operation_id.to_string()],
                                |row| row.get(0),
                            )?,
                            conn.query_row(
                                "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                                [connect_operation_id.to_string()],
                                |row| row.get(0),
                            )?,
                        ))
                    })
                    .await?;
                assert_eq!(states, ("ready".to_string(), "dispatching".to_string()));
                recheck_current_host_approval_effect_boundary(
                    "external_mcp_tools_call",
                    &[serde_json::json!({
                        "execute": {"server": "calendar", "tool": "create_event", "wire_input": {"title": "Planning"}}
                    })],
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            },
            |_: &()| Some(true),
        )
        .await
        .unwrap();

        let states: (String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [tool_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [connect_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(states, ("succeeded".to_string(), "succeeded".to_string()));
    }

    #[tokio::test]
    async fn composed_ready_handoffs_reject_mismatched_only_boundary() {
        let (db, session_id, agent_instance_id, revision) = running_host_effect_agent().await;
        let tool_operation = crate::agent_tree::HostApprovalOperation::new(
            "external_mcp_tool",
            serde_json::json!({
                "server": "calendar",
                "tool": "create_event",
                "candidate_effects": [{
                    "selection": "approve",
                    "execute": {"server": "calendar", "tool": "create_event", "wire_input": {"title": "Planning"}}
                }],
            }),
        )
        .unwrap();
        let tool_operation_id = tool_operation.operation_id;
        insert_ready_host_effect_handoff(
            &db,
            session_id,
            agent_instance_id,
            revision,
            &tool_operation,
        )
        .await;

        with_host_approval_effect_scope(
            "mcp_initialize_request",
            tokio_util::sync::CancellationToken::new(),
            async {
                assert!(register_host_approval_effect_handoff(
                    HostApprovalEffectHandoff::new(
                        db.clone(),
                        crate::agent_tree::HostApprovalAuthority::trusted_host(),
                        session_id,
                        agent_instance_id,
                        Uuid::nil(),
                        tool_operation,
                    ),
                ));
                let error = recheck_current_host_approval_effect_boundary(
                    "mcp_initialize_request",
                    &[serde_json::json!({
                        "connect": {"server": "calendar", "identity": "https://calendar.example.invalid/mcp"}
                    })],
                )
                .await
                .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("no live host approval capability authorizes this effect boundary"),
                    "{error}"
                );
                Ok::<(), anyhow::Error>(())
            },
            |_: &()| Some(true),
        )
        .await
        .unwrap();

        let state: String = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                    [tool_operation_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(state, "rejected");
    }

    #[tokio::test]
    async fn skill_manage_composed_fence_rejects_every_action_after_owner_revision_invalidates() {
        for (action, payload) in [
            (
                "create",
                serde_json::json!({"description": "new", "content": "body"}),
            ),
            ("delete", serde_json::json!({"absorbed_into": "umbrella"})),
            (
                "remove_file",
                serde_json::json!({"path": "references/old.md"}),
            ),
        ] {
            let (db, session_id, agent_instance_id, revision) = running_host_effect_agent().await;
            let root = format!("/external-skills/{action}");
            let access_operation = crate::agent_tree::HostApprovalOperation::new(
                "path_access",
                serde_json::json!({
                    "path": &root,
                    "required_access": "ReadWrite",
                    "candidate_effects": [{
                        "selection": "approve",
                        "access": {"path": &root, "required_access": "ReadWrite"},
                    }],
                }),
            )
            .unwrap();
            let mutation_operation = crate::agent_tree::HostApprovalOperation::new(
                "skill_manage_mutation",
                serde_json::json!({
                    "action": action,
                    "skill_name": "revision-race",
                    "payload": payload,
                    "candidate_effects": [{
                        "selection": "approve",
                        "execute": {
                            "action": action,
                            "skill_name": "revision-race",
                            "payload": payload,
                        },
                    }],
                }),
            )
            .unwrap();
            let access_operation_id = access_operation.operation_id;
            let mutation_operation_id = mutation_operation.operation_id;
            insert_ready_host_effect_handoff(
                &db,
                session_id,
                agent_instance_id,
                revision,
                &access_operation,
            )
            .await;
            insert_ready_host_effect_handoff(
                &db,
                session_id,
                agent_instance_id,
                revision,
                &mutation_operation,
            )
            .await;
            assert!(matches!(
                db.transition_agent_instance(
                    session_id,
                    agent_instance_id,
                    revision,
                    crate::db::agent_tree_decisions::AgentInstanceState::Cancelled,
                    "{}",
                    4,
                )
                .await
                .unwrap(),
                crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(_)
            ));

            with_host_approval_effect_scope(
                "skill_manage_mutation",
                tokio_util::sync::CancellationToken::new(),
                async {
                    for operation in [access_operation, mutation_operation] {
                        assert!(register_host_approval_effect_handoff(
                            HostApprovalEffectHandoff::new(
                                db.clone(),
                                crate::agent_tree::HostApprovalAuthority::trusted_host(),
                                session_id,
                                agent_instance_id,
                                Uuid::nil(),
                                operation,
                            ),
                        ));
                    }
                    let error = recheck_current_host_approval_effect_boundary(
                        "skill_manage_mutation",
                        &[
                            serde_json::json!({
                                "access": {"path": &root, "required_access": "ReadWrite"},
                            }),
                            serde_json::json!({
                                "execute": {
                                    "action": action,
                                    "skill_name": "revision-race",
                                    "payload": payload,
                                },
                            }),
                        ],
                    )
                    .await
                    .unwrap_err();
                    assert!(
                        error
                            .to_string()
                            .contains("capability is no longer live at effect boundary"),
                        "{action}: {error}"
                    );
                    Ok::<(), anyhow::Error>(())
                },
                |_: &()| Some(true),
            )
            .await
            .unwrap();

            let states: (String, String) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                            [access_operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                            [mutation_operation_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                states,
                ("rejected".to_string(), "rejected".to_string()),
                "{action}"
            );
        }
    }

    #[tokio::test]
    async fn nested_effect_cancellation_wins_after_claim_over_outer_success() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/repo", "builder")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let agent = match db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                2,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected running transition: {outcome:?}"),
        };
        let candidate = serde_json::json!({
            "selection": "approve",
            "execute": {"operation": "nested-effect"},
        });
        let operation = crate::agent_tree::HostApprovalOperation::new(
            "nested_effect",
            serde_json::json!({
                "operation": "nested-effect",
                "candidate_effects": [candidate.clone()],
            }),
        )
        .unwrap();
        let selected_candidate_json =
            String::from_utf8(crate::agent_tree::canonical_json_bytes(&candidate).unwrap())
                .unwrap();
        let operation_id = operation.operation_id;
        let operation_kind = operation.operation_kind.clone();
        let canonical_input_json = operation.canonical_input_json.clone();
        let input_digest = operation.input_digest.clone();
        let session_id = session.session_id.to_string();
        let agent_id = agent.agent_instance_id.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, state, approved_agent_revision,
                     selected_response_json, selected_candidate_json, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'approved', ?7, ?8, ?9, 3)",
                rusqlite::params![
                    operation_id.to_string(),
                    session_id.clone(),
                    agent_id.clone(),
                    operation_kind.clone(),
                    canonical_input_json.clone(),
                    input_digest.clone(),
                    agent.revision,
                    r#"{"kind":"single","data":{"selected_id":"approve"}}"#,
                    selected_candidate_json.clone(),
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, selected_candidate_json,
                     idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ready', 3)",
                rusqlite::params![
                    operation_id.to_string(),
                    session_id,
                    agent_id,
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    selected_candidate_json,
                    operation_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let outer_cancel = tokio_util::sync::CancellationToken::new();
        let inner_cancel = tokio_util::sync::CancellationToken::new();
        let inner_for_effect = inner_cancel.clone();
        with_host_approval_effect_scope(
            "outer_host_effect",
            outer_cancel,
            async {
                with_host_approval_effect_scope(
                    "computer_coordinator_backend_execute",
                    inner_cancel,
                    async {
                        assert!(register_host_approval_effect_handoff(
                            HostApprovalEffectHandoff::new(
                                db.clone(),
                                crate::agent_tree::HostApprovalAuthority::trusted_host(),
                                session.session_id,
                                agent.agent_instance_id,
                                Uuid::nil(),
                                operation,
                            ),
                        ));
                        recheck_current_host_approval_effect_boundary(
                            "computer_coordinator_backend_execute",
                            &[serde_json::json!({
                                "execute": {"operation": "nested-effect"},
                            })],
                        )
                        .await?;
                        // This mirrors coordinator invalidation after the
                        // durable handoff claim but before the outer tool
                        // wrapper reports a successful result.
                        inner_for_effect.cancel();
                        Ok::<(), anyhow::Error>(())
                    },
                    |_: &()| Some(true),
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            },
            |_: &()| Some(true),
        )
        .await
        .unwrap();

        let states: (String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            states,
            ("submission_unknown".into(), "submission_unknown".into())
        );
    }

    #[tokio::test]
    async fn pre_resolved_host_approval_replay_completes_the_persisted_operation_receipt() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/repo", "builder")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                crate::db::agent_tree_decisions::NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let agent = match db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                2,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected agent transition: {outcome:?}"),
        };
        let input = serde_json::json!({
            "effect": "replay-receipt",
            "candidate_effects": [{
                "selection": "approve",
                "execute": {"effect": "replay-receipt"},
            }],
        });
        let persisted_operation =
            crate::agent_tree::HostApprovalOperation::new("replay_receipt_effect", input.clone())
                .unwrap();
        let persisted_operation_id = persisted_operation.operation_id;
        let question = InterruptQuestion::Single {
            prompt: "Approve replay receipt effect?".into(),
            options: vec![InterruptOption {
                id: "approve".into(),
                label: "Approve".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let questions = InterruptQuestionSet {
            questions: vec![question],
        };
        let description = "replay receipt effect";
        let interrupt_id = db
            .raise_interrupt_questions_with_agent_instance_and_payload(
                session.session_id,
                "builder",
                Some(agent.agent_instance_id),
                description,
                &questions,
                None,
            )
            .await
            .unwrap();
        db.reserve_host_approval_final_operation(
            session.session_id,
            agent.agent_instance_id,
            persisted_operation.operation_id,
            persisted_operation.operation_kind.clone(),
            persisted_operation.canonical_input_json.clone(),
            persisted_operation.input_digest.clone(),
            crate::agent_tree::HostApprovalAuthority::trusted_host().into_db(),
            3,
        )
        .await
        .unwrap();
        let lifecycle = crate::agent_tree::AgentTreeLifecycle::new(db.clone());
        let decision = lifecycle
            .request_decision_for_interrupt(
                session.session_id,
                crate::agent_tree::NewDecisionContract::user_question_interrupt(
                    agent.agent_instance_id,
                    agent.revision,
                    &questions,
                    None,
                )
                .unwrap()
                .with_host_approval_subject(
                    persisted_operation,
                    crate::agent_tree::HostApprovalAuthority::trusted_host(),
                ),
                interrupt_id,
                3,
            )
            .await
            .unwrap();
        let approval_response = ResolveResponse::Single {
            selected_id: "approve".into(),
        };
        lifecycle
            .resolve_host_approval(
                session.session_id,
                decision.decision_request_id,
                interrupt_id,
                &serde_json::to_string(&approval_response).unwrap(),
                crate::agent_tree::HostApprovalAuthority::trusted_host(),
                4,
            )
            .await
            .unwrap();

        // Recovery reconstructs the same canonical facts but starts with a
        // fresh UUID. The replay bridge must replace it only after matching
        // the persisted decision and drive that persisted UUID to completion.
        let replay_operation =
            crate::agent_tree::HostApprovalOperation::new("replay_receipt_effect", input).unwrap();
        assert_ne!(replay_operation.operation_id, persisted_operation_id);
        let replay_questions = questions.clone();
        let concrete_effect = serde_json::json!({
            "execute": {"effect": "replay-receipt"},
        });
        with_pre_resolved_interrupt_question(
            interrupt_id,
            approval_response,
            PreResolvedInterruptQuestion {
                agent_instance_id: Some(agent.agent_instance_id),
                agent: "builder".into(),
                description: description.into(),
                questions: replay_questions.clone(),
                occurrence: 1,
            },
            async {
                with_host_approval_effect_scope(
                    // The broad ordinary gate has an opaque `Result<()>`.
                    // The nested concrete ToolOutput boundary must propagate
                    // its classifier through the shared scope.
                    "ordinary_tool_dispatch_gate",
                    tokio_util::sync::CancellationToken::new(),
                    async {
                        with_host_approval_effect_scope(
                            "tool_dispatch",
                            tokio_util::sync::CancellationToken::new(),
                            async {
                                let outcome = raise_and_wait_with_agent_tree(
                                    &db,
                                    &InterruptHub::detached(),
                                    session.session_id,
                                    "builder",
                                    Some(agent.agent_instance_id),
                                    description,
                                    replay_questions,
                                    crate::agent_tree::HostDecisionSubject::HostApproval {
                                        operation: replay_operation,
                                    },
                                    "replay test",
                                )
                                .await;
                                assert!(matches!(
                                    outcome,
                                    InterruptOutcome::Resolved(ResolveResponse::Single { ref selected_id })
                                        if selected_id == "approve"
                                ));
                                // Simulate the real concrete tool boundary:
                                // approval consumed, exact candidate claimed
                                // and rechecked, then a successful ToolOutput.
                                recheck_current_host_approval_effect_boundary(
                                    "tool_dispatch",
                                    std::slice::from_ref(&concrete_effect),
                                )
                                .await?;
                                Ok::<crate::engine::tool::ToolOutput, anyhow::Error>(
                                    crate::engine::tool::ToolOutput::text("effect succeeded"),
                                )
                            },
                            |output: &crate::engine::tool::ToolOutput| {
                                Some(output.exit_code.is_none_or(|code| code == 0))
                            },
                        )
                        .await
                        .map(|_| ())
                    },
                    |_: &()| None,
                )
                .await
            },
        )
        .await
        .unwrap();

        let (operation_state, handoff_state, handoff_operation_id, receipt): (
            String,
            String,
            String,
            String,
        ) = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT operation.state, handoff.state, handoff.operation_id,
                            handoff.completion_receipt_json
                       FROM agent_host_approval_operations operation
                       JOIN agent_host_approval_effect_handoffs handoff
                         ON handoff.operation_id = operation.operation_id
                      WHERE operation.operation_id = ?1",
                    [persisted_operation_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(operation_state, "completed");
        assert_eq!(handoff_state, "succeeded");
        assert_eq!(handoff_operation_id, persisted_operation_id.to_string());
        assert!(receipt.contains("tool_dispatch"), "{receipt}");
    }
}
