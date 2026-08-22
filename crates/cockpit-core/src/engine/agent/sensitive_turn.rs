//! Provider sensitive-turn barrier.
//!
//! The state machine `Open -> Buffering -> Released | Contained | Discarded` that
//! intercepts an ingress-only `report_leak` tool call **before** any generic tool
//! dispatch, history persistence, stream-to-parent delivery, audit, or export.
//!
//! A turn starts [`SensitiveTurnState::Open`]. The dispatch chokepoint hands this
//! module the full per-turn buffered tool-call list (the provider adapters have
//! already aggregated every streamed tool-call delta into one vector before any
//! generic dispatch runs — see the barrier seam in
//! `crate::engine::agent::turn_phases::run_turn`). If none of the buffered calls
//! is a sensitive-ingress call the turn is [`SensitiveTurnState::Released`] and
//! ordinary dispatch proceeds unchanged. If at least one is, the turn moves to
//! [`SensitiveTurnState::Buffering`]: every buffered item is now withheld, the
//! sensitive call is routed through the fail-closed host ingress
//! [`crate::leak_report::decode_and_contain_report_leak`], the reported secret is
//! installed into the live redaction table **before** the turn is acked, and the
//! turn terminates:
//!
//! * [`SensitiveTurnState::Contained`] — a valid `report_leak` committed its
//!   protected record and the redaction install succeeded. The model receives
//!   only `contained`; every other buffered text/reasoning/ordinary tool call is
//!   discarded (absent from parent/UI/history/tool/audit/export).
//! * [`SensitiveTurnState::Discarded`] — a malformed call, a rate-limited call, a
//!   containment error, or a redaction-install failure. **No** plaintext is ever
//!   released; the model receives only a content-free `rate_limited` / `failed`.
//!
//! ## Registration barrier (AC10)
//!
//! [`SENSITIVE_INGRESS_TOOL_NAMES`] is the closed set of ingress-only tool names.
//! [`partition_sensitive_calls`] pulls every call whose name is in that set out of
//! the buffered list **before** the generic dispatch loop can ever see it, so
//! `report_leak` can never be dispatched as a generic tool — regardless of whether
//! it was (incorrectly) advertised on the generic roster. No type in
//! `crate::leak_report` implements [`crate::engine::tool::Tool`], so the plaintext
//! `secret` argument can never reach the generic authorized-tool surface; this
//! barrier is the runtime half of that guarantee at the dispatch chokepoint.
//!
//! ## Fail-closed
//!
//! There is no `.unwrap()`/panic on the decode/containment path. Any containment
//! error, key-store failure, rate limit, malformed argument, or redaction-install
//! failure terminates the turn [`SensitiveTurnState::Discarded`] with a
//! content-free result — never [`SensitiveTurnState::Contained`] with a live
//! unredacted secret, and never a plaintext byte crossing to generic persistence.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::engine::message::ToolCall;
use crate::leak_report::{LeakReportOutcome, REPORT_LEAK_TOOL, parse_report_leak_args};

/// The provider sensitive-turn lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveTurnState {
    /// The turn has not been classified yet.
    Open,
    /// A sensitive-ingress call is present; all buffered output is withheld until
    /// classification completes.
    Buffering,
    /// No sensitive-ingress call was present; ordinary dispatch proceeds.
    Released,
    /// A valid `report_leak` committed and its redaction was installed before ack.
    Contained,
    /// The turn was discarded (malformed / rate-limited / containment error /
    /// install failure); no plaintext was released.
    Discarded,
}

impl SensitiveTurnState {
    /// `Open -> Released`: no sensitive-ingress call was buffered, so the turn is
    /// released to ordinary dispatch. Only valid from [`SensitiveTurnState::Open`].
    fn released(self) -> Self {
        debug_assert_eq!(self, SensitiveTurnState::Open);
        SensitiveTurnState::Released
    }

    /// `Open -> Buffering`: a sensitive-ingress call is present, so every buffered
    /// item is withheld pending classification. Only valid from
    /// [`SensitiveTurnState::Open`].
    fn buffering(self) -> Self {
        debug_assert_eq!(self, SensitiveTurnState::Open);
        SensitiveTurnState::Buffering
    }
}

/// The closed set of ingress-only tool names that MUST be contained before any
/// generic dispatch and can NEVER be registered/dispatched as a generic tool
/// (AC10 registration barrier). Adding a sensitive-ingress name here is the only
/// way to introduce one; the dispatch chokepoint routes every name in this set to
/// containment, so a new tool-call decoder cannot omit the barrier.
pub const SENSITIVE_INGRESS_TOOL_NAMES: [&str; 1] = [REPORT_LEAK_TOOL];

/// Whether `name` is an ingress-only sensitive tool that must be contained rather
/// than dispatched generically.
pub fn is_sensitive_ingress_tool(name: &str) -> bool {
    SENSITIVE_INGRESS_TOOL_NAMES.contains(&name)
}

/// Whether the sensitive-turn barrier engages (decodes + contains) for this turn.
///
/// The barrier engages **only** on a route that advertised `report_leak`
/// (`report_leak_eligible`, the single funnel
/// [`crate::leak_report::route_advertises_report_leak`]) AND that buffered at
/// least one sensitive-ingress call. A route that never advertised the schema —
/// trusted, tool-disabled, or otherwise unsupported — does **not** decode or
/// contain a `report_leak`-named call (AC3: those routes "neither advertise nor
/// decode it"). On such a route a hallucinated `report_leak { secret: ... }`
/// falls through to ordinary unknown-tool handling: its plaintext argument is
/// never parsed into a zeroizing frame, never durably contained, and never
/// collapses the turn. This is the SAME predicate that gates schema advertisement
/// and the buffered-delivery sink, so decode/contain, advertise, and withhold
/// can never drift apart.
pub fn sensitive_turn_engages(report_leak_eligible: bool, calls: &[ToolCall]) -> bool {
    report_leak_eligible
        && calls
            .iter()
            .any(|tc| is_sensitive_ingress_tool(&tc.function.name))
}

/// Partition a per-turn buffered tool-call list into (sensitive-ingress calls,
/// generic calls), preserving order within each bucket.
///
/// This is the registration barrier at the dispatch chokepoint: a sensitive call
/// is pulled out **before** the generic dispatch loop can see it, so a
/// `report_leak` call can never reach generic dispatch/persistence in any decoder
/// ordering.
pub fn partition_sensitive_calls(calls: Vec<ToolCall>) -> (Vec<ToolCall>, Vec<ToolCall>) {
    let mut sensitive = Vec::new();
    let mut generic = Vec::new();
    for tc in calls {
        if is_sensitive_ingress_tool(&tc.function.name) {
            sensitive.push(tc);
        } else {
            generic.push(tc);
        }
    }
    (sensitive, generic)
}

/// The host boundary the barrier drives: the fail-closed containment ingress and
/// the live-session redaction install.
///
/// Kept as a trait so the state machine's ordering and fail-closed guarantees are
/// unit-testable without a live daemon. The production implementation is
/// [`LiveSensitiveContainmentHost`].
#[async_trait]
pub trait SensitiveContainmentHost: Send + Sync {
    /// Route a decoded `report_leak` argument object through the fail-closed host
    /// ingress ([`crate::leak_report::decode_and_contain_report_leak`]). Returns
    /// only the closed content-free outcome; never plaintext.
    async fn contain(&self, args: &Value) -> LeakReportOutcome;

    /// Install the reported secret literal into the LIVE session redaction table
    /// so subsequent output is scrubbed. Called on a Contained/Deduplicated
    /// classification **before** the turn is acked. Fail-closed: an `Err` aborts
    /// the containment ack — the turn is Discarded, never acked `contained` with a
    /// live unredacted secret.
    async fn install_redaction(&self, secret: &Zeroizing<String>) -> Result<()>;
}

/// The content-free result the model receives for one sensitive-ingress call.
///
/// Carries only the originating call's safe wire identifiers — NEVER its
/// arguments. The plaintext `secret` argument is consumed into a zeroizing frame
/// by the containment path and never reaches this released structure, so a
/// `SensitiveResult` is safe to log, serialize, or hand back to the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveResult {
    /// The originating call's wire id (a random tool-call id; never the secret).
    pub call_id: String,
    /// The originating call's optional provider-supplied call id.
    pub provider_call_id: Option<String>,
    /// The content-free model string: `contained` | `rate_limited` | `failed`.
    pub model_output: String,
}

/// The terminal classification of a turn that passed through the barrier.
#[derive(Debug, Clone)]
pub struct SensitiveTurnOutcome {
    /// Terminal state.
    pub state: SensitiveTurnState,
    /// Generic (non-sensitive) tool calls that survive to ordinary dispatch. On a
    /// Contained/Discarded sensitive turn this is EMPTY: every other buffered item
    /// is dropped so no non-sensitive item reaches parent/UI/history/tool/audit.
    pub generic_calls: Vec<ToolCall>,
    /// Content-free results for each sensitive call, in order.
    pub sensitive_results: Vec<SensitiveResult>,
}

/// Contain a single decoded `report_leak` call. Returns `(contained, model_str)`.
///
/// `contained` is true only when the protected record committed AND the live
/// redaction install succeeded — the ordering the ack depends on.
async fn contain_one(host: &dyn SensitiveContainmentHost, call: &ToolCall) -> (bool, &'static str) {
    // Parse the raw args into a zeroizing secret frame. Generic dispatch never
    // sees this literal. A malformed sensitive call is Discarded (content-free
    // `failed`) with no containment and no redaction install.
    let request = match parse_report_leak_args(&call.function.arguments) {
        Ok(r) => r,
        Err(_) => return (false, "failed"),
    };

    // Route through the fail-closed host ingress (commits the protected record).
    let outcome = host.contain(&call.function.arguments).await;
    match &outcome {
        LeakReportOutcome::Contained { .. } | LeakReportOutcome::Deduplicated { .. } => {
            // The reported secret MUST be installed into the live redaction table
            // BEFORE the `contained` ack, so downstream output is scrubbed.
            // Fail-closed: an install error Discards the turn (never acked
            // `contained` with a live unredacted secret).
            match host.install_redaction(&request.secret).await {
                Ok(()) => (true, "contained"),
                Err(_) => (false, "failed"),
            }
        }
        // Rate-limited / failed containment: content-free, no redaction install,
        // no plaintext released.
        other => (false, other.to_model_string()),
    }
    // `request` (the `Zeroizing` secret) is dropped and wiped here.
}

/// Run the provider sensitive-turn barrier over one turn's buffered tool calls.
///
/// See the module docs for the full state machine. On a turn containing any
/// sensitive-ingress call, `generic_calls` is empty (every other buffered item is
/// discarded) and the returned results are content-free.
pub async fn run_sensitive_turn_barrier(
    host: &dyn SensitiveContainmentHost,
    calls: Vec<ToolCall>,
) -> SensitiveTurnOutcome {
    // Open: the turn is unclassified until the buffered calls are partitioned.
    let state = SensitiveTurnState::Open;
    let (sensitive, generic) = partition_sensitive_calls(calls);
    if sensitive.is_empty() {
        // Open -> Released: an ordinary turn with no sensitive-ingress call.
        return SensitiveTurnOutcome {
            state: state.released(),
            generic_calls: generic,
            sensitive_results: Vec::new(),
        };
    }

    // Open -> Buffering: at least one sensitive-ingress call. Every buffered
    // item (including the turn's text/reasoning, buffered upstream by the
    // streaming barrier) is now withheld until classification completes.
    let state = state.buffering();
    let mut all_contained = true;
    let mut results = Vec::with_capacity(sensitive.len());
    for call in sensitive {
        let (contained, model_output) = contain_one(host, &call).await;
        if !contained {
            // Any per-call containment failure (malformed / rate-limited /
            // containment error / redaction-install failure) forces the WHOLE
            // turn to fail closed: a later successful containment can never
            // "latch" the turn Contained and thereby release surviving output
            // that may hold a secret which was NOT installed into the table.
            all_contained = false;
        }
        // Carry only the safe wire identifiers — never the plaintext arguments.
        results.push(SensitiveResult {
            call_id: call.id.to_string(),
            provider_call_id: call
                .provider
                .as_ref()
                .map(|provider| provider.call_id.clone()),
            model_output: model_output.to_string(),
        });
    }

    // Buffering -> Contained iff EVERY reported secret was committed and its
    // redaction installed; otherwise the turn fails closed (Discarded) so its
    // surviving text/reasoning is dropped, never released raw.
    let state = match (state, all_contained) {
        (SensitiveTurnState::Buffering, true) => SensitiveTurnState::Contained,
        _ => SensitiveTurnState::Discarded,
    };

    SensitiveTurnOutcome {
        state,
        // Collapse: no generic call survives a sensitive turn, so no buffered
        // non-sensitive item reaches parent/UI/history/tool/audit/export.
        generic_calls: Vec::new(),
        sensitive_results: results,
    }
}

/// The production [`SensitiveContainmentHost`], backed by the live session's
/// database, protected-redaction-history key resolver, and interrupt hub (which
/// owns the live redaction table). Provenance is **host-derived** from the active
/// route (provider/model), never from model-supplied data.
pub struct LiveSensitiveContainmentHost<'a> {
    /// The session database the protected record commits to.
    pub db: &'a crate::db::Db,
    /// The protected-redaction-history key resolver (fail-closed on key failure).
    pub key_resolver: &'a dyn crate::redact::protected_redaction_history::RedactionKeyResolver,
    /// The interrupt hub that owns the live redaction table (redaction install).
    pub interrupts: &'a crate::engine::interrupt::InterruptHub,
    /// The live session (persists the redaction table; supplies the resolver).
    pub session: &'a crate::session::Session,
    /// Host-derived provenance stamped on the containment record.
    pub provenance: crate::db::protected_leak_records::LeakProvenance,
    /// The session id the report is bound to.
    pub session_id: String,
    /// Wall-clock milliseconds stamped on the containment record.
    pub now_ms: i64,
}

#[async_trait]
impl SensitiveContainmentHost for LiveSensitiveContainmentHost<'_> {
    async fn contain(&self, args: &Value) -> LeakReportOutcome {
        crate::leak_report::decode_and_contain_report_leak(
            self.db,
            self.key_resolver,
            self.now_ms,
            self.provenance.clone(),
            &self.session_id,
            args,
        )
        .await
    }

    async fn install_redaction(&self, secret: &Zeroizing<String>) -> Result<()> {
        // Install the forced contained-leak literal into the live redaction table
        // before the ack. The encrypted protected-history row was already written
        // by `contain`; this only swaps the live scrubbing table.
        match self
            .interrupts
            .install_contained_leak_literal(self.session, secret.as_str().to_owned())
            .await?
        {
            Some(_table) => Ok(()),
            // No live redaction table (a detached / standalone hub owns none):
            // fail CLOSED. Without a live table the reported secret cannot be
            // scrubbed from subsequent output, so the report must NOT be acked
            // Contained — the caller downgrades the turn to Discarded.
            None => anyhow::bail!(
                "no live redaction table available to install the contained-leak literal"
            ),
        }
    }
}

#[cfg(test)]
mod tests;
