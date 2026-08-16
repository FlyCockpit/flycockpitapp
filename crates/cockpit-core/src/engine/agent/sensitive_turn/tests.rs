//! Tests for the provider sensitive-turn barrier state machine.
//!
//! These drive the `Open -> Buffering -> Released | Contained | Discarded` machine
//! through a fake [`SensitiveContainmentHost`] so the ordering and fail-closed
//! guarantees are proven without a live daemon:
//!
//! * `provider_sensitive_turn_state_machine_*` — the state machine transitions.
//! * `buffered_delivery_ordering_*` — a `report_leak` decode buffers/contains and
//!   never lets its plaintext (nor any other buffered item) reach generic
//!   dispatch, in any ordering.
//! * `redaction_install_*` — the reported secret is installed into the redaction
//!   table BEFORE the `contained` ack, and an install failure fails closed.
//! * `contain_*` / `malformed_*` / `rate_limited_*` — fail-closed classification.
//! * `provider_adapter_registration_includes_sensitive_barrier` — the closed
//!   registration barrier (AC10).

use std::sync::Mutex;

use serde_json::{Value, json};

use super::*;
use crate::leak_report::LeakReportOutcome;

/// A fake host recording the order and payloads of `contain` / `install_redaction`
/// so the barrier's ordering and fail-closed behavior are directly assertable.
struct FakeHost {
    /// Ordered sequence of operations: "contain" then "install".
    events: Mutex<Vec<&'static str>>,
    /// The literal(s) handed to `install_redaction`.
    installed: Mutex<Vec<String>>,
    /// The raw args handed to `contain`.
    contained_args: Mutex<Vec<Value>>,
    /// What `contain` returns.
    outcome: LeakReportOutcome,
    /// Whether `install_redaction` succeeds.
    install_ok: bool,
}

impl FakeHost {
    fn with(outcome: LeakReportOutcome, install_ok: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            installed: Mutex::new(Vec::new()),
            contained_args: Mutex::new(Vec::new()),
            outcome,
            install_ok,
        }
    }

    fn contained() -> Self {
        Self::with(
            LeakReportOutcome::Contained {
                report_id: "report-1".to_string(),
            },
            true,
        )
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
    fn installed(&self) -> Vec<String> {
        self.installed.lock().unwrap().clone()
    }
    fn contained_args(&self) -> Vec<Value> {
        self.contained_args.lock().unwrap().clone()
    }
}

#[async_trait]
impl SensitiveContainmentHost for FakeHost {
    async fn contain(&self, args: &Value) -> LeakReportOutcome {
        self.events.lock().unwrap().push("contain");
        self.contained_args.lock().unwrap().push(args.clone());
        self.outcome.clone()
    }

    async fn install_redaction(&self, secret: &Zeroizing<String>) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("install");
        self.installed
            .lock()
            .unwrap()
            .push(secret.as_str().to_owned());
        if self.install_ok {
            Ok(())
        } else {
            anyhow::bail!("install failed")
        }
    }
}

fn tool_call(name: &str, args: Value) -> ToolCall {
    use rig::message::ToolFunction;
    ToolCall {
        id: format!("tc-{name}"),
        call_id: None,
        function: ToolFunction {
            name: name.to_string(),
            arguments: args,
        },
        signature: None,
        additional_params: None,
    }
}

fn report_leak_call(secret: &str) -> ToolCall {
    tool_call(
        REPORT_LEAK_TOOL,
        json!({ "secret": secret, "source": "model_output" }),
    )
}

// ---------------------------------------------------------------------------
// Released: an ordinary turn with no sensitive-ingress call passes through.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_sensitive_turn_state_machine_releases_ordinary_turn() {
    let host = FakeHost::contained();
    let calls = vec![
        tool_call("read", json!({ "path": "src/lib.rs" })),
        tool_call("write", json!({ "path": "a", "content": "b" })),
    ];
    let out = run_sensitive_turn_barrier(&host, calls.clone()).await;

    assert_eq!(out.state, SensitiveTurnState::Released);
    // Every ordinary call survives, in order, to generic dispatch.
    assert_eq!(out.generic_calls.len(), 2);
    assert_eq!(out.generic_calls[0].function.name, "read");
    assert_eq!(out.generic_calls[1].function.name, "write");
    assert!(out.sensitive_results.is_empty());
    // Containment was never entered for an ordinary turn.
    assert!(host.events().is_empty());
}

// ---------------------------------------------------------------------------
// Contained: a valid report_leak commits + installs redaction + acks `contained`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_sensitive_turn_state_machine_contains_valid_report_leak() {
    let host = FakeHost::contained();
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call("SENTINEL-abc")]).await;

    assert_eq!(out.state, SensitiveTurnState::Contained);
    assert_eq!(out.sensitive_results.len(), 1);
    assert_eq!(out.sensitive_results[0].model_output, "contained");
    // Both containment and redaction install ran.
    assert_eq!(host.events(), vec!["contain", "install"]);
}

// ---------------------------------------------------------------------------
// Deduplicated still installs redaction and acks `contained`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_sensitive_turn_state_machine_deduplicated_installs_redaction() {
    let host = FakeHost::with(
        LeakReportOutcome::Deduplicated {
            report_id: "report-1".to_string(),
            seen_count: 2,
        },
        true,
    );
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call("dup-secret")]).await;

    assert_eq!(out.state, SensitiveTurnState::Contained);
    assert_eq!(out.sensitive_results[0].model_output, "contained");
    // A re-report still installs the redaction (idempotent), before the ack.
    assert_eq!(host.events(), vec!["contain", "install"]);
    assert_eq!(host.installed(), vec!["dup-secret".to_string()]);
}

// ---------------------------------------------------------------------------
// Buffered-delivery ORDERING: a report_leak decode buffers/contains and never
// lets its plaintext — nor any other buffered item — reach generic dispatch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_delivery_ordering_report_leak_never_reaches_generic_dispatch() {
    let secret = "PLAINTEXT-MUST-NOT-PERSIST-7f3a";
    let host = FakeHost::contained();
    // A report_leak call mixed with an ordinary tool call in the same turn.
    let calls = vec![
        tool_call("read", json!({ "path": "notes.txt" })),
        report_leak_call(secret),
        tool_call("write", json!({ "path": "out", "content": "x" })),
    ];
    let out = run_sensitive_turn_barrier(&host, calls).await;

    // The turn is Contained.
    assert_eq!(out.state, SensitiveTurnState::Contained);

    // COLLAPSE: no generic (ordinary) call survives to dispatch/persistence.
    assert!(
        out.generic_calls.is_empty(),
        "a sensitive turn must discard every other buffered ordinary tool call"
    );

    // The plaintext secret appears in NONE of the released representation: not in
    // the content-free results, not in any surviving generic call.
    let released = format!("{:?}{:?}", out.generic_calls, out.sensitive_results);
    assert!(
        !released.contains(secret),
        "the reported plaintext must never cross into the released turn representation"
    );
    // The only thing the model receives is the content-free `contained`.
    assert_eq!(out.sensitive_results.len(), 1);
    assert_eq!(out.sensitive_results[0].model_output, "contained");

    // The plaintext only ever reached the fail-closed host ingress (which
    // encrypts it), never a generic dispatch path.
    assert_eq!(host.contained_args().len(), 1);
    assert_eq!(host.installed(), vec![secret.to_string()]);
}

// ---------------------------------------------------------------------------
// Redaction install PRECEDES the `contained` ack.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redaction_install_precedes_contained_ack() {
    let secret = "install-before-ack-secret";
    let host = FakeHost::contained();
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call(secret)]).await;

    // The ack is `contained` ONLY because the install already ran: the recorded
    // order is contain -> install, and the install carried the exact secret.
    assert_eq!(host.events(), vec!["contain", "install"]);
    assert_eq!(host.installed(), vec![secret.to_string()]);
    assert_eq!(out.sensitive_results[0].model_output, "contained");
    // The `install` event is strictly before the ack is producible: the barrier
    // only maps to `contained` after `install_redaction` returns `Ok`.
    let events = host.events();
    let install_idx = events.iter().position(|e| *e == "install").unwrap();
    let contain_idx = events.iter().position(|e| *e == "contain").unwrap();
    assert!(contain_idx < install_idx);
}

// ---------------------------------------------------------------------------
// Fail-closed: a redaction-install failure never acks `contained`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redaction_install_failure_fails_closed() {
    // Containment commits, but the live redaction install fails.
    let host = FakeHost::with(
        LeakReportOutcome::Contained {
            report_id: "report-1".to_string(),
        },
        false, // install fails
    );
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call("secret")]).await;

    // The turn is Discarded — never Contained with a live unredacted secret.
    assert_eq!(out.state, SensitiveTurnState::Discarded);
    assert_eq!(out.sensitive_results[0].model_output, "failed");
    assert_ne!(out.sensitive_results[0].model_output, "contained");
    // The install WAS attempted (after containment) but failed closed.
    assert_eq!(host.events(), vec!["contain", "install"]);
    assert!(out.generic_calls.is_empty());
}

// ---------------------------------------------------------------------------
// Fail-closed: a containment error never installs redaction, never acks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contain_error_fails_closed_and_skips_install() {
    let host = FakeHost::with(LeakReportOutcome::Failed, true);
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call("secret")]).await;

    assert_eq!(out.state, SensitiveTurnState::Discarded);
    assert_eq!(out.sensitive_results[0].model_output, "failed");
    // Containment failed → the redaction install is never attempted.
    assert_eq!(host.events(), vec!["contain"]);
    assert!(host.installed().is_empty());
}

// ---------------------------------------------------------------------------
// Rate-limited: content-free `rate_limited`, no redaction install.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limited_report_leak_releases_content_free() {
    let host = FakeHost::with(LeakReportOutcome::RateLimited, true);
    let out = run_sensitive_turn_barrier(&host, vec![report_leak_call("secret")]).await;

    assert_eq!(out.state, SensitiveTurnState::Discarded);
    assert_eq!(out.sensitive_results[0].model_output, "rate_limited");
    // A rate-limited report installs no redaction.
    assert_eq!(host.events(), vec!["contain"]);
    assert!(host.installed().is_empty());
}

// ---------------------------------------------------------------------------
// Malformed report_leak: Discarded before containment, no plaintext handling.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_report_leak_is_discarded_before_containment() {
    let host = FakeHost::contained();
    // A closed-source violation: `source` is not in the closed enum.
    let bad = tool_call(
        REPORT_LEAK_TOOL,
        json!({ "secret": "x", "source": "arbitrary_untrusted_source" }),
    );
    let out = run_sensitive_turn_barrier(&host, vec![bad]).await;

    assert_eq!(out.state, SensitiveTurnState::Discarded);
    assert_eq!(out.sensitive_results[0].model_output, "failed");
    // Malformed args are rejected by the closed parser BEFORE the host ingress or
    // any redaction install runs.
    assert!(host.events().is_empty());
}

// ---------------------------------------------------------------------------
// Registration barrier (AC10): report_leak is always classified sensitive and
// pulled out before generic dispatch; no ordinary tool is classified sensitive.
// ---------------------------------------------------------------------------

#[test]
fn provider_adapter_registration_includes_sensitive_barrier() {
    // The closed set names the ingress-only tool exactly.
    assert!(SENSITIVE_INGRESS_TOOL_NAMES.contains(&REPORT_LEAK_TOOL));
    assert_eq!(REPORT_LEAK_TOOL, "report_leak");
    assert!(is_sensitive_ingress_tool("report_leak"));

    // Ordinary tools are never classified sensitive.
    for ordinary in ["read", "write", "bash", "task", "use_sealed_value", "mcp"] {
        assert!(
            !is_sensitive_ingress_tool(ordinary),
            "`{ordinary}` must dispatch generically, never through containment"
        );
    }

    // The partition pulls report_leak out of a mixed buffer BEFORE the generic
    // dispatch loop can see it — regardless of ordering.
    let (sensitive, generic) = partition_sensitive_calls(vec![
        tool_call("read", json!({})),
        report_leak_call("s"),
        tool_call("write", json!({})),
    ]);
    assert_eq!(sensitive.len(), 1);
    assert_eq!(sensitive[0].function.name, "report_leak");
    assert_eq!(generic.len(), 2);
    assert!(generic.iter().all(|c| c.function.name != "report_leak"));
}

// ---------------------------------------------------------------------------
// Multiple report_leak calls in one turn: all contained, one collapse.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_sensitive_turn_state_machine_contains_multiple_reports() {
    let host = FakeHost::contained();
    let out = run_sensitive_turn_barrier(
        &host,
        vec![report_leak_call("secret-a"), report_leak_call("secret-b")],
    )
    .await;

    assert_eq!(out.state, SensitiveTurnState::Contained);
    assert_eq!(out.sensitive_results.len(), 2);
    assert!(
        out.sensitive_results
            .iter()
            .all(|r| r.model_output == "contained")
    );
    assert_eq!(
        host.installed(),
        vec!["secret-a".to_string(), "secret-b".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Partial failure fails the WHOLE turn closed: a later failed call cannot be
// masked by an earlier contained one (no Contained latch).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_sensitive_turn_state_machine_partial_failure_discards_whole_turn() {
    let host = FakeHost::contained();
    // One valid report_leak + one malformed one (closed-source violation).
    let malformed = tool_call(
        REPORT_LEAK_TOOL,
        json!({ "secret": "x", "source": "bogus_source" }),
    );
    let out =
        run_sensitive_turn_barrier(&host, vec![report_leak_call("good-secret"), malformed]).await;

    // Even though the first call contained, the second's failure forces the whole
    // turn to fail closed — so the turn's surviving text/reasoning is dropped, not
    // released with a secret that was never installed.
    assert_eq!(out.state, SensitiveTurnState::Discarded);
    assert_eq!(out.sensitive_results.len(), 2);
    assert_eq!(out.sensitive_results[0].model_output, "contained");
    assert_eq!(out.sensitive_results[1].model_output, "failed");
}
