//! Tests for the per-turn buffered delivery sink (leak-report increment 2,
//! AC1/2/2b/2c).
//!
//! These drive the sink's real public API — the exact surface `run_turn` uses:
//! [`BufferedDeliverySink::spawn`] hands the completion an `event_tx`, the caller
//! drops it and [`BufferedDeliverySink::finish`]es to collect the withheld
//! deltas, then either [`WithheldDeltas::flush_to`]s (a positively-classified
//! non-sensitive turn) or drops the buffer (every contained / discarded / error
//! / overflow path).
//!
//! Non-vacuity: each test plants a DISTINCT marker in a withheld delta, asserts
//! the marker really entered the buffer (precondition), and proves it does NOT
//! reach the real channel on a drop path — with a positive control that a flush
//! WOULD surface it. A sink that (like current production) forwarded deltas live
//! would fail `withholds_deltas_until_classification` and `overflow_is_discarded`
//! immediately.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::*;

const AGENT: &str = "builder";

fn text_delta(delta: &str) -> TurnEvent {
    TurnEvent::AssistantTextDelta {
        agent: AGENT.to_string(),
        delta: delta.to_string(),
    }
}

fn reasoning_delta(delta: &str) -> TurnEvent {
    TurnEvent::ReasoningDelta {
        agent: AGENT.to_string(),
        delta: delta.to_string(),
    }
}

fn inference_warning() -> TurnEvent {
    TurnEvent::InferenceWarning {
        agent: AGENT.to_string(),
        provider: "openai".to_string(),
        model: "m".to_string(),
        phase: "ttft".to_string(),
        waited_secs: 1,
    }
}

/// The retry-boundary status event the model layer sends (via the SAME channel,
/// in order) right before it re-invokes a failed attempt.
fn reconnecting() -> TurnEvent {
    TurnEvent::Reconnecting {
        agent: AGENT.to_string(),
        attempt: 1,
        provider: "openai".to_string(),
        model: "m".to_string(),
        url: "http://127.0.0.1/v1".to_string(),
    }
}

/// Drain everything currently queued on the real channel into a Vec.
fn drain(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

/// Whether any event on the real channel carries `needle` in a delta payload.
fn any_delta_contains(events: &[TurnEvent], needle: &str) -> bool {
    events.iter().any(|event| match event {
        TurnEvent::AssistantTextDelta { delta, .. } | TurnEvent::ReasoningDelta { delta, .. } => {
            delta.contains(needle)
        }
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// AC1 — withhold text/reasoning deltas until classification; on a Contained
// turn they never reach the client stream.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_delivery_withholds_deltas_until_classification() {
    const SECRET: &str = "sk-PLANTED-LEAK-AC1-000";

    let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());

    // The completion streams a secret-bearing text delta, a reasoning delta, and
    // a non-delta status event, all BEFORE the turn is classified.
    event_tx
        .send(text_delta(&format!("here is {SECRET} oops")))
        .await
        .unwrap();
    event_tx.send(reasoning_delta("thinking...")).await.unwrap();
    event_tx.send(inference_warning()).await.unwrap();

    // Completion returns: close the wrapped sender and collect the buffer.
    drop(event_tx);
    let withheld = sink.finish().await;

    // The non-delta status event forwarded LIVE; both deltas were WITHHELD.
    let live = drain(&mut real_rx);
    assert!(
        live.iter()
            .any(|e| matches!(e, TurnEvent::InferenceWarning { .. })),
        "the non-delta status event must forward live"
    );
    assert!(
        !any_delta_contains(&live, SECRET),
        "the planted secret must NOT reach the client stream before classification"
    );
    assert!(
        !live.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantTextDelta { .. } | TurnEvent::ReasoningDelta { .. }
        )),
        "no delta may reach the client stream before classification"
    );

    // Precondition: the deltas really were captured (so the absence above is
    // withholding, not that nothing was ever sent).
    assert_eq!(withheld.withheld_count(), 2, "both deltas must be withheld");
    assert!(!withheld.overflowed());

    // A Contained turn DROPS the buffer (never flushes). Simulate that: do not
    // call flush_to. The secret never reaches the client on any channel.
    drop(withheld);
    assert!(
        drain(&mut real_rx).is_empty(),
        "a Contained turn must not release any withheld plaintext"
    );
}

// ---------------------------------------------------------------------------
// AC2 — a non-sensitive (Released) turn flushes the buffered deltas in order.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_sensitive_turn_flushes_buffered_deltas_in_order() {
    let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx.clone(), CancellationToken::new());

    event_tx.send(text_delta("A")).await.unwrap();
    event_tx.send(reasoning_delta("R")).await.unwrap();
    event_tx.send(text_delta("B")).await.unwrap();

    drop(event_tx);
    let withheld = sink.finish().await;

    // Before classification, nothing streamed.
    assert!(
        drain(&mut real_rx).is_empty(),
        "deltas must be withheld until the turn is classified"
    );

    // Released: flush the buffer in stream order.
    withheld.flush_to(&real_tx).await;

    let flushed = drain(&mut real_rx);
    let payloads: Vec<&str> = flushed
        .iter()
        .filter_map(|e| match e {
            TurnEvent::AssistantTextDelta { delta, .. }
            | TurnEvent::ReasoningDelta { delta, .. } => Some(delta.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        payloads,
        vec!["A", "R", "B"],
        "Released turn must flush every withheld delta in original stream order"
    );
}

// ---------------------------------------------------------------------------
// AC2b — every pre-classification terminal path is Discarded: the withheld
// plaintext reaches neither the client stream nor any durable/parent/log/export
// representation, and the sink never deadlocks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_delivery_terminal_paths_are_discarded() {
    // A terminal path (cancellation, provider/inference error, EOF without a
    // classification, a malformed / rate-limited report_leak, a mixed-call
    // discard, a dropped completion future) all reduce, at the delivery seam, to
    // "the buffer is dropped, never flushed". Prove that invariant, plus a
    // positive control that a flush WOULD have surfaced the secret.
    const SECRET: &str = "sk-PLANTED-LEAK-AC2B-111";

    // Case 1: EOF / error terminal path — buffer dropped without flush.
    {
        let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
        let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());
        event_tx
            .send(text_delta(&format!("leaked {SECRET}")))
            .await
            .unwrap();
        drop(event_tx); // stream ended (EOF / error / cancel) with no classification
        let withheld = sink.finish().await; // finish returns — no deadlock

        assert_eq!(
            withheld.withheld_count(),
            1,
            "the secret delta was buffered"
        );
        drop(withheld); // Discarded: never flushed
        assert!(
            !any_delta_contains(&drain(&mut real_rx), SECRET),
            "a discarded terminal path must not release withheld plaintext"
        );
    }

    // Case 2: client disconnect — the real receiver is gone. The sink must still
    // finish (no deadlock) and never surface plaintext.
    {
        let (real_tx, real_rx) = mpsc::channel::<TurnEvent>(64);
        let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());
        drop(real_rx); // client disconnected
        event_tx.send(inference_warning()).await.unwrap(); // non-delta send fails silently
        event_tx
            .send(text_delta(&format!("leaked {SECRET}")))
            .await
            .unwrap();
        drop(event_tx);
        let withheld = sink.finish().await; // must return despite the dead receiver
        assert_eq!(withheld.withheld_count(), 1);
        // Discard: nothing to flush to (and we must not).
    }

    // Positive control: the SAME buffered secret WOULD reach the client on a
    // Released flush — so Case 1's absence is real containment, not a dead path.
    {
        let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
        let (event_tx, sink) =
            BufferedDeliverySink::spawn(real_tx.clone(), CancellationToken::new());
        event_tx
            .send(text_delta(&format!("leaked {SECRET}")))
            .await
            .unwrap();
        drop(event_tx);
        let withheld = sink.finish().await;
        withheld.flush_to(&real_tx).await;
        assert!(
            any_delta_contains(&drain(&mut real_rx), SECRET),
            "positive control: a Released flush surfaces the buffered delta"
        );
    }
}

// ---------------------------------------------------------------------------
// AC2c — exceeding SENSITIVE_TURN_BUFFER_CAP is Discarded (drop buffer,
// content-free status), with the same no-plaintext proof as 2b.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffered_delivery_overflow_is_discarded() {
    const MARKER: &str = "sk-PLANTED-LEAK-AC2C-222";

    let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx.clone(), CancellationToken::new());

    // A small marker delta, then a delta that blows the 1 MiB withhold budget.
    event_tx
        .send(text_delta(&format!("marker {MARKER}")))
        .await
        .unwrap();
    event_tx
        .send(text_delta(&"x".repeat(SENSITIVE_TURN_BUFFER_CAP + 1)))
        .await
        .unwrap();

    drop(event_tx);
    let withheld = sink.finish().await;

    assert!(
        withheld.overflowed(),
        "exceeding the withhold budget must mark the turn overflowed"
    );
    assert_eq!(
        withheld.withheld_count(),
        0,
        "overflow drops the whole buffer, including any earlier marker delta"
    );

    // Nothing streamed live, and a flush attempt is a no-op on an overflowed
    // buffer — the marker never reaches the client on any channel.
    assert!(!any_delta_contains(&drain(&mut real_rx), MARKER));
    withheld.flush_to(&real_tx).await;
    assert!(
        !any_delta_contains(&drain(&mut real_rx), MARKER),
        "an overflowed buffer must never flush withheld plaintext"
    );
}

// ---------------------------------------------------------------------------
// Liveness — a stalled, RETAINED receiver with a full channel must never wedge
// finish(); nor may a cancelled turn. A blocking `send().await` in the forwarder
// would hang finish() here forever (the reason the forwarder uses `try_send`).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finish_does_not_wedge_on_stalled_full_receiver() {
    // A tiny real channel whose receiver is RETAINED but never drained.
    let (real_tx, real_rx) = mpsc::channel::<TurnEvent>(1);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());

    // More live status events than the channel can hold: a blocking forwarder
    // would wedge on the second `send`. A secret-bearing delta is also withheld.
    for _ in 0..8 {
        event_tx.send(inference_warning()).await.unwrap();
    }
    event_tx
        .send(text_delta("sk-PLANTED-LEAK-LIVENESS-333"))
        .await
        .unwrap();
    drop(event_tx);

    // finish() must return promptly despite the stalled, retained receiver.
    let withheld = tokio::time::timeout(Duration::from_secs(5), sink.finish())
        .await
        .expect("finish must not wedge on a stalled full receiver");
    assert_eq!(withheld.withheld_count(), 1, "the delta was still withheld");
    drop(real_rx);
}

#[tokio::test]
async fn finish_returns_after_cancel() {
    let (real_tx, real_rx) = mpsc::channel::<TurnEvent>(1);
    let cancel = CancellationToken::new();
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, cancel.clone());

    for _ in 0..4 {
        event_tx.send(inference_warning()).await.unwrap();
    }
    // A cancelled turn: the forwarder must stop and finish() must return.
    cancel.cancel();

    let _ = tokio::time::timeout(Duration::from_secs(5), sink.finish())
        .await
        .expect("finish must return after the turn is cancelled");
    drop(event_tx);
    drop(real_rx);
}

// ---------------------------------------------------------------------------
// HIGH #1 — retry boundary. The sink aggregates the WHOLE retry sequence; a
// failed attempt's withheld deltas must be DISCARDED at the retry boundary
// (the in-band `Reconnecting` the model layer sends before re-streaming) so a
// later Released classification of the SUCCESSFUL attempt can never flush a
// prior attempt's plaintext.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconnect_boundary_discards_prior_attempt_deltas() {
    const ATTEMPT1_SECRET: &str = "sk-ATTEMPT1-PLANTED-LEAK-r1";
    const ATTEMPT2_CLEAN: &str = "clean-attempt2-prose-r2";

    let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx.clone(), CancellationToken::new());

    // Attempt 1 streams a secret-bearing delta, then transport-fails: the retry
    // loop sends `Reconnecting` on the same channel, in order, before re-stream.
    event_tx
        .send(text_delta(&format!("leaked {ATTEMPT1_SECRET}")))
        .await
        .unwrap();
    event_tx.send(reconnecting()).await.unwrap();
    // Attempt 2 succeeds clean (no report_leak) -> the turn classifies Released.
    event_tx.send(text_delta(ATTEMPT2_CLEAN)).await.unwrap();
    drop(event_tx);

    let withheld = sink.finish().await;
    // Only attempt 2's delta survives; attempt 1's was discarded at the boundary.
    assert_eq!(
        withheld.withheld_count(),
        1,
        "the failed attempt's withheld delta must be discarded at the retry boundary"
    );

    // A Released flush must carry ONLY attempt 2's clean prose, never attempt 1's
    // secret. (Against the pre-fix sink, which aggregated across attempts, the
    // flush would still hold ATTEMPT1_SECRET here.)
    withheld.flush_to(&real_tx).await;
    let seen = drain(&mut real_rx);
    let blob = format!("{seen:?}");
    assert!(
        !blob.contains(ATTEMPT1_SECRET),
        "a discarded attempt's plaintext must never flush: {blob}"
    );
    assert!(
        any_delta_contains(&seen, ATTEMPT2_CLEAN),
        "the successful attempt's prose must flush"
    );
    // The retry status event itself was forwarded live (before the flush).
    assert!(
        seen.iter()
            .any(|e| matches!(e, TurnEvent::Reconnecting { .. })),
        "Reconnecting must still forward live as a status event"
    );
}

// ---------------------------------------------------------------------------
// HIGH #2 — a turn cancelled while the forwarder was draining must be marked so
// the flush decision DROPS the buffer (never releases a cancelled buffer), even
// when the provider resolved Ok and the final choice is non-sensitive.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelled_turn_marks_buffer_and_is_not_flushable() {
    const SECRET: &str = "sk-CANCELLED-PLANTED-LEAK-c1";
    let cancel = CancellationToken::new();
    let (real_tx, mut real_rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx.clone(), cancel.clone());

    event_tx
        .send(text_delta(&format!("withheld {SECRET}")))
        .await
        .unwrap();
    // Cancellation fires before the forwarder joins; keep `event_tx` alive so the
    // forwarder's only exit is the cancellation arm (deterministic flag set).
    cancel.cancel();
    let withheld = sink.finish().await;
    drop(event_tx);

    assert!(
        withheld.cancelled(),
        "a turn cancelled mid-drain must mark the buffer cancelled"
    );
    // The flush decision drops it — via the carried flag AND the live read.
    assert!(!withheld_should_flush(
        false,
        &withheld,
        cancel.is_cancelled()
    ));
    assert!(!withheld_should_flush(false, &withheld, false));

    // Even a direct flush_to is a no-op on a cancelled buffer (defense in depth).
    withheld.flush_to(&real_tx).await;
    assert!(
        !any_delta_contains(&drain(&mut real_rx), SECRET),
        "a cancelled turn must never flush withheld plaintext"
    );
}

#[tokio::test]
async fn withheld_should_flush_only_on_clean_released() {
    // Build each terminal state through the real sink, then drive the actual
    // flush-decision predicate `run_turn` uses.
    async fn clean() -> WithheldDeltas {
        let (real_tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());
        event_tx.send(text_delta("prose")).await.unwrap();
        drop(event_tx);
        sink.finish().await
    }

    let released = clean().await;
    assert!(!released.overflowed() && !released.cancelled());
    // The ONLY flush case: non-sensitive, not overflowed, not cancelled.
    assert!(withheld_should_flush(false, &released, false));
    // Every fail-closed axis drops.
    assert!(
        !withheld_should_flush(true, &released, false),
        "sensitive turn drops"
    );
    assert!(
        !withheld_should_flush(false, &released, true),
        "live-cancelled drops"
    );

    // Overflowed buffer.
    let (real_tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, CancellationToken::new());
    event_tx
        .send(text_delta(&"x".repeat(SENSITIVE_TURN_BUFFER_CAP + 1)))
        .await
        .unwrap();
    drop(event_tx);
    let overflowed = sink.finish().await;
    assert!(overflowed.overflowed());
    assert!(
        !withheld_should_flush(false, &overflowed, false),
        "overflow drops"
    );

    // Cancelled buffer.
    let cancel = CancellationToken::new();
    let (real_tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let (event_tx, sink) = BufferedDeliverySink::spawn(real_tx, cancel.clone());
    event_tx.send(text_delta("prose")).await.unwrap();
    cancel.cancel();
    let cancelled = sink.finish().await;
    drop(event_tx);
    assert!(cancelled.cancelled());
    assert!(
        !withheld_should_flush(false, &cancelled, false),
        "cancelled-flag drops"
    );
}
