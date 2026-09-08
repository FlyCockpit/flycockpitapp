//! Per-turn buffered stream-delivery sink for the provider sensitive-turn
//! barrier (leak-report increment 2, AC1/2/2b/2c).
//!
//! ## Why
//!
//! Increment 1 wired the sensitive-turn barrier
//! ([`crate::engine::agent::sensitive_turn`]) into `run_turn`, but it classifies
//! a turn only AFTER the completion returns — by which point the provider's
//! `AssistantTextDelta` / `ReasoningDelta` chunks have already streamed live to
//! the client (see `drain_items` in `crate::engine::model::dispatch`, which sends
//! them onto the per-turn `event_tx` as they arrive). A secret the untrusted
//! model echoed in its prose would therefore reach the live client stream BEFORE
//! containment could run.
//!
//! ## What this sink does
//!
//! On a route where `report_leak` is advertised/decodable (a **supported,
//! untrusted, tool-capable** provider/mode route — the single eligibility funnel
//! [`crate::leak_report::route_advertises_report_leak`]), `run_turn` hands the
//! completion stream a wrapped `event_tx` produced by [`BufferedDeliverySink`]
//! instead of the real turn channel. The sink:
//!
//! * **Withholds** every `AssistantTextDelta` / `ReasoningDelta` — buffering it
//!   in stream order rather than forwarding it — until the turn is classified.
//! * **Forwards** every other event (e.g. `InferenceWarning`) to the real
//!   channel immediately, preserving its ordering. Those carry no
//!   pre-classification assistant plaintext.
//! * Is **bounded**: at most [`SENSITIVE_TURN_BUFFER_CAP`] withheld UTF-8 bytes.
//!   Exceeding it drops the whole buffer and marks the turn overflowed — the
//!   turn then fails closed to `Discarded` (no plaintext, content-free status).
//!
//! After the completion returns and `run_turn` classifies the turn, the caller:
//!
//! * flushes the buffer in order via [`WithheldDeltas::flush_to`] **iff** the
//!   turn positively classified non-sensitive (`Released`) AND did not overflow;
//! * otherwise **drops** the buffer (every `Contained` / `Discarded` / overflow
//!   / provider-error / cancellation / EOF path) so no withheld plaintext ever
//!   reaches the client stream, durable history, logs, diagnostics, or exports.
//!
//! ## Fail-closed
//!
//! The buffer is flushed on EXACTLY ONE outcome: a positively-classified,
//! non-overflowed `Released` turn. Every other terminal path — cancellation,
//! client disconnect, a dropped/lost completion future, a provider/inference
//! error, a malformed / rate-limited `report_leak`, EOF without classification,
//! a mixed-call discard, or buffer overflow — drops the withheld buffer without
//! flushing it. A lost forwarder task ([`BufferedDeliverySink::finish`] join
//! error) is also treated as overflow, so the turn fails closed.
//!
//! ## No deadlock
//!
//! The forwarder drains the intermediate channel eagerly. Its only `.await` on a
//! full channel is `real_tx.send(...)` for a non-delta event — the SAME
//! backpressure the completion already applied when it sent directly onto the
//! real channel, so the sink introduces no new stall. When the completion
//! returns and `run_turn` drops the wrapped `event_tx`, the intermediate channel
//! closes and the forwarder finishes on its own.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::TurnEvent;

/// Maximum withheld UTF-8 delta bytes buffered per turn before the turn fails
/// closed. 1 MiB — far beyond any legitimate single assistant turn; a turn whose
/// withheld `AssistantTextDelta` + `ReasoningDelta` payloads exceed it is
/// `Discarded` (drop buffer, content-free status), never `Released`.
pub(crate) const SENSITIVE_TURN_BUFFER_CAP: usize = 1024 * 1024;

/// Bounded capacity of the intermediate channel between the completion stream
/// and the forwarder. Small: the forwarder drains eagerly, so this only smooths
/// per-delta handoff. Backpressure here is the SAME backpressure the real event
/// channel already applied, so it adds no new deadlock.
const SINK_CHANNEL_CAP: usize = 64;

/// The withheld deltas collected by the forwarder for one turn.
///
/// Deliberately does not derive `Clone`: the withheld plaintext must not be
/// duplicated. The buffer is either flushed once ([`Self::flush_to`], consuming
/// it) on a `Released` turn, or dropped. Its `Debug` is redacting (see below) so
/// a stray `{:?}` cannot render the withheld deltas' plaintext.
#[derive(Default)]
pub(crate) struct WithheldDeltas {
    /// The withheld events, in stream order: the `AssistantTextDelta` /
    /// `ReasoningDelta` deltas plus any non-allowlisted event caught by the
    /// forwarder's fail-closed default arm. Cleared the instant `overflow` is
    /// set, so no plaintext survives an overflow even transiently.
    events: Vec<TurnEvent>,
    /// Total withheld byte count charged against [`SENSITIVE_TURN_BUFFER_CAP`]:
    /// delta payload UTF-8 bytes PLUS the serialized size of any non-allowlisted
    /// event withheld by the fail-closed default arm (so no event class can drive
    /// unbounded retention).
    bytes: usize,
    /// The withheld byte budget was exceeded (or the forwarder task was lost):
    /// the turn MUST fail closed to `Discarded` and the buffer MUST NOT flush.
    overflow: bool,
    /// The turn was cancelled while the forwarder was still draining (the
    /// cancellation `select!` arm fired). A cancelled turn is Discarded: the
    /// buffer MUST NOT flush. Carried out of the sink so the flush decision does
    /// not race a live `cancel.is_cancelled()` read.
    cancelled: bool,
}

impl std::fmt::Debug for WithheldDeltas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The withheld events carry raw pre-classification assistant plaintext;
        // never render it. Expose only content-free counters.
        f.debug_struct("WithheldDeltas")
            .field("withheld_events", &self.events.len())
            .field("withheld_bytes", &self.bytes)
            .field("overflow", &self.overflow)
            .field("cancelled", &self.cancelled)
            .finish()
    }
}

impl WithheldDeltas {
    /// Whether the turn must be discarded (never flush the buffer) because the
    /// withheld byte budget overflowed or the forwarder task was lost.
    pub(crate) fn overflowed(&self) -> bool {
        self.overflow
    }

    /// Whether the turn was cancelled while the forwarder was draining. A
    /// cancelled turn is Discarded — its buffer MUST NOT flush.
    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// The number of withheld delta events (for tests / diagnostics; never their
    /// content).
    #[cfg(test)]
    pub(crate) fn withheld_count(&self) -> usize {
        self.events.len()
    }

    /// Flush the withheld deltas, in original stream order, to the real turn
    /// channel. Called ONLY on a positively-classified non-sensitive
    /// (`Released`) turn that neither overflowed nor was cancelled. Consumes the
    /// buffer.
    pub(crate) async fn flush_to(self, real_tx: &mpsc::Sender<TurnEvent>) {
        // Defensive: an overflowed or cancelled buffer must never flush (the
        // overflow buffer is already empty; a cancelled one is fail-closed).
        if self.overflow || self.cancelled {
            return;
        }
        for event in self.events {
            let _ = real_tx.send(event).await;
        }
    }
}

/// The single flush decision `run_turn` uses after classification: the withheld
/// buffer is flushed to the live client stream ONLY on a clean Released turn.
///
/// Flush iff ALL hold:
/// * `!sensitive_turn_active` — a sensitive-ingress (`report_leak`) turn is
///   Contained/Discarded; its buffer is dropped, never flushed.
/// * `!withheld.overflowed()` — an overflowed turn is fail-closed Discarded.
/// * `!withheld.cancelled()` — a turn cancelled mid-drain is Discarded (flag
///   carried out of the forwarder's cancellation arm, race-free).
/// * `!cancel_fired` — a belt-and-suspenders live read for the ordering where
///   cancellation fired AFTER the forwarder finished via channel close (so the
///   `cancelled` flag was not set), yet the turn is still cancelled.
///
/// Any other outcome DROPS the buffer. Every fail-closed terminal path
/// (sensitive, overflow, cancellation, provider error handled upstream) resolves
/// to "do not flush".
pub(crate) fn withheld_should_flush(
    sensitive_turn_active: bool,
    withheld: &WithheldDeltas,
    cancel_fired: bool,
) -> bool {
    !sensitive_turn_active && !withheld.overflowed() && !withheld.cancelled() && !cancel_fired
}

/// A per-turn buffered delivery sink wrapping the real turn event channel.
///
/// See the module docs. The intermediate channel's only sender is the
/// `mpsc::Sender` returned by [`Self::spawn`]; the caller hands it to the
/// completion as `event_tx` and drops it once the completion returns, which lets
/// the forwarder finish and [`Self::finish`] yield the withheld buffer.
pub(crate) struct BufferedDeliverySink {
    forwarder: JoinHandle<WithheldDeltas>,
}

impl BufferedDeliverySink {
    /// Spawn the forwarder over a fresh intermediate channel. Returns
    /// `(event_tx, sink)`: hand `event_tx` to the completion in place of the
    /// real turn channel, then after the completion returns drop it and call
    /// [`Self::finish`].
    ///
    /// `cancel` is the turn's cancellation token: when it fires the forwarder
    /// stops immediately, so a cancelled turn cannot wedge [`Self::finish`].
    pub(crate) fn spawn(
        real_tx: mpsc::Sender<TurnEvent>,
        cancel: CancellationToken,
    ) -> (mpsc::Sender<TurnEvent>, Self) {
        let (inner_tx, inner_rx) = mpsc::channel(SINK_CHANNEL_CAP);
        let forwarder = tokio::spawn(forward(inner_rx, real_tx, cancel));
        (inner_tx, Self { forwarder })
    }

    /// Await the forwarder and return the withheld deltas. The caller MUST have
    /// already dropped the `event_tx` returned by [`Self::spawn`] so the
    /// intermediate channel is closed and the forwarder can finish; otherwise
    /// this awaits until it is. A lost forwarder task (panic/cancel) yields an
    /// overflow-marked buffer so the turn fails closed (never flushes).
    pub(crate) async fn finish(self) -> WithheldDeltas {
        match self.forwarder.await {
            Ok(withheld) => withheld,
            Err(_) => WithheldDeltas {
                events: Vec::new(),
                bytes: 0,
                overflow: true,
                cancelled: false,
            },
        }
    }
}

/// The forwarder loop: drain the intermediate channel, WITHHOLD text/reasoning
/// deltas (bounded), forward the allowlisted plaintext-free status events live,
/// and withhold anything else (fail-closed). Ends when the intermediate sender is
/// dropped (the completion returned and the caller dropped `event_tx`) or when
/// `cancel` fires.
///
/// Liveness: the loop's only `.await` points are `inner_rx.recv()` and
/// `cancel.cancelled()`. Live forwarding uses `try_send` (never `send().await`),
/// so a stalled or full downstream — even one whose receiver is still retained —
/// can NEVER block the forwarder and wedge [`BufferedDeliverySink::finish`].
async fn forward(
    mut inner_rx: mpsc::Receiver<TurnEvent>,
    real_tx: mpsc::Sender<TurnEvent>,
    cancel: CancellationToken,
) -> WithheldDeltas {
    let mut withheld = WithheldDeltas::default();
    loop {
        let event = tokio::select! {
            biased;
            // A cancelled turn is Discarded: mark the buffer so the caller's flush
            // decision drops it (race-free, not a live `cancel` re-read), stop
            // forwarding at once, and let whatever is buffered be dropped.
            _ = cancel.cancelled() => {
                withheld.cancelled = true;
                break;
            }
            maybe = inner_rx.recv() => match maybe {
                Some(event) => event,
                None => break,
            },
        };
        match &event {
            TurnEvent::AssistantTextDelta { delta, .. }
            | TurnEvent::ReasoningDelta { delta, .. } => {
                if withheld.overflow {
                    // Already overflowed: drop every further delta. No plaintext
                    // is forwarded or retained once the budget is blown.
                    continue;
                }
                let next = withheld.bytes.saturating_add(delta.len());
                if next > SENSITIVE_TURN_BUFFER_CAP {
                    // Fail closed: exceed the withhold budget -> drop the whole
                    // buffer now and mark overflow so the turn is Discarded.
                    withheld.overflow = true;
                    withheld.events.clear();
                    withheld.bytes = 0;
                    continue;
                }
                withheld.bytes = next;
                withheld.events.push(event);
            }
            // RETRY BOUNDARY. `with_retry` sends `Reconnecting` on the SAME
            // event channel, IN ORDER, right before it re-invokes a failed
            // attempt (see `crate::engine::retry::with_retry`). The model layer
            // discards the failed attempt's partial output, so its withheld
            // deltas MUST be discarded too — otherwise a later Released
            // classification of the SUCCESSFUL attempt's `choice` would flush a
            // prior (failed) attempt's plaintext to the client. Reset the whole
            // per-attempt buffer here, then forward the status event live.
            TurnEvent::Reconnecting { .. } => {
                withheld.events.clear();
                withheld.bytes = 0;
                withheld.overflow = false;
                let _ = real_tx.try_send(event);
            }
            // ALLOWLIST of the other plaintext-free live status event the
            // completion stream emits (`drain_items` sends `InferenceWarning`).
            // It carries no assistant plaintext, so stream it live — non-blocking
            // (`try_send`), dropping under transient backpressure rather than
            // wedging the turn.
            TurnEvent::InferenceWarning { .. } => {
                let _ = real_tx.try_send(event);
            }
            // Fail-closed default: any OTHER event is WITHHELD (buffered, surfaced
            // only on a Released flush, dropped on a contained/discarded turn)
            // rather than streamed live, so a future plaintext-bearing completion
            // event cannot silently reach the client before classification. A new
            // live-safe status event must be added to the allowlist above — this
            // arm makes that an explicit review decision, never a silent stream.
            // Charge its serialized size against the same cap so no event class
            // can drive unbounded retention (overflow -> fail-closed Discarded).
            _ => {
                if withheld.overflow {
                    continue;
                }
                // `TurnEvent` is not `Serialize`; its derived `Debug` length is a
                // conservative proxy for the retained size, enough to bound the
                // buffer against a future large-payload event (overflow ->
                // fail-closed Discarded, same as a delta overflow).
                let size = format!("{event:?}").len();
                let next = withheld.bytes.saturating_add(size);
                if next > SENSITIVE_TURN_BUFFER_CAP {
                    withheld.overflow = true;
                    withheld.events.clear();
                    withheld.bytes = 0;
                    continue;
                }
                withheld.bytes = next;
                withheld.events.push(event);
            }
        }
    }
    withheld
}

#[cfg(test)]
mod tests;
