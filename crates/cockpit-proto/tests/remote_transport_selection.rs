//! Cross-language transport-selection *vocabulary and constants* fixtures.
//!
//! Rust is the source of truth. This target owns only the wire surface that the
//! crate graph permits the proto crate to know about — the serde enum strings
//! and the fixed policy constants — and writes them to
//! `packages/cockpit-protocol/fixtures/remote-transport-selection/`. It never
//! calls `compute_authorized_plan` or `reduce`; those behavioral fixtures
//! (`plan-matrix.json` / `traces.json`) are owned by the `cockpit-core` target
//! `crates/cockpit-core/tests/remote_transport_selection_fixtures.rs`.
//!
//! Every enum string here is produced by *serializing the real serde types*,
//! never hand-typed, and every constant is emitted from the real `pub const`.
//! The TypeScript mirror in
//! `packages/cockpit-protocol/src/remote-transport-selection.test.ts` asserts
//! the same committed files against its exported unions and constants.
//!
//! Regenerate from the repository root with:
//!
//! ```sh
//! COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto --test remote_transport_selection
//! ```

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

use cockpit_proto::remote_ip_consent::ConsentCapability;
use cockpit_proto::remote_transport_selection::{
    ChildState, DRAINING_TIMEOUT_SECS, DurableLifecycle, HealthTier,
    ICE_DISCONNECTED_FALLBACK_MISSES, INITIAL_DEADLINE_SECS, LIVENESS_PROBE_INTERVAL_SECS,
    MAX_COMMITTED_RESERVATIONS_ROLLING, MAX_DEADLINE_SECS, MAX_ORDINARY_PENDING_CHILDREN,
    MAX_PENDING_PER_KIND, MAX_PHYSICAL_CHILDREN_TURN_EXCEPTION, MAX_RESERVATIONS_PER_TRAIN,
    MAX_ROUTED_CURRENT_CHILDREN, MAX_SAME_KIND_RETRIES, MIN_DEADLINE_SECS, ParentState,
    RECOVERY_CONSECUTIVE_HEALTHY, RETRY_DELAY_SECS, ROLLING_WINDOW_SECS, ReachabilityClass,
    ReservationOutcome, RoutingClass, SecondChildReason, TRAIN_ID_BYTES, TransportDenial,
    TransportKind, UserTransportPreference, WEBRTC_DEGRADED_BUFFER_BYTES, WEBRTC_DEGRADED_MISSES,
    WEBRTC_FAILED_MISSES, WEBRTC_HEALTHY_CONSECUTIVE_SUCCESSES, WEBSOCKET_DEGRADED_BUFFER_BYTES,
    WEBSOCKET_DEGRADED_UNACKED_AGE_SECS, WEBSOCKET_FAILED_RETRANSMISSIONS,
};

const FIXTURE_DIR: &str = "../../packages/cockpit-protocol/fixtures/remote-transport-selection";
const UPDATE_ENV: &str = "COCKPIT_UPDATE_GOLDEN";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR)
}

fn update_fixtures() -> bool {
    std::env::var(UPDATE_ENV).is_ok()
}

// --- Biome-compatible JSON rendering (mirrors remote_transport_fixtures.rs) ---

const LINE_WIDTH: usize = 100;

fn render_json(value: &Value) -> String {
    let mut out = String::new();
    render_value(value, 0, &mut out);
    out.push('\n');
    out
}

fn render_value(value: &Value, indent: usize, out: &mut String) {
    match value {
        Value::Object(map) => render_object(map, indent, out),
        Value::Array(items) => render_array(items, indent, out),
        other => out.push_str(&scalar(other)),
    }
}

fn scalar(value: &Value) -> String {
    serde_json::to_string(value).expect("scalar serializes")
}

fn render_object(map: &Map<String, Value>, indent: usize, out: &mut String) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    let inner = indent + 2;
    for (i, (key, value)) in map.iter().enumerate() {
        out.push_str(&" ".repeat(inner));
        out.push_str(&scalar(&Value::String(key.clone())));
        out.push_str(": ");
        render_value(value, inner, out);
        if i + 1 < map.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push('}');
}

fn render_array(items: &[Value], indent: usize, out: &mut String) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    let composite = items
        .iter()
        .any(|item| matches!(item, Value::Object(_) | Value::Array(_)));
    if !composite {
        let single = format!(
            "[{}]",
            items.iter().map(scalar).collect::<Vec<_>>().join(", ")
        );
        if indent + single.len() <= LINE_WIDTH {
            out.push_str(&single);
            return;
        }
    }
    out.push_str("[\n");
    let inner = indent + 2;
    for (i, item) in items.iter().enumerate() {
        out.push_str(&" ".repeat(inner));
        render_value(item, inner, out);
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&" ".repeat(indent));
    out.push(']');
}

fn sync_fixture(name: &str, value: &Value) {
    let path = fixture_root().join(name);
    // Fully in-crate deterministic rendering (stable key ordering, fixed indent,
    // single trailing newline) with NO external formatter. Regeneration and the
    // check compare the SAME rendered bytes, so a second regen is byte-identical
    // and the cross-language contract is byte-for-byte, not semantic.
    let rendered = render_json(value);
    if update_fixtures() {
        std::fs::create_dir_all(fixture_root()).expect("create fixture dir");
        std::fs::write(&path, rendered.as_bytes())
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }
    // Read the committed file as raw BYTES (not `read_to_string`, which would
    // panic on non-UTF-8 input instead of surfacing the drift as an assertion),
    // and compare against the rendered bytes so a formatting-only mutation is a
    // failed byte assertion rather than a decode panic.
    let existing = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error} — regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-proto --test remote_transport_selection",
            path.display()
        )
    });
    assert_eq!(
        existing.as_slice(),
        rendered.as_bytes(),
        "{} drifted (byte comparison); regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-proto --test remote_transport_selection",
        path.display()
    );
}

/// Serialize each real serde variant to its wire string. The strings come from
/// serde `rename_all = "snake_case"`, never from hand-typed literals.
fn wire_strings<T: Serialize>(values: &[T]) -> Vec<Value> {
    values
        .iter()
        .map(|v| serde_json::to_value(v).expect("enum serializes to string"))
        .collect()
}

fn vocabulary_fixture() -> Value {
    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_selection test. Do not hand edit.",
        "transportKinds": wire_strings(&[TransportKind::Webrtc, TransportKind::Websocket]),
        "userPreferences": wire_strings(&[
            UserTransportPreference::Auto,
            UserTransportPreference::Webrtc,
            UserTransportPreference::Websocket,
        ]),
        "parentStates": wire_strings(&[
            ParentState::Planning,
            ParentState::Establishing,
            ParentState::Active,
            ParentState::Degraded,
            ParentState::Denied,
            ParentState::Failed,
            ParentState::Cancelled,
            ParentState::Superseded,
        ]),
        "childStates": wire_strings(&[
            ChildState::Pending,
            ChildState::Authenticating,
            ChildState::Active,
            ChildState::Degraded,
            ChildState::Closing,
            ChildState::Closed,
        ]),
        "durableLifecycle": wire_strings(&[
            DurableLifecycle::Current,
            DurableLifecycle::ReplacementPending,
            DurableLifecycle::Draining,
        ]),
        "reachabilityClasses": wire_strings(&[
            ReachabilityClass::IceNoCandidatePair,
            ReachabilityClass::IceTimeout,
            ReachabilityClass::NetworkUnreachable,
            ReachabilityClass::TurnUnreachable,
            ReachabilityClass::IceDisconnected,
        ]),
        "healthTiers": wire_strings(&[
            HealthTier::Healthy,
            HealthTier::Degraded,
            HealthTier::Failed,
        ]),
        "routingClasses": wire_strings(&[
            RoutingClass::Control,
            RoutingClass::Interactive,
            RoutingClass::Bulk,
        ]),
        "secondChildReasons": wire_strings(&[
            SecondChildReason::PreferredPathRecovery,
            SecondChildReason::NetworkHandoff,
            SecondChildReason::OperatorForce,
            SecondChildReason::DegradedPathReplacement,
            SecondChildReason::CredentialRotation,
        ]),
        "transportDenials": wire_strings(&[
            TransportDenial::KindNotAuthorized,
            TransportDenial::KindNotAvailable,
            TransportDenial::IpConsentDenied,
            TransportDenial::QuotaExhausted,
            TransportDenial::ClientCapabilityMissing,
            TransportDenial::PreferenceDisallowed,
            TransportDenial::PolicyDenied,
            TransportDenial::RelayRequiredTurnUnavailable,
            TransportDenial::RetryBudgetExhausted,
            TransportDenial::DatabaseOutage,
            TransportDenial::SecurityFailure,
            TransportDenial::ChildCapExceeded,
        ]),
        "reservationOutcomes": wire_strings(&[
            ReservationOutcome::Active,
            ReservationOutcome::Cancelled,
            ReservationOutcome::Failed,
            ReservationOutcome::ReservationFailed,
        ]),
        // ConsentCapability is not a serde type; its wire names come from the
        // canonical `name()` over `ConsentCapability::ALL`.
        "consentCapabilities": ConsentCapability::ALL
            .iter()
            .map(|c| json!(c.name()))
            .collect::<Vec<_>>(),
    })
}

fn constants_fixture() -> Value {
    json!({
        "_comment": "Generated by cockpit-proto's remote_transport_selection test. Do not hand edit.",
        "initialDeadlineSecs": INITIAL_DEADLINE_SECS,
        "minDeadlineSecs": MIN_DEADLINE_SECS,
        "maxDeadlineSecs": MAX_DEADLINE_SECS,
        "livenessProbeIntervalSecs": LIVENESS_PROBE_INTERVAL_SECS,
        "iceDisconnectedFallbackMisses": ICE_DISCONNECTED_FALLBACK_MISSES,
        "webrtcHealthyConsecutiveSuccesses": WEBRTC_HEALTHY_CONSECUTIVE_SUCCESSES,
        "webrtcDegradedMisses": WEBRTC_DEGRADED_MISSES,
        "webrtcDegradedBufferBytes": WEBRTC_DEGRADED_BUFFER_BYTES,
        "webrtcFailedMisses": WEBRTC_FAILED_MISSES,
        "websocketDegradedUnackedAgeSecs": WEBSOCKET_DEGRADED_UNACKED_AGE_SECS,
        "websocketDegradedBufferBytes": WEBSOCKET_DEGRADED_BUFFER_BYTES,
        "websocketFailedRetransmissions": WEBSOCKET_FAILED_RETRANSMISSIONS,
        "recoveryConsecutiveHealthy": RECOVERY_CONSECUTIVE_HEALTHY,
        "drainingTimeoutSecs": DRAINING_TIMEOUT_SECS,
        "maxRoutedCurrentChildren": MAX_ROUTED_CURRENT_CHILDREN,
        "maxOrdinaryPendingChildren": MAX_ORDINARY_PENDING_CHILDREN,
        "maxPendingPerKind": MAX_PENDING_PER_KIND,
        "maxPhysicalChildrenTurnException": MAX_PHYSICAL_CHILDREN_TURN_EXCEPTION,
        "maxReservationsPerTrain": MAX_RESERVATIONS_PER_TRAIN,
        "maxCommittedReservationsRolling": MAX_COMMITTED_RESERVATIONS_ROLLING,
        "rollingWindowSecs": ROLLING_WINDOW_SECS,
        "retryDelaySecs": RETRY_DELAY_SECS,
        "maxSameKindRetries": MAX_SAME_KIND_RETRIES,
        "trainIdBytes": TRAIN_ID_BYTES,
    })
}

// --- tests -----------------------------------------------------------------

#[test]
fn remote_transport_selection_vocabulary_fixture() {
    let fixture = vocabulary_fixture();

    // The new denial variant is present, and no retired parallel-taxonomy
    // string leaks in.
    let denials = fixture["transportDenials"].as_array().unwrap();
    assert!(denials.contains(&json!("relay_required_turn_unavailable")));
    assert!(denials.contains(&json!("ip_consent_denied")));
    for retired in [
        "consent_unavailable",
        "preference_unavailable",
        "no_authorized_transport",
        "privacy_relay_only_no_turn",
    ] {
        assert!(
            !denials.contains(&json!(retired)),
            "retired denial {retired}"
        );
    }
    assert_eq!(
        fixture["consentCapabilities"],
        json!(["direct_allowed", "relay_only", "unavailable"])
    );

    sync_fixture("vocabulary.json", &fixture);
}

#[test]
fn remote_transport_selection_constants_fixture() {
    let fixture = constants_fixture();
    // Independent literals (not re-derived from the same const) guard the wire.
    assert_eq!(fixture["initialDeadlineSecs"], json!(10));
    assert_eq!(fixture["minDeadlineSecs"], json!(3));
    assert_eq!(fixture["maxDeadlineSecs"], json!(30));
    assert_eq!(fixture["trainIdBytes"], json!(16));
    assert_eq!(fixture["rollingWindowSecs"], json!(3600));
    sync_fixture("constants.json", &fixture);
}
