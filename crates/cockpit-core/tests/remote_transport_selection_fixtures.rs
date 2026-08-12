//! Cross-language transport-selection behavior fixtures (core side).
//!
//! Rust is the source of truth. This target owns the two *behavioral* fixtures:
//!
//! - `plan-matrix.json` — every authorized-plan vector, produced by calling the
//!   production [`compute_authorized_plan`].
//! - `traces.json` — golden transition/route traces, produced by driving the
//!   production [`reduce`] via [`record_golden_trace`].
//!
//! The wire *vocabulary* and *constants* live in the sibling `cockpit-proto`
//! target (`crates/cockpit-proto/tests/remote_transport_selection.rs`) so the
//! proto crate stays logic-free (crate graph: proto must not depend on core).
//!
//! The TypeScript mirror in
//! `packages/cockpit-protocol/src/remote-transport-selection.test.ts` consumes
//! the very same files, so neither side can drift without the other failing.
//!
//! Regenerate from the repository root with:
//!
//! ```sh
//! COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-core --test remote_transport_selection_fixtures
//! ```

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use cockpit_core::daemon::transport_selection::{
    AuthorizedPlan, ChildAttemptId, ParticipantPrivacy, TransportAuthorization,
    TransportSelectionInput, TransportSelectionState, compute_authorized_plan, record_golden_trace,
};
use cockpit_proto::remote_ip_consent::ConsentCapability;
use cockpit_proto::remote_transport_selection::{
    INITIAL_DEADLINE_SECS, RoutingClass, TRAIN_ID_BYTES, TransportKind, UserTransportPreference,
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
    // The canonical bytes are produced entirely in-crate by `render_json`
    // (stable key ordering via `serde_json::Map`, fixed two-space indent, single
    // trailing newline). There is NO external formatter: regeneration and the
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
            "read {}: {error} — regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-core --test remote_transport_selection_fixtures",
            path.display()
        )
    });
    assert_eq!(
        existing.as_slice(),
        rendered.as_bytes(),
        "{} drifted (byte comparison); regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-core --test remote_transport_selection_fixtures",
        path.display()
    );
}

// --- Plan matrix -----------------------------------------------------------

fn base_auth() -> TransportAuthorization {
    TransportAuthorization {
        webrtc_authorized: true,
        websocket_authorized: true,
        ip_consent: ConsentCapability::DirectAllowed,
        participant_privacy: ParticipantPrivacy::DirectAllowed,
        turn_available: true,
        quota_available: true,
        client_supports_webrtc: true,
        client_supports_websocket: true,
    }
}

fn consent_name(c: ConsentCapability) -> &'static str {
    c.name()
}

fn privacy_name(p: ParticipantPrivacy) -> String {
    serde_json::to_value(p)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn preference_name(p: UserTransportPreference) -> String {
    serde_json::to_value(p)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn input_value(auth: &TransportAuthorization, preference: UserTransportPreference) -> Value {
    json!({
        "webrtc_authorized": auth.webrtc_authorized,
        "websocket_authorized": auth.websocket_authorized,
        "client_supports_webrtc": auth.client_supports_webrtc,
        "client_supports_websocket": auth.client_supports_websocket,
        "ip_consent": consent_name(auth.ip_consent),
        "participant_privacy": privacy_name(auth.participant_privacy),
        "turn_available": auth.turn_available,
        "quota_available": auth.quota_available,
        "user_preference": preference_name(preference),
    })
}

fn plan_value(plan: &AuthorizedPlan) -> Value {
    json!({
        "allowed_kinds": plan
            .allowed_kinds
            .iter()
            .map(|k| json!(k.as_str()))
            .collect::<Vec<_>>(),
        "denials": plan
            .denials
            .iter()
            .map(|d| serde_json::to_value(d).unwrap())
            .collect::<Vec<_>>(),
        "preference": serde_json::to_value(plan.preference).unwrap(),
        "turn_required": plan.turn_required,
    })
}

fn plan_row(
    name: String,
    auth: TransportAuthorization,
    preference: UserTransportPreference,
) -> Value {
    let plan = compute_authorized_plan(&auth, preference);
    json!({
        "name": name,
        "input": input_value(&auth, preference),
        "expected": plan_value(&plan),
    })
}

fn plan_matrix_fixture() -> Value {
    let mut rows: Vec<Value> = Vec::new();

    // Full consent × TURN × privacy grid under auto preference.
    for consent in [
        ConsentCapability::DirectAllowed,
        ConsentCapability::RelayOnly,
        ConsentCapability::Unavailable,
    ] {
        for turn in [true, false] {
            for privacy in [
                ParticipantPrivacy::DirectAllowed,
                ParticipantPrivacy::TurnRequired,
                ParticipantPrivacy::RelayOnly,
            ] {
                let mut auth = base_auth();
                auth.ip_consent = consent;
                auth.turn_available = turn;
                auth.participant_privacy = privacy;
                let name = format!(
                    "consent_{}__turn_{}__privacy_{}",
                    consent_name(consent),
                    turn,
                    privacy_name(privacy)
                );
                rows.push(plan_row(name, auth, UserTransportPreference::Auto));
            }
        }
    }

    // Unavailable consent takes precedence over per-kind authorization gaps:
    // `ip_consent_denied` is emitted (and both kinds withheld) even when the
    // kinds are ALSO unauthorized. Guards against the per-kind sweep masking the
    // consent denial with `kind_not_authorized`.
    let mut auth = base_auth();
    auth.ip_consent = ConsentCapability::Unavailable;
    auth.webrtc_authorized = false;
    auth.websocket_authorized = false;
    rows.push(plan_row(
        "unavailable_consent_with_unauthorized_kinds".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));

    // Each preference under full authorization.
    for preference in [
        UserTransportPreference::Auto,
        UserTransportPreference::Webrtc,
        UserTransportPreference::Websocket,
    ] {
        rows.push(plan_row(
            format!("preference_{}", preference_name(preference)),
            base_auth(),
            preference,
        ));
    }

    // Quota exhaustion clears both kinds regardless of consent.
    let mut auth = base_auth();
    auth.quota_available = false;
    rows.push(plan_row(
        "quota_exhausted".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));

    // Client-capability gaps.
    let mut auth = base_auth();
    auth.client_supports_webrtc = false;
    rows.push(plan_row(
        "client_missing_webrtc".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));
    let mut auth = base_auth();
    auth.client_supports_websocket = false;
    rows.push(plan_row(
        "client_missing_websocket".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));

    // Authorization gaps.
    let mut auth = base_auth();
    auth.webrtc_authorized = false;
    rows.push(plan_row(
        "webrtc_unauthorized".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));
    let mut auth = base_auth();
    auth.websocket_authorized = false;
    rows.push(plan_row(
        "websocket_unauthorized".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));
    let mut auth = base_auth();
    auth.webrtc_authorized = false;
    auth.websocket_authorized = false;
    rows.push(plan_row(
        "neither_authorized".to_string(),
        auth,
        UserTransportPreference::Auto,
    ));

    // Preference-disallowed vectors.
    let mut auth = base_auth();
    auth.webrtc_authorized = false;
    rows.push(plan_row(
        "preference_webrtc_unauthorized".to_string(),
        auth,
        UserTransportPreference::Webrtc,
    ));
    let mut auth = base_auth();
    auth.websocket_authorized = false;
    rows.push(plan_row(
        "preference_websocket_unauthorized".to_string(),
        auth,
        UserTransportPreference::Websocket,
    ));

    json!({
        "_comment": "Generated by cockpit-core's remote_transport_selection_fixtures test. Do not hand edit.",
        "rows": rows,
    })
}

// --- Traces ----------------------------------------------------------------

fn train_id() -> cockpit_core::daemon::transport_selection::TrainId {
    cockpit_core::daemon::transport_selection::TrainId([0x42; TRAIN_ID_BYTES])
}

fn auto_state() -> TransportSelectionState {
    TransportSelectionState::new(
        base_auth(),
        UserTransportPreference::Auto,
        train_id(),
        INITIAL_DEADLINE_SECS,
    )
}

fn scenario(
    name: &str,
    state: TransportSelectionState,
    inputs: Vec<TransportSelectionInput>,
) -> Value {
    let trace = record_golden_trace(state, &inputs);
    json!({
        "name": name,
        "trace": serde_json::to_value(&trace).expect("trace serializes"),
    })
}

fn traces_fixture() -> Value {
    // 1. Auto-preference deadline fallback: WebRTC first, then WebSocket after
    // the server-signed deadline fires with no active WebRTC.
    let deadline_fallback = scenario(
        "auto_deadline_fallback",
        auto_state(),
        vec![
            TransportSelectionInput::StartPlan,
            TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        ],
    );

    // 2. Preference-forced denial: WebRTC-only preference with WebRTC
    // unauthorized returns a typed denial and never falls back.
    let mut forced_auth = base_auth();
    forced_auth.webrtc_authorized = false;
    let forced_denial = scenario(
        "preference_forced_denial",
        TransportSelectionState::new(
            forced_auth,
            UserTransportPreference::Webrtc,
            train_id(),
            INITIAL_DEADLINE_SECS,
        ),
        vec![TransportSelectionInput::StartPlan],
    );

    // 3. TURN credential-rotation replacement and cutover.
    let turn_cutover = scenario(
        "turn_replacement_cutover",
        auto_state(),
        vec![
            TransportSelectionInput::StartPlan,
            TransportSelectionInput::ChildActive {
                child_attempt: ChildAttemptId(1),
                now_ms: 1_000,
            },
            TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
            TransportSelectionInput::ChildActive {
                child_attempt: ChildAttemptId(2),
                now_ms: 10_001,
            },
            TransportSelectionInput::CredentialRotationLead { now_ms: 20_000 },
            // The replacement child is the next allocated attempt id. With
            // WebRTC active at the deadline no WebSocket child is created, so the
            // credential-rotation replacement is attempt 2 (not 3). Matching it
            // makes the supervisor cutover actually occur and record
            // `emit_cutover_lease`.
            TransportSelectionInput::SupervisorCutoverAck {
                old: ChildAttemptId(1),
                new: ChildAttemptId(2),
            },
            TransportSelectionInput::SecondLease {
                old: ChildAttemptId(1),
            },
        ],
    );

    // 4. Retry-budget exhaustion: initial establishment plus one same-kind
    // retry, then failure.
    let retry_exhaustion = scenario(
        "retry_budget_exhaustion",
        auto_state(),
        vec![
            TransportSelectionInput::StartPlan,
            TransportSelectionInput::ChildClosed {
                child_attempt: ChildAttemptId(1),
                security_failure: false,
            },
            TransportSelectionInput::RetryDelayFired { now_ms: 2_000 },
            TransportSelectionInput::ChildClosed {
                child_attempt: ChildAttemptId(2),
                security_failure: false,
            },
        ],
    );

    // 5. Multi-path routing across two active children.
    let multi_path = scenario(
        "multi_path_routing",
        auto_state(),
        vec![
            TransportSelectionInput::StartPlan,
            TransportSelectionInput::ChildActive {
                child_attempt: ChildAttemptId(1),
                now_ms: 1_000,
            },
            // A named continuity reason starts the second authorized kind
            // alongside the active WebRTC child.
            TransportSelectionInput::RequestSecondChild {
                reason:
                    cockpit_proto::remote_transport_selection::SecondChildReason::NetworkHandoff,
                now_ms: 2_000,
            },
            TransportSelectionInput::ChildActive {
                child_attempt: ChildAttemptId(2),
                now_ms: 3_000,
            },
            // Make both children healthy.
            TransportSelectionInput::WebrtcProbe {
                child_attempt: ChildAttemptId(1),
                success: true,
                buffered_bytes: 8 * 1024 * 1024,
            },
            TransportSelectionInput::WebrtcProbe {
                child_attempt: ChildAttemptId(1),
                success: true,
                buffered_bytes: 8 * 1024 * 1024,
            },
            TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ChildAttemptId(2),
                oldest_unacked_age_secs: 0,
                buffered_bytes: 0,
                retransmissions: 0,
            },
            TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ChildAttemptId(2),
                oldest_unacked_age_secs: 0,
                buffered_bytes: 0,
                retransmissions: 0,
            },
            TransportSelectionInput::RouteRequest {
                delivery_id: "d_interactive".to_string(),
                routing_class: RoutingClass::Interactive,
            },
            TransportSelectionInput::RouteRequest {
                delivery_id: "d_bulk".to_string(),
                routing_class: RoutingClass::Bulk,
            },
        ],
    );

    json!({
        "_comment": "Generated by cockpit-core's remote_transport_selection_fixtures test. Do not hand edit.",
        "scenarios": [
            deadline_fallback,
            forced_denial,
            turn_cutover,
            retry_exhaustion,
            multi_path,
        ],
    })
}

// --- tests -----------------------------------------------------------------

#[test]
fn remote_transport_selection_plan_matrix_fixture() {
    let fixture = plan_matrix_fixture();
    let rows = fixture["rows"].as_array().expect("rows");
    assert!(!rows.is_empty());

    // DirectAllowed vs RelayOnly consent are observably different plans.
    let direct = compute_authorized_plan(&base_auth(), UserTransportPreference::Auto);
    let mut relay_auth = base_auth();
    relay_auth.ip_consent = ConsentCapability::RelayOnly;
    let relay = compute_authorized_plan(&relay_auth, UserTransportPreference::Auto);
    assert_ne!(direct, relay);
    assert!(!direct.turn_required);
    assert!(relay.turn_required);

    // turn_required privacy vs direct_allowed privacy differ.
    let mut turn_priv = base_auth();
    turn_priv.participant_privacy = ParticipantPrivacy::TurnRequired;
    let turn_plan = compute_authorized_plan(&turn_priv, UserTransportPreference::Auto);
    assert_ne!(turn_plan, direct);

    // turn_required privacy × !turn_available denies WebRTC only.
    let mut no_turn = base_auth();
    no_turn.participant_privacy = ParticipantPrivacy::TurnRequired;
    no_turn.turn_available = false;
    let no_turn_plan = compute_authorized_plan(&no_turn, UserTransportPreference::Auto);
    assert!(!no_turn_plan.allowed_kinds.contains(&TransportKind::Webrtc));
    assert!(
        no_turn_plan
            .allowed_kinds
            .contains(&TransportKind::Websocket)
    );

    // Unavailable consent denies both kinds.
    let mut unavailable = base_auth();
    unavailable.ip_consent = ConsentCapability::Unavailable;
    let unavailable_plan = compute_authorized_plan(&unavailable, UserTransportPreference::Auto);
    assert!(unavailable_plan.allowed_kinds.is_empty());

    sync_fixture("plan-matrix.json", &fixture);
}

#[test]
fn remote_transport_selection_trace_fixture() {
    let fixture = traces_fixture();
    let scenarios = fixture["scenarios"].as_array().expect("scenarios");
    assert_eq!(scenarios.len(), 5);
    for scenario in scenarios {
        let trace = scenario["trace"].as_array().expect("trace");
        assert!(
            !trace.is_empty(),
            "{} trace must be nonempty",
            scenario["name"]
        );
        // No Debug spelling leaks into the wire form: enum variants are
        // snake_case, so the CamelCase Debug names must be absent.
        let text = serde_json::to_string(scenario).unwrap();
        assert!(!text.contains("Webrtc"));
        assert!(!text.contains("Establishing"));
        assert!(!text.contains("StartChild"));
    }
    sync_fixture("traces.json", &fixture);
}
