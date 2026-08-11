//! Transport-selection state-machine conformance — Rust mirror of the TS matrices.
//!
//! Every test here mirrors an acceptance criterion in the
//! `remote-transport-selection-state-machine` prompt and the TypeScript suite
//! in `packages/cockpit-protocol/src/remote-transport-selection.test.ts`. The
//! pure plan computation, caps, retry budget, health, and routing are exercised
//! with deterministic inputs.

use cockpit_proto::remote_transport_selection::*;

fn full_input() -> RemoteTransportPlanInput {
    RemoteTransportPlanInput {
        deployment_webrtc: true,
        deployment_websocket: true,
        service_webrtc: true,
        service_websocket: true,
        tenant_webrtc: true,
        tenant_websocket: true,
        daemon_webrtc: true,
        daemon_websocket: true,
        ip_consent: RemoteIpConsentTriState::DirectAllowed,
        participant_privacy: RemoteParticipantPrivacy::DirectAllowed,
        live_quota: RemoteLiveQuota {
            remaining_reservations_this_hour: 12,
            remaining_bytes: 1024 * 1024 * 1024,
            remaining_allocation_seconds: 28800,
            exhausted: false,
        },
        client_capabilities: RemoteClientCapabilities {
            webrtc_supported: true,
            websocket_supported: true,
        },
        user_preference: RemoteUserPreference::Auto,
    }
}

#[test]
fn plan_authorizes_both_when_all_layers_permit() {
    let plan = compute_authorized_plan(&full_input());
    assert!(plan.webrtc_authorized);
    assert!(plan.websocket_authorized);
    assert!(plan.denial.is_none());
    assert!(!plan.turn_required);
}

#[test]
fn plan_denies_when_deployment_disables_both() {
    let mut input = full_input();
    input.deployment_webrtc = false;
    input.deployment_websocket = false;
    let plan = compute_authorized_plan(&input);
    assert!(matches!(
        plan.denial,
        Some(RemoteTransportPlanDenial::NoAuthorizedTransport { .. })
    ));
}

#[test]
fn plan_denies_on_quota_exhaustion() {
    let mut input = full_input();
    input.live_quota.exhausted = true;
    let plan = compute_authorized_plan(&input);
    assert!(matches!(
        plan.denial,
        Some(RemoteTransportPlanDenial::QuotaExhausted { .. })
    ));
}

#[test]
fn plan_denies_on_consent_unavailable() {
    let mut input = full_input();
    input.ip_consent = RemoteIpConsentTriState::Unavailable;
    let plan = compute_authorized_plan(&input);
    assert!(matches!(
        plan.denial,
        Some(RemoteTransportPlanDenial::ConsentUnavailable { .. })
    ));
}

#[test]
fn plan_marks_turn_required_for_turn_required_privacy() {
    let mut input = full_input();
    input.participant_privacy = RemoteParticipantPrivacy::TurnRequired;
    let plan = compute_authorized_plan(&input);
    assert!(plan.turn_required);
    assert!(plan.webrtc_authorized);
    assert!(plan.denial.is_none());
}

#[test]
fn plan_meet_cannot_widen() {
    let mut input = full_input();
    input.tenant_webrtc = false;
    let plan = compute_authorized_plan(&input);
    assert!(!plan.webrtc_authorized);
    assert!(plan.websocket_authorized);
}

#[test]
fn preference_webrtc_authorizes_webrtc_only() {
    let mut input = full_input();
    input.user_preference = RemoteUserPreference::WebRtc;
    let plan = compute_authorized_plan(&input);
    assert!(plan.webrtc_authorized);
    assert!(!plan.websocket_authorized);
}

#[test]
fn preference_websocket_authorizes_websocket_only() {
    let mut input = full_input();
    input.user_preference = RemoteUserPreference::WebSocket;
    let plan = compute_authorized_plan(&input);
    assert!(!plan.webrtc_authorized);
    assert!(plan.websocket_authorized);
}

#[test]
fn preference_webrtc_unavailable_returns_typed_denial() {
    let mut input = full_input();
    input.user_preference = RemoteUserPreference::WebRtc;
    input.deployment_webrtc = false;
    let plan = compute_authorized_plan(&input);
    assert!(!plan.webrtc_authorized);
    assert!(matches!(
        plan.denial,
        Some(RemoteTransportPlanDenial::PreferenceUnavailable {
            preference: RemoteUserPreference::WebRtc,
            ..
        })
    ));
}

#[test]
fn preference_auto_neither_available_returns_no_authorized_transport() {
    let mut input = full_input();
    input.user_preference = RemoteUserPreference::Auto;
    input.deployment_webrtc = false;
    input.deployment_websocket = false;
    let plan = compute_authorized_plan(&input);
    assert!(matches!(
        plan.denial,
        Some(RemoteTransportPlanDenial::NoAuthorizedTransport { .. })
    ));
}

#[test]
fn terminal_close_reasons_never_fallback() {
    let terminal = [
        RemoteTransportCloseReason::AuthFailure,
        RemoteTransportCloseReason::ProofFailure,
        RemoteTransportCloseReason::CertificateFailure,
        RemoteTransportCloseReason::VersionFailure,
        RemoteTransportCloseReason::IntegrityFailure,
        RemoteTransportCloseReason::RevocationFailure,
        RemoteTransportCloseReason::PolicyFailure,
        RemoteTransportCloseReason::QuotaFailure,
        RemoteTransportCloseReason::ConsentFailure,
    ];
    for reason in terminal {
        assert!(reason.is_terminal());
        assert!(!reason.is_reachability());
    }
}

#[test]
fn reachability_close_reasons_may_fallback() {
    let reachability = [
        RemoteTransportCloseReason::IceNoCandidatePair,
        RemoteTransportCloseReason::IceTimeout,
        RemoteTransportCloseReason::NetworkUnreachable,
        RemoteTransportCloseReason::TurnUnreachable,
    ];
    for reason in reachability {
        assert!(reason.is_reachability());
        assert!(!reason.is_terminal());
    }
}

#[test]
fn ice_disconnected_maps_after_three_probes() {
    assert_eq!(ice_disconnected_to_reachability(0), None);
    assert_eq!(ice_disconnected_to_reachability(2), None);
    assert_eq!(
        ice_disconnected_to_reachability(3),
        Some(RemoteReachabilityClass::NetworkUnreachable)
    );
}

#[test]
fn deadline_default_and_range() {
    assert_eq!(REMOTE_AUTO_INITIAL_DEADLINE_SECONDS, 10);
    assert_eq!(REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS, 3);
    assert_eq!(REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS, 30);
    assert!(validate_auto_deadline_seconds(2).is_err());
    assert!(validate_auto_deadline_seconds(3).is_ok());
    assert!(validate_auto_deadline_seconds(30).is_ok());
    assert!(validate_auto_deadline_seconds(31).is_err());
}

#[test]
fn physical_cap_normal_and_turn_replacement() {
    assert_eq!(REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL, 2);
    assert_eq!(REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT, 3);
    assert_eq!(physical_child_cap(false), 2);
    assert_eq!(physical_child_cap(true), 3);
}

#[test]
fn current_caps_are_one_per_kind() {
    assert_eq!(REMOTE_MAX_CURRENT_WEBRTC, 1);
    assert_eq!(REMOTE_MAX_CURRENT_WEBSOCKET, 1);
}

#[test]
fn pending_caps_are_two_total_one_per_kind() {
    assert_eq!(REMOTE_MAX_PENDING_CHILDREN_TOTAL, 2);
    assert_eq!(REMOTE_MAX_PENDING_CHILDREN_PER_KIND, 1);
}

#[test]
fn budget_schema_name() {
    assert_eq!(
        REMOTE_RETRY_RESERVATION_SCHEMA,
        "RemoteTransportRetryReservation"
    );
    assert_eq!(REMOTE_TRAIN_ID_BYTES, 16);
}

#[test]
fn budget_reserves_initial_idempotently() {
    let snapshot = RemoteRetryBudgetSnapshot::default();
    let request = RemoteRetryBudgetRequest {
        train_id: "train_1".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_1".into(),
        reservation_type: RemoteReservationType::Initial,
    };
    let outcome = evaluate_retry_budget(&snapshot, &request, 0);
    assert!(matches!(
        outcome,
        RemoteRetryReservationOutcome::Reserved(_)
    ));
}

#[test]
fn budget_duplicate_is_idempotent() {
    let request = RemoteRetryBudgetRequest {
        train_id: "train_1".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_1".into(),
        reservation_type: RemoteReservationType::Initial,
    };
    let first = evaluate_retry_budget(&RemoteRetryBudgetSnapshot::default(), &request, 0);
    let reservation = match first {
        RemoteRetryReservationOutcome::Reserved(r) => r,
        _ => panic!("expected reserved"),
    };
    let snapshot = RemoteRetryBudgetSnapshot {
        train_reservations: vec![reservation.clone()],
        rolling_window_reservations: vec![reservation],
    };
    let dup = evaluate_retry_budget(&snapshot, &request, 1000);
    assert!(matches!(dup, RemoteRetryReservationOutcome::Duplicate(_)));
}

#[test]
fn budget_rejects_more_than_four_per_train() {
    assert_eq!(REMOTE_RETRY_BUDGET_MAX_PER_TRAIN, 4);
    let mut reservations = Vec::new();
    for i in 0..4 {
        reservations.push(RemoteTransportRetryReservationV1 {
            schema_version: 1,
            reservation_id: format!("res_{i}"),
            tenant_id: String::new(),
            account_id: String::new(),
            client_device_id: String::new(),
            logical_attachment_id: String::new(),
            train_id: "train_1".into(),
            transport_kind: RemoteTransportKind::WebRtc,
            child_attempt_id: format!("att_{i}"),
            reservation_type: RemoteReservationType::Initial,
            reserved_at_ms: 0,
            expires_at_ms: 9999,
            terminal_outcome: None,
            terminal_at_ms: None,
        });
    }
    let snapshot = RemoteRetryBudgetSnapshot {
        train_reservations: reservations,
        rolling_window_reservations: vec![],
    };
    let request = RemoteRetryBudgetRequest {
        train_id: "train_1".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_new".into(),
        reservation_type: RemoteReservationType::Initial,
    };
    let outcome = evaluate_retry_budget(&snapshot, &request, 100);
    assert!(matches!(
        outcome,
        RemoteRetryReservationOutcome::Rejected(RemoteRetryBudgetDenialReason::MaxPerTrainExceeded)
    ));
}

#[test]
fn budget_rejects_twelve_per_hour_rolling() {
    assert_eq!(REMOTE_RETRY_BUDGET_MAX_PER_HOUR, 12);
    assert_eq!(REMOTE_RETRY_BUDGET_WINDOW_SECONDS, 3600);
    let now: i64 = 10_000_000;
    let mut reservations = Vec::new();
    for i in 0..12 {
        reservations.push(RemoteTransportRetryReservationV1 {
            schema_version: 1,
            reservation_id: format!("res_{i}"),
            tenant_id: String::new(),
            account_id: String::new(),
            client_device_id: String::new(),
            logical_attachment_id: String::new(),
            train_id: format!("train_{i}"),
            transport_kind: RemoteTransportKind::WebRtc,
            child_attempt_id: format!("att_{i}"),
            reservation_type: RemoteReservationType::Initial,
            reserved_at_ms: now - 1000,
            expires_at_ms: now + 9999,
            terminal_outcome: None,
            terminal_at_ms: None,
        });
    }
    let snapshot = RemoteRetryBudgetSnapshot {
        train_reservations: vec![],
        rolling_window_reservations: reservations,
    };
    let request = RemoteRetryBudgetRequest {
        train_id: "train_new".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_new".into(),
        reservation_type: RemoteReservationType::Initial,
    };
    let outcome = evaluate_retry_budget(&snapshot, &request, now);
    assert!(matches!(
        outcome,
        RemoteRetryReservationOutcome::Rejected(RemoteRetryBudgetDenialReason::MaxPerHourExceeded)
    ));
}

#[test]
fn budget_kind_retry_exhausted_after_one() {
    assert_eq!(REMOTE_MAX_RETRIES_PER_KIND, 1);
    let retry_res = RemoteTransportRetryReservationV1 {
        schema_version: 1,
        reservation_id: "res_r1".into(),
        tenant_id: String::new(),
        account_id: String::new(),
        client_device_id: String::new(),
        logical_attachment_id: String::new(),
        train_id: "train_1".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_r1".into(),
        reservation_type: RemoteReservationType::Retry,
        reserved_at_ms: 0,
        expires_at_ms: 9999,
        terminal_outcome: None,
        terminal_at_ms: None,
    };
    let snapshot = RemoteRetryBudgetSnapshot {
        train_reservations: vec![retry_res],
        rolling_window_reservations: vec![],
    };
    let request = RemoteRetryBudgetRequest {
        train_id: "train_1".into(),
        transport_kind: RemoteTransportKind::WebRtc,
        child_attempt_id: "att_r2".into(),
        reservation_type: RemoteReservationType::Retry,
    };
    let outcome = evaluate_retry_budget(&snapshot, &request, 100);
    assert!(matches!(
        outcome,
        RemoteRetryReservationOutcome::Rejected(RemoteRetryBudgetDenialReason::KindRetryExhausted)
    ));
}

#[test]
fn budget_outage_denies() {
    assert!(matches!(
        retry_budget_outcome_outage(),
        RemoteRetryReservationOutcome::Rejected(RemoteRetryBudgetDenialReason::DatabaseOutage)
    ));
}

#[test]
fn budget_retry_delay_is_one_second() {
    assert_eq!(REMOTE_RETRY_DELAY_MS, 1000);
}

#[test]
fn webrtc_probe_interval_is_five_seconds() {
    assert_eq!(REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS, 5);
}

#[test]
fn webrtc_healthy_after_two_successes() {
    assert_eq!(REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES, 2);
    let c = RemoteChildHealthCounters::default();
    let r1 = compute_webrtc_health(c, true, 0);
    assert_eq!(r1.consecutive_healthy, 1);
    assert_eq!(r1.health, None);
    let r2 = compute_webrtc_health(r1, true, 0);
    assert_eq!(r2.consecutive_healthy, 2);
    assert_eq!(r2.health, Some(RemoteChildHealth::Healthy));
}

#[test]
fn webrtc_degraded_after_three_misses() {
    assert_eq!(REMOTE_WEBRTC_DEGRADED_MISS_PROBES, 3);
    let c = RemoteChildHealthCounters {
        consecutive_misses: 2,
        ..Default::default()
    };
    let r = compute_webrtc_health(c, false, 0);
    assert_eq!(r.consecutive_misses, 3);
    assert_eq!(r.health, Some(RemoteChildHealth::Degraded));
}

#[test]
fn webrtc_failed_after_six_misses() {
    assert_eq!(REMOTE_WEBRTC_FAILED_MISS_PROBES, 6);
    let c = RemoteChildHealthCounters {
        consecutive_misses: 5,
        ..Default::default()
    };
    let r = compute_webrtc_health(c, false, 0);
    assert_eq!(r.consecutive_misses, 6);
    assert_eq!(r.health, Some(RemoteChildHealth::Failed));
}

#[test]
fn webrtc_degraded_buffer_threshold() {
    assert_eq!(REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES, 4 * 1024 * 1024);
    assert_eq!(REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES, 2);
    let c = RemoteChildHealthCounters {
        consecutive_buffer_high: 1,
        ..Default::default()
    };
    let r = compute_webrtc_health(c, true, 4 * 1024 * 1024);
    assert_eq!(r.consecutive_buffer_high, 2);
    assert_eq!(r.health, Some(RemoteChildHealth::Degraded));
}

#[test]
fn websocket_degraded_oldest_unacked_three_seconds() {
    assert_eq!(REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS, 3);
    let c = RemoteChildHealthCounters::default();
    let r = compute_websocket_health(c, 3, 0, 0);
    assert_eq!(r.health, Some(RemoteChildHealth::Degraded));
}

#[test]
fn websocket_failed_at_third_retransmission() {
    assert_eq!(REMOTE_WEBSOCKET_FAILED_RETRANSMISSION, 3);
    let c = RemoteChildHealthCounters::default();
    let r = compute_websocket_health(c, 0, 0, 3);
    assert_eq!(r.health, Some(RemoteChildHealth::Failed));
}

#[test]
fn recovery_requires_two_intervals() {
    assert_eq!(REMOTE_HEALTH_RECOVERY_INTERVALS, 2);
}

fn routable(
    id: &str,
    kind: RemoteTransportKind,
    epoch: &str,
    health: RemoteChildHealth,
    lifecycle: Option<RemoteTurnLifecycle>,
    writable: u64,
) -> RemoteRoutableChild {
    RemoteRoutableChild {
        child_attempt_id: id.into(),
        transport_kind: kind,
        transport_epoch: epoch.into(),
        turn_lifecycle: lifecycle,
        health,
        writable_bytes: writable,
    }
}

#[test]
fn route_control_healthy_over_degraded() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebRtc,
            "ep_1",
            RemoteChildHealth::Degraded,
            None,
            1024,
        ),
        routable(
            "b",
            RemoteTransportKind::WebSocket,
            "ep_2",
            RemoteChildHealth::Healthy,
            None,
            1024,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Control).unwrap();
    assert_eq!(selected.child_attempt_id, "b");
}

#[test]
fn route_interactive_healthy_webrtc_first() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebSocket,
            "ep_1",
            RemoteChildHealth::Healthy,
            None,
            1024,
        ),
        routable(
            "b",
            RemoteTransportKind::WebRtc,
            "ep_2",
            RemoteChildHealth::Healthy,
            None,
            1024,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Interactive).unwrap();
    assert_eq!(selected.transport_kind, RemoteTransportKind::WebRtc);
}

#[test]
fn route_bulk_more_writable_bytes() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebRtc,
            "ep_1",
            RemoteChildHealth::Healthy,
            None,
            512,
        ),
        routable(
            "b",
            RemoteTransportKind::WebSocket,
            "ep_2",
            RemoteChildHealth::Healthy,
            None,
            4096,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Bulk).unwrap();
    assert_eq!(selected.child_attempt_id, "b");
}

#[test]
fn route_bulk_tie_webrtc() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebSocket,
            "ep_1",
            RemoteChildHealth::Healthy,
            None,
            2048,
        ),
        routable(
            "b",
            RemoteTransportKind::WebRtc,
            "ep_2",
            RemoteChildHealth::Healthy,
            None,
            2048,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Bulk).unwrap();
    assert_eq!(selected.transport_kind, RemoteTransportKind::WebRtc);
}

#[test]
fn route_replacement_pending_never_selected() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebRtc,
            "ep_1",
            RemoteChildHealth::Healthy,
            Some(RemoteTurnLifecycle::ReplacementPending),
            1024,
        ),
        routable(
            "b",
            RemoteTransportKind::WebSocket,
            "ep_2",
            RemoteChildHealth::Degraded,
            None,
            1024,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Control).unwrap();
    assert_eq!(selected.child_attempt_id, "b");
}

#[test]
fn route_draining_never_selected() {
    let children = vec![
        routable(
            "a",
            RemoteTransportKind::WebRtc,
            "ep_1",
            RemoteChildHealth::Healthy,
            Some(RemoteTurnLifecycle::Draining),
            1024,
        ),
        routable(
            "b",
            RemoteTransportKind::WebSocket,
            "ep_2",
            RemoteChildHealth::Healthy,
            None,
            1024,
        ),
    ];
    let selected = select_route_child(&children, RemoteRouteLane::Control).unwrap();
    assert_eq!(selected.child_attempt_id, "b");
}

#[test]
fn schema_version_is_one() {
    assert_eq!(REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION, 1);
}

#[test]
fn turn_drain_max_is_thirty_seconds() {
    assert_eq!(REMOTE_TURN_DRAIN_MAX_SECONDS, 30);
}
