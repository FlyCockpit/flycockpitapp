//! Core-logic tests for the leaks module: MAC'd list cursor, snapshot
//! watermark, filters, `has_more`, rotation-plan derivation, and the reveal
//! capability/rate state. These drive the production entry points in
//! `crate::leaks`; dispatch-level and reveal-consumption tests live in
//! `crate::daemon::server::leaks_tests`.

use super::*;
use crate::db::Db;
use crate::db::protected_leak_records::{
    LeakCategory, LeakListFilters, LeakProvenance, LeakRecordStatus, LeakRotation, LeakSource,
};
use crate::leak_report::{LeakReportHandler, LeakReportOutcome, ReportLeakAuthority};
use crate::redact::protected_redaction_history::{
    MapKeyResolver, REDACTION_KEY_LEN, RedactionKeyResolver,
};
use zeroize::Zeroizing;

fn test_key_v1() -> [u8; REDACTION_KEY_LEN] {
    [0x42u8; REDACTION_KEY_LEN]
}

fn test_resolver() -> MapKeyResolver {
    MapKeyResolver::new().with_version(1, test_key_v1())
}

fn cursor_key() -> [u8; 32] {
    [7u8; 32]
}

fn session_a() -> &'static str {
    "aaaaaaaa-aaaa-aaaa-aaaa-111111111111"
}
fn session_b() -> &'static str {
    "bbbbbbbb-bbbb-bbbb-bbbb-222222222222"
}

/// Seed two sessions with distinct project roots so the `project_root` join is
/// exercised with a real discriminating input.
async fn test_db() -> Db {
    let db = Db::open_in_memory().unwrap();
    for (sid, root) in [(session_a(), "/proj/a"), (session_b(), "/proj/b")] {
        let sid = sid.to_owned();
        let root = root.to_owned();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
                 VALUES(?1,'p',?2,1,1)",
                rusqlite::params![sid, root],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }
    db
}

fn provenance() -> LeakProvenance {
    LeakProvenance {
        provider_id: Some("openai".to_owned()),
        model_id: Some("gpt-4".to_owned()),
        generation: Some(42),
        connector_id: None,
    }
}

async fn insert_contained_leak(
    db: &Db,
    resolver: &dyn RedactionKeyResolver,
    session_id: &str,
    secret: &str,
    source: LeakSource,
    category: LeakCategory,
    now_ms: i64,
) -> String {
    let handler = LeakReportHandler::new(db, resolver, now_ms);
    let authority = ReportLeakAuthority::new(source, provenance(), session_id.to_owned());
    let outcome = handler
        .report(&authority, Zeroizing::new(secret.to_owned()), category)
        .await
        .unwrap();
    match outcome {
        LeakReportOutcome::Contained { report_id } => report_id,
        LeakReportOutcome::Deduplicated { report_id, .. } => report_id,
        other => panic!("expected contained, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Rotation-plan derivation (closed vocabulary)
// ---------------------------------------------------------------------------

#[test]
fn leak_rotation_proposal_derivation_is_closed_vocabulary() {
    assert_eq!(
        LeakRotationPlan::derive(LeakSource::CredentialLeak, LeakCategory::Token, Some("c1")),
        LeakRotationPlan::RevokeConnectorCredential
    );
    assert_eq!(
        LeakRotationPlan::derive(LeakSource::ModelOutput, LeakCategory::Token, Some("c1")),
        LeakRotationPlan::RevokeConnectorCredential
    );
    for cat in [
        LeakCategory::Secret,
        LeakCategory::Key,
        LeakCategory::Password,
    ] {
        assert_eq!(
            LeakRotationPlan::derive(LeakSource::ModelOutput, cat, None),
            LeakRotationPlan::RotateNamedSecret
        );
    }
    for src in [LeakSource::EnvLeak, LeakSource::Reasoning] {
        assert_eq!(
            LeakRotationPlan::derive(src, LeakCategory::Pii, None),
            LeakRotationPlan::InvalidateSession
        );
    }
    assert_eq!(
        LeakRotationPlan::derive(LeakSource::Other, LeakCategory::Other, None),
        LeakRotationPlan::OwnerReviewRequired
    );
}

#[test]
fn leak_list_row_debug_has_no_secret_fields() {
    let row = LeakListRow {
        report_id: "r1".into(),
        session_id: "s1".into(),
        source: LeakSource::ModelOutput,
        category: LeakCategory::Token,
        provider_id: None,
        model_id: None,
        generation: None,
        connector_id: None,
        status: LeakRecordStatus::Contained,
        seen_count: 1,
        rotation: LeakRotation::None,
        rotation_plan: LeakRotationPlan::OwnerReviewRequired,
        first_reported_ms: 1000,
        last_reported_ms: 1000,
        contained_at_ms: Some(1000),
    };
    let debug = format!("{row:?}");
    for forbidden in [
        "secret:",
        "plaintext:",
        "ciphertext:",
        "prefix:",
        "fingerprint:",
        "nonce:",
        "literal:",
    ] {
        assert!(
            !debug.contains(forbidden),
            "debug leaks field `{forbidden}`"
        );
    }
}

// ---------------------------------------------------------------------------
// Reveal state (mint/replace/take + rate window) — unit
// ---------------------------------------------------------------------------

#[test]
fn leak_reveal_state_mint_replaces_and_rate_window_slides() {
    let mut state = LeakRevealState::new();
    // No capability -> NoCapability (unauthorized), rate untouched.
    assert!(matches!(
        state.begin_reveal(1000),
        RevealStart::NoCapability
    ));

    // Mint, then a second mint replaces (invalidates) the first: only the
    // second token survives in the single slot.
    state.mint([1u8; 32], "r1".into(), 61_000);
    state.mint([2u8; 32], "r2".into(), 62_000);
    match state.begin_reveal(1000) {
        RevealStart::Consumed(cap) => {
            assert_eq!(cap.report_id(), "r2");
            assert_eq!(cap.token(), &[2u8; 32]);
        }
        other => panic!("expected Consumed, got {other:?}"),
    }
    // Single-use: the slot is now empty.
    assert!(matches!(
        state.begin_reveal(1000),
        RevealStart::NoCapability
    ));

    // Rate window: 3 successes exhaust the limit; a 4th begin is RateLimited
    // (and does not consume a freshly minted capability).
    let mut state = LeakRevealState::new();
    for t in [1000, 1500, 2000] {
        state.record_success(t);
    }
    state.mint([9u8; 32], "r".into(), 100_000);
    assert!(matches!(state.begin_reveal(2500), RevealStart::RateLimited));
    // The capability was not consumed.
    assert!(state.pending_is_some());
    // After the window slides past 60s, begin succeeds.
    match state.begin_reveal(65_000) {
        RevealStart::Consumed(cap) => assert_eq!(cap.report_id(), "r"),
        other => panic!("expected Consumed after window slide, got {other:?}"),
    }
}

/// R1 (TOCTOU): in-flight reservations count toward the 3/min limit, so a
/// concurrent 4th reveal is rejected even though NO success has been confirmed
/// yet (all three are still awaiting their DB rehydrate). A released reservation
/// frees the budget again.
#[test]
fn leak_reveal_state_in_flight_reservation_counts_toward_limit() {
    let mut state = LeakRevealState::new();
    // Three reveals reserved-but-not-confirmed (each takes the single slot, so
    // mint before each). None has recorded a success.
    for _ in 0..3 {
        state.mint([1u8; 32], "r".into(), 100_000);
        assert!(matches!(state.begin_reveal(1000), RevealStart::Consumed(_)));
    }
    // A 4th concurrent reveal must be RateLimited on the reservations alone —
    // this fails against a limiter that counts only confirmed successes.
    state.mint([1u8; 32], "r".into(), 100_000);
    assert!(matches!(state.begin_reveal(1000), RevealStart::RateLimited));

    // Releasing one reservation (a failed reveal) frees exactly one slot.
    state.release_reservation(1000);
    state.mint([1u8; 32], "r".into(), 100_000);
    assert!(matches!(state.begin_reveal(1000), RevealStart::Consumed(_)));

    // Confirming a reservation keeps the count (reservation -> success), so the
    // budget stays exhausted.
    state.confirm_success(1000, 1000);
    state.mint([1u8; 32], "r".into(), 100_000);
    assert!(matches!(state.begin_reveal(1000), RevealStart::RateLimited));
}

/// RL2: a stalled reveal's reservation is NOT aged out of the window, so it keeps
/// counting until it confirms/releases — preventing more than 3 successes per
/// rolling minute even when the first batch stalls past the window and then
/// completes.
#[test]
fn leak_reveal_state_stalled_reservations_are_not_aged_out() {
    let mut state = LeakRevealState::new();
    // Three reveals reserve at T0 and then stall (never confirm).
    for _ in 0..3 {
        state.mint([1u8; 32], "r".into(), 1_000_000);
        assert!(matches!(state.begin_reveal(0), RevealStart::Consumed(_)));
    }
    // A 4th far past the 60s window is STILL RateLimited: the three in-flight
    // reservations are not aged out. This fails against a limiter that ages
    // reservations by their reserve time (which would free the slots here).
    state.mint([1u8; 32], "r".into(), 1_000_000);
    assert!(matches!(
        state.begin_reveal(70_000),
        RevealStart::RateLimited
    ));

    // The stalled three finally confirm, recorded at the CONFIRM time (70_000).
    for _ in 0..3 {
        state.confirm_success(0, 70_000);
    }
    // A 4th within a minute of their confirm is still RateLimited.
    state.mint([1u8; 32], "r".into(), 1_000_000);
    assert!(matches!(
        state.begin_reveal(80_000),
        RevealStart::RateLimited
    ));

    // Only a full minute past their confirm reopens the budget.
    state.mint([1u8; 32], "r".into(), 1_000_000);
    assert!(matches!(
        state.begin_reveal(131_000),
        RevealStart::Consumed(_)
    ));
}

// ---------------------------------------------------------------------------
// Cursor MAC (AC6)
// ---------------------------------------------------------------------------

fn sample_payload() -> LeakCursorPayload {
    LeakCursorPayload {
        session_filter: Some(session_a().to_owned()),
        project_root: Some("/proj/a".to_owned()),
        rotation: Some(LeakRotation::PendingUser),
        snapshot_high_watermark: 5_000_000,
        last_seen_ms: 3_000_000,
        last_report_id: "report-xyz".to_owned(),
    }
}

fn matching_filters(p: &LeakCursorPayload) -> LeakListFilters {
    LeakListFilters {
        session_filter: p.session_filter.clone(),
        project_root: p.project_root.clone(),
        rotation: p.rotation,
    }
}

#[test]
fn leak_list_cursor_mac_rejects_tamper() {
    let key = cursor_key();
    let payload = sample_payload();
    let filters = matching_filters(&payload);
    let cursor = encode_leak_cursor(&key, &payload);

    // Unmodified round-trip is accepted and preserves the payload.
    let decoded = decode_leak_cursor(&key, &cursor, &filters).unwrap();
    assert_eq!(decoded, payload);

    // Flip any single payload byte -> rejected.
    let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .unwrap();
    let flipped = {
        let mut r = raw.clone();
        r[3] ^= 0x01; // inside the payload region
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&r)
    };
    assert_eq!(
        decode_leak_cursor(&key, &flipped, &filters),
        Err(LeakListError::InvalidCursor)
    );

    // Alter a MAC byte (last byte) -> rejected.
    let last = raw.len() - 1;
    raw[last] ^= 0x80;
    let mac_altered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
    assert_eq!(
        decode_leak_cursor(&key, &mac_altered, &filters),
        Err(LeakListError::InvalidCursor)
    );

    // Truncated frame -> rejected.
    let truncated = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cursor.as_bytes())
            .unwrap()[..10],
    );
    assert_eq!(
        decode_leak_cursor(&key, &truncated, &filters),
        Err(LeakListError::InvalidCursor)
    );

    // A cursor minted under a different boot key -> rejected.
    let other_key = [9u8; 32];
    let other_cursor = encode_leak_cursor(&other_key, &payload);
    assert_eq!(
        decode_leak_cursor(&key, &other_cursor, &filters),
        Err(LeakListError::InvalidCursor)
    );

    // Filters that differ from the cursor's bound filters -> rejected.
    let mismatched = LeakListFilters {
        session_filter: Some(session_b().to_owned()),
        ..filters.clone()
    };
    assert_eq!(
        decode_leak_cursor(&key, &cursor, &mismatched),
        Err(LeakListError::InvalidCursor)
    );
    let mismatched_rot = LeakListFilters {
        rotation: Some(LeakRotation::Rotated),
        ..filters.clone()
    };
    assert_eq!(
        decode_leak_cursor(&key, &cursor, &mismatched_rot),
        Err(LeakListError::InvalidCursor)
    );

    // A well-formed legacy base64-JSON cursor -> rejected (no valid MAC).
    let legacy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "last_seen_ms": 3_000_000,
            "report_id": "report-xyz"
        }))
        .unwrap(),
    );
    assert_eq!(
        decode_leak_cursor(&key, &legacy, &filters),
        Err(LeakListError::InvalidCursor)
    );
}

// ---------------------------------------------------------------------------
// Snapshot watermark + has_more (AC7)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_list_snapshot_watermark_and_has_more() {
    let db = test_db().await;
    let resolver = test_resolver();
    let key = cursor_key();

    // Three rows, distinct last_reported timestamps.
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "s1",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "s2",
        LeakSource::ToolOutput,
        LeakCategory::Key,
        2_000_000,
    )
    .await;
    let r3 = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "s3",
        LeakSource::Reasoning,
        LeakCategory::Password,
        3_000_000,
    )
    .await;

    // Page 1 (limit 2): newest first, has_more true, cursor present.
    let page1 = list_leak_reports(&db, &key, LeakListFilters::default(), 2, None)
        .await
        .unwrap();
    assert_eq!(page1.refs.len(), 2);
    assert_eq!(page1.refs[0].last_reported_ms, 3_000_000);
    assert_eq!(page1.refs[1].last_reported_ms, 2_000_000);
    assert!(page1.has_more);
    let cursor = page1.next_cursor.clone().expect("cursor for page 2");

    // Insert a NEW row and RE-REPORT r3 (bumping its last_reported_ms above the
    // snapshot watermark) before fetching page 2. Neither may appear.
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "s4",
        LeakSource::EnvLeak,
        LeakCategory::Secret,
        4_000_000,
    )
    .await;
    // Re-report r3's secret with a later timestamp -> dedup bumps last_reported.
    let _ = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "s3",
        LeakSource::Reasoning,
        LeakCategory::Password,
        5_000_000,
    )
    .await;

    let page2 = list_leak_reports(&db, &key, LeakListFilters::default(), 2, Some(&cursor))
        .await
        .unwrap();
    // Only the original oldest row (s1) remains in this snapshot chain.
    assert_eq!(
        page2.refs.len(),
        1,
        "re-reported/new rows must not appear mid-chain"
    );
    assert_eq!(page2.refs[0].last_reported_ms, 1_000_000);
    assert!(!page2.has_more);
    assert!(page2.next_cursor.is_none());
    // r3 is absent from the remainder of the chain (it left the snapshot).
    assert!(!page2.refs.iter().any(|r| r.report_id == r3));

    // Refresh: a fresh snapshot now sees all 4 rows, newest first.
    let refreshed = list_leak_reports(&db, &key, LeakListFilters::default(), 100, None)
        .await
        .unwrap();
    assert_eq!(refreshed.refs.len(), 4);
    assert_eq!(refreshed.refs[0].last_reported_ms, 5_000_000);
    assert!(!refreshed.has_more);
    assert!(refreshed.next_cursor.is_none());
}

#[tokio::test]
async fn leak_list_exact_multiple_page_has_no_cursor() {
    let db = test_db().await;
    let resolver = test_resolver();
    let key = cursor_key();
    for i in 0..2 {
        insert_contained_leak(
            &db,
            &resolver,
            session_a(),
            &format!("x{i}"),
            LeakSource::ModelOutput,
            LeakCategory::Token,
            1_000_000 + i,
        )
        .await;
    }
    // Exactly `limit` rows -> has_more false, no cursor (regression for the old
    // `refs.len() == limit` bug that emitted a cursor to an empty next page).
    let page = list_leak_reports(&db, &key, LeakListFilters::default(), 2, None)
        .await
        .unwrap();
    assert_eq!(page.refs.len(), 2);
    assert!(!page.has_more);
    assert!(page.next_cursor.is_none());

    // limit+1 available -> has_more true and a working cursor to the last page.
    let page = list_leak_reports(&db, &key, LeakListFilters::default(), 1, None)
        .await
        .unwrap();
    assert!(page.has_more);
    let cursor = page.next_cursor.unwrap();
    let page2 = list_leak_reports(&db, &key, LeakListFilters::default(), 1, Some(&cursor))
        .await
        .unwrap();
    assert_eq!(page2.refs.len(), 1);
}

#[tokio::test]
async fn leak_list_invalid_limit_and_cursor() {
    let db = test_db().await;
    let key = cursor_key();
    assert_eq!(
        list_leak_reports(&db, &key, LeakListFilters::default(), 0, None).await,
        Err(LeakListError::InvalidLimit)
    );
    assert_eq!(
        list_leak_reports(&db, &key, LeakListFilters::default(), 101, None).await,
        Err(LeakListError::InvalidLimit)
    );
    assert_eq!(
        list_leak_reports(
            &db,
            &key,
            LeakListFilters::default(),
            10,
            Some("not-a-valid-cursor")
        )
        .await,
        Err(LeakListError::InvalidCursor)
    );
}

// ---------------------------------------------------------------------------
// project_root + rotation filters (AC8)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_list_project_root_and_rotation_filters() {
    let db = test_db().await;
    let resolver = test_resolver();
    let key = cursor_key();

    let ra = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "sa",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    let rb = insert_contained_leak(
        &db,
        &resolver,
        session_b(),
        "sb",
        LeakSource::ToolOutput,
        LeakCategory::Key,
        2_000_000,
    )
    .await;

    // Machine-wide default includes both.
    let all = list_leak_reports(&db, &key, LeakListFilters::default(), 100, None)
        .await
        .unwrap();
    assert_eq!(all.refs.len(), 2);

    // project_root join: '/proj/a' returns only session_a's record.
    let only_a = list_leak_reports(
        &db,
        &key,
        LeakListFilters {
            project_root: Some("/proj/a".to_owned()),
            ..Default::default()
        },
        100,
        None,
    )
    .await
    .unwrap();
    assert_eq!(only_a.refs.len(), 1);
    assert_eq!(only_a.refs[0].report_id, ra);

    // Other-root and unknown-root return the distinct empty page (not an error).
    for root in ["/proj/b", "/proj/does-not-exist"] {
        let page = list_leak_reports(
            &db,
            &key,
            LeakListFilters {
                project_root: Some(root.to_owned()),
                ..Default::default()
            },
            100,
            None,
        )
        .await
        .unwrap();
        if root == "/proj/b" {
            assert_eq!(page.refs.len(), 1);
            assert_eq!(page.refs[0].report_id, rb);
        } else {
            assert!(page.refs.is_empty());
            assert!(page.next_cursor.is_none());
        }
    }

    // Rotation-state filter exact-matches each of the four states. Set ra's
    // rotation to PendingUser and mark rb Rotated.
    update_rotation(&db, &ra, LeakRotationAction::Accept)
        .await
        .unwrap();
    update_rotation(&db, &rb, LeakRotationAction::MarkRotated)
        .await
        .unwrap();
    let cases = [
        (LeakRotation::None, 0),
        (LeakRotation::PendingUser, 1),
        (LeakRotation::Rotated, 1),
        (LeakRotation::NotApplicable, 0),
    ];
    for (rotation, expected) in cases {
        let page = list_leak_reports(
            &db,
            &key,
            LeakListFilters {
                rotation: Some(rotation),
                ..Default::default()
            },
            100,
            None,
        )
        .await
        .unwrap();
        assert_eq!(page.refs.len(), expected, "rotation filter {rotation:?}");
    }
}
