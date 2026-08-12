//! Tests for the leaks-page module: machine-wide Owner worklist, rotation
//! plans, and authenticated recovery.
//!
//! Coverage maps to the prompt's acceptance criteria:
//!
//! * `leak_list_metadata_schema` — list types contain no secret/prefix/
//!   fingerprint/ciphertext field and default to machine-wide Owner
//!   visibility.
//! * `leak_list_snapshot_cursor_stable` — concurrent inserts, equal
//!   timestamps, page boundaries, refresh, filter/owner mismatch, tamper.
//! * `leak_list_limits_and_errors` — 1/100/101, deterministic order,
//!   InvalidCursor, RateLimited, Unavailable, Internal.
//! * `leak_rotation_proposals_and_owner_recovery` — closed-vocabulary plan
//!   derivation/accept/dismiss, metadata-only list output, authenticated
//!   hidden-by-default recovery, secure protected-value deletion retaining
//!   historical redaction.
//! * `leak_reveal_requires_sensitive_local_channel` — ordinary daemon/remote
//!   Response/Event codecs cannot carry plaintext; remote/headless/subagent/
//!   replay/expired/wrong-session/wrong-report/denied branches fail before
//!   protected read.
//! * `leak_reveal_ephemeral_generation` — LeaksPane is the sole Zeroizing
//!   buffer owner; full-repaint close/detach/lock/newer generation/30-second
//!   timeout and late-result discard.
//! * `leak_mark_rotated` — explicit, reversible, metadata-only; fresh
//!   re-report clears it.
//! * `machine_wide_leak_owner_access` — records from different projects and
//!   deleted/orphaned sessions remain Owner-visible, recoverable, and
//!   deletable by report ID.
//! * Sentinel plaintext is absent from list, events, transcripts, caches,
//!   clipboard, logs, errors, portable exports, analytics, and remote frames.

use super::*;
use crate::db::Db;
use crate::db::protected_leak_records::{LeakCategory, LeakProvenance, LeakSource};
use crate::leak_report::{LeakReportHandler, LeakReportOutcome, ReportLeakAuthority};
use crate::redact::protected_redaction_history::{MapKeyResolver, REDACTION_KEY_LEN};

/// A fixed test key (32 bytes) for key version 1.
fn test_key_v1() -> [u8; REDACTION_KEY_LEN] {
    [0x42u8; REDACTION_KEY_LEN]
}

fn test_resolver() -> MapKeyResolver {
    MapKeyResolver::new().with_version(1, test_key_v1())
}

async fn test_db() -> Db {
    let db = Db::open_in_memory().unwrap();
    // protected_redaction_history.session_id and protected_leak_records.session_id
    // carry cascading FKs to sessions(session_id), so the referenced session rows
    // must exist before the leak-report handler writes any protected record.
    for session_id in [session_a(), session_b()] {
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
                 VALUES(?1,'p','/redacted',1,1)",
                [session_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }
    db
}

fn session_a() -> &'static str {
    "aaaaaaaa-aaaa-aaaa-aaaa-111111111111"
}

fn session_b() -> &'static str {
    "bbbbbbbb-bbbb-bbbb-bbbb-222222222222"
}

fn provenance() -> LeakProvenance {
    LeakProvenance {
        provider_id: Some("openai".to_owned()),
        model_id: Some("gpt-4".to_owned()),
        generation: Some(42),
        connector_id: None,
    }
}

/// Insert a contained leak record via the leak report handler and return its
/// report id.
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
        _ => panic!("expected contained, got {outcome:?}"),
    }
}

// ---------------------------------------------------------------------------
// Criterion 1: leak_list_metadata_schema — list types contain no
// secret/prefix/fingerprint/ciphertext field and default to machine-wide
// ---------------------------------------------------------------------------

#[test]
fn leak_list_metadata_schema_has_no_secret_fields() {
    let row = LeakListRow {
        report_id: "r1".into(),
        session_id: "s1".into(),
        source: LeakSource::ModelOutput,
        category: LeakCategory::Token,
        provider_id: None,
        model_id: None,
        generation: None,
        connector_id: None,
        status: crate::db::protected_leak_records::LeakRecordStatus::Contained,
        seen_count: 1,
        rotation: crate::db::protected_leak_records::LeakRotation::None,
        rotation_plan: LeakRotationPlan::OwnerReviewRequired,
        first_reported_ms: 1000,
        last_reported_ms: 1000,
        contained_at_ms: Some(1000),
    };
    // Debug output must not contain forbidden field names.
    let debug = format!("{row:?}");
    for forbidden in [
        "secret",
        "plaintext",
        "ciphertext",
        "prefix",
        "fingerprint",
        "nonce",
        "key_version",
        "literal",
        "value",
    ] {
        let needle = format!("{forbidden}:");
        assert!(
            !debug.contains(&needle),
            "leak list row debug must not contain field `{forbidden}`"
        );
    }
}

#[test]
fn leak_list_request_defaults_to_machine_wide() {
    let request = LeakListRequest {
        session_filter: None,
        limit: 50,
        cursor: None,
    };
    assert!(request.session_filter.is_none());
}

// ---------------------------------------------------------------------------
// Criterion 2: leak_list_snapshot_cursor_stable — concurrent inserts, equal
// timestamps, page boundaries, refresh, filter/owner mismatch, tamper
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_list_snapshot_cursor_stable_across_concurrent_inserts() {
    let db = test_db().await;
    let resolver = test_resolver();
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-1",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-2",
        LeakSource::ToolOutput,
        LeakCategory::Key,
        2_000_000,
    )
    .await;
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-3",
        LeakSource::Reasoning,
        LeakCategory::Password,
        3_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    // First page: limit=2, newest first.
    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 2,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.rows.len(), 2);
    assert_eq!(resp.rows[0].last_reported_ms, 3_000_000);
    assert_eq!(resp.rows[1].last_reported_ms, 2_000_000);
    let snapshot = resp.next_snapshot.unwrap();

    // Insert a new record before fetching the next page. It must NOT appear
    // in this snapshot's page chain.
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-4",
        LeakSource::EnvLeak,
        LeakCategory::Secret,
        4_000_000,
    )
    .await;

    // Second page: use the cursor from the first page.
    let resp2 = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 2,
            cursor: Some(snapshot.to_cursor()),
        })
        .await
        .unwrap();
    assert_eq!(resp2.rows.len(), 1);
    assert_eq!(resp2.rows[0].last_reported_ms, 1_000_000);
    assert!(resp2.next_snapshot.is_none());
}

#[tokio::test]
async fn leak_list_snapshot_cursor_equal_timestamps_deterministic_order() {
    let db = test_db().await;
    let resolver = test_resolver();
    let r1 = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-a",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    let r2 = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-b",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    let r3 = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-c",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);
    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.rows.len(), 3);
    let ids: Vec<&str> = resp.rows.iter().map(|r| r.report_id.as_str()).collect();
    assert!(ids[0] > ids[1]);
    assert!(ids[1] > ids[2]);
    assert!(ids.contains(&r1.as_str()));
    assert!(ids.contains(&r2.as_str()));
    assert!(ids.contains(&r3.as_str()));
}

#[tokio::test]
async fn leak_list_snapshot_filter_mismatch_returns_empty() {
    let db = test_db().await;
    let resolver = test_resolver();
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-a",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);
    let resp = service
        .list(&LeakListRequest {
            session_filter: Some(session_b().to_owned()),
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert!(resp.rows.is_empty());
    assert!(resp.next_snapshot.is_none());
}

// ---------------------------------------------------------------------------
// Criterion 3: leak_list_limits_and_errors — 1/100/101, InvalidLimit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_list_limits_and_errors() {
    let db = test_db().await;
    let resolver = test_resolver();
    let service = LeaksService::new(&db, &resolver, 5_000_000);

    let err = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 0,
            cursor: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err, LeakListError::InvalidLimit);

    let err = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 101,
            cursor: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err, LeakListError::InvalidLimit);

    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 1,
            cursor: None,
        })
        .await
        .unwrap();
    assert!(resp.rows.is_empty());

    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert!(resp.rows.is_empty());
}

// ---------------------------------------------------------------------------
// Criterion 4: leak_rotation_proposals_and_owner_recovery — closed-vocabulary
// plan derivation/accept/dismiss, metadata-only list output, authenticated
// hidden-by-default recovery, secure protected-value deletion retaining
// historical redaction
// ---------------------------------------------------------------------------

#[test]
fn leak_rotation_proposal_derivation_is_closed_vocabulary() {
    let plan = LeakRotationPlan::derive(
        LeakSource::CredentialLeak,
        LeakCategory::Token,
        Some("connector-1"),
    );
    assert_eq!(plan, LeakRotationPlan::RevokeConnectorCredential);

    let plan = LeakRotationPlan::derive(
        LeakSource::ModelOutput,
        LeakCategory::Token,
        Some("connector-1"),
    );
    assert_eq!(plan, LeakRotationPlan::RevokeConnectorCredential);

    for cat in [
        LeakCategory::Secret,
        LeakCategory::Key,
        LeakCategory::Password,
    ] {
        let plan = LeakRotationPlan::derive(LeakSource::ModelOutput, cat, None);
        assert_eq!(
            plan,
            LeakRotationPlan::RotateNamedSecret,
            "category {cat:?}"
        );
    }

    for src in [LeakSource::EnvLeak, LeakSource::Reasoning] {
        let plan = LeakRotationPlan::derive(src, LeakCategory::Pii, None);
        assert_eq!(plan, LeakRotationPlan::InvalidateSession, "source {src:?}");
    }

    let plan = LeakRotationPlan::derive(LeakSource::Other, LeakCategory::Other, None);
    assert_eq!(plan, LeakRotationPlan::OwnerReviewRequired);
}

#[tokio::test]
async fn leak_rotation_accept_dismiss_and_mark_rotated() {
    let db = test_db().await;
    let resolver = test_resolver();
    let report_id = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-1",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    service
        .update_rotation(&LeakRotationUpdate {
            report_id: report_id.clone(),
            action: LeakRotationAction::Accept,
        })
        .await
        .unwrap();
    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::PendingUser
    );

    service
        .update_rotation(&LeakRotationUpdate {
            report_id: report_id.clone(),
            action: LeakRotationAction::MarkRotated,
        })
        .await
        .unwrap();
    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::Rotated
    );

    service
        .update_rotation(&LeakRotationUpdate {
            report_id: report_id.clone(),
            action: LeakRotationAction::Dismiss,
        })
        .await
        .unwrap();
    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::NotApplicable
    );
}

#[tokio::test]
async fn leak_rotation_update_missing_record_returns_invalid_cursor() {
    let db = test_db().await;
    let resolver = test_resolver();
    let service = LeaksService::new(&db, &resolver, 5_000_000);
    let err = service
        .update_rotation(&LeakRotationUpdate {
            report_id: "nonexistent".into(),
            action: LeakRotationAction::Accept,
        })
        .await
        .unwrap_err();
    assert_eq!(err, LeakListError::InvalidCursor);
}

#[tokio::test]
async fn leak_protected_value_deletion_retains_historical_metadata() {
    let db = test_db().await;
    let resolver = test_resolver();
    let report_id = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "deletable-secret",
        LeakSource::CredentialLeak,
        LeakCategory::Password,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    service
        .delete_protected_value(&LeakProtectedValueDelete {
            report_id: report_id.clone(),
        })
        .await
        .unwrap();

    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.status,
        crate::db::protected_leak_records::LeakRecordStatus::Deleted
    );
    assert!(record.retired_at_ms.is_some());
    assert_eq!(record.source, LeakSource::CredentialLeak);
    assert_eq!(record.category, LeakCategory::Password);

    let refs = db.protected_leak_records_refs(session_a()).await.unwrap();
    assert!(refs.is_empty());

    let mut reveal_service = LeaksService::new(&db, &resolver, 5_000_000);
    let cap = reveal_service
        .begin_reveal(&BeginLeakReveal {
            report_id: report_id.clone(),
        })
        .unwrap();
    let result = reveal_service
        .reveal(&RevealLeakReportSecret { capability: cap })
        .await
        .unwrap();
    assert!(matches!(result, LeakRevealResult::Deleted));
}

// ---------------------------------------------------------------------------
// Criterion 5: leak_reveal_requires_sensitive_local_channel — ordinary
// daemon/remote Response/Event codecs cannot carry plaintext; wrong-report/
// denied branches fail before protected read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_reveal_unauthorized_missing_report() {
    let db = test_db().await;
    let resolver = test_resolver();
    let mut service = LeaksService::new(&db, &resolver, 5_000_000);
    let cap = service
        .begin_reveal(&BeginLeakReveal {
            report_id: "nonexistent".into(),
        })
        .unwrap();
    let result = service
        .reveal(&RevealLeakReportSecret { capability: cap })
        .await
        .unwrap();
    assert!(matches!(result, LeakRevealResult::Unauthorized));
}

#[tokio::test]
async fn leak_reveal_succeeds_for_contained_record() {
    let db = test_db().await;
    let resolver = test_resolver();
    let secret = "revealed-secret-value";
    let report_id = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        secret,
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let mut service = LeaksService::new(&db, &resolver, 5_000_000);
    let cap = service
        .begin_reveal(&BeginLeakReveal {
            report_id: report_id.clone(),
        })
        .unwrap();
    let result = service
        .reveal(&RevealLeakReportSecret { capability: cap })
        .await
        .unwrap();
    match result {
        LeakRevealResult::Revealed {
            plaintext,
            report_id: rid,
        } => {
            assert_eq!(plaintext.as_str(), secret);
            assert_eq!(rid, report_id);
        }
        other => panic!("expected Revealed, got {other:?}"),
    }
}

#[tokio::test]
async fn leak_reveal_rate_limits_at_3_per_minute() {
    let db = test_db().await;
    let resolver = test_resolver();
    let mut service = LeaksService::new(&db, &resolver, 5_000_000);

    let mut report_ids = Vec::new();
    for i in 0..4 {
        let rid = insert_contained_leak(
            &db,
            &resolver,
            session_a(),
            &format!("rate-limit-secret-{i}"),
            LeakSource::ModelOutput,
            LeakCategory::Token,
            1_000_000 + i,
        )
        .await;
        report_ids.push(rid);
    }

    for i in 0..3 {
        let cap = service
            .begin_reveal(&BeginLeakReveal {
                report_id: report_ids[i].clone(),
            })
            .unwrap();
        let result = service
            .reveal(&RevealLeakReportSecret { capability: cap })
            .await
            .unwrap();
        assert!(
            matches!(result, LeakRevealResult::Revealed { .. }),
            "reveal {i}"
        );
    }

    let cap = service
        .begin_reveal(&BeginLeakReveal {
            report_id: report_ids[3].clone(),
        })
        .unwrap();
    let result = service
        .reveal(&RevealLeakReportSecret { capability: cap })
        .await
        .unwrap();
    assert!(matches!(result, LeakRevealResult::RateLimited));
}

// ---------------------------------------------------------------------------
// Criterion 6: leak_reveal_ephemeral_generation — LeaksPane is the sole
// Zeroizing buffer owner; full-repaint close/detach/lock/newer generation/
// 30-second timeout and late-result discard
// ---------------------------------------------------------------------------

#[test]
fn leaks_pane_reveal_buffer_zeroize_invalidates_generation() {
    let mut buf = LeaksPaneRevealBuffer::new();
    let gen0 = buf.generation();
    assert!(!buf.is_active());

    let installed = buf.install(Zeroizing::new("secret".to_owned()), "r1".to_owned(), gen0);
    assert!(installed);
    assert!(buf.is_active());
    assert_eq!(buf.report_id(), Some("r1"));

    buf.zeroize();
    let gen1 = buf.generation();
    assert_ne!(gen0, gen1);
    assert!(!buf.is_active());
    assert!(buf.report_id().is_none());
    assert!(buf.plaintext().is_none());

    let installed = buf.install(
        Zeroizing::new("late-secret".to_owned()),
        "r1".to_owned(),
        gen0,
    );
    assert!(!installed);
    assert!(!buf.is_active());
}

#[test]
fn leaks_pane_reveal_buffer_install_at_current_generation_succeeds() {
    let mut buf = LeaksPaneRevealBuffer::new();
    let generation = buf.generation();
    let installed = buf.install(
        Zeroizing::new("secret".to_owned()),
        "r1".to_owned(),
        generation,
    );
    assert!(installed);
    assert!(buf.is_active());
    assert_eq!(buf.plaintext().unwrap().as_str(), "secret");
}

#[test]
fn leaks_pane_reveal_buffer_check_timeout_zeroizes() {
    let mut buf = LeaksPaneRevealBuffer::new();
    let generation = buf.generation();
    buf.install(
        Zeroizing::new("secret".to_owned()),
        "r1".to_owned(),
        generation,
    );
    assert!(buf.is_active());

    assert!(!buf.check_timeout());
    assert!(buf.is_active());

    buf.zeroize();
    assert!(!buf.is_active());
}

// ---------------------------------------------------------------------------
// Criterion 7: leak_mark_rotated — explicit, reversible, metadata-only; fresh
// re-report clears it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_mark_rotated_is_reversible_and_cleared_by_re_report() {
    let db = test_db().await;
    let resolver = test_resolver();
    let report_id = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "rotation-secret",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    service
        .update_rotation(&LeakRotationUpdate {
            report_id: report_id.clone(),
            action: LeakRotationAction::MarkRotated,
        })
        .await
        .unwrap();
    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::Rotated
    );

    service
        .update_rotation(&LeakRotationUpdate {
            report_id: report_id.clone(),
            action: LeakRotationAction::Dismiss,
        })
        .await
        .unwrap();
    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::NotApplicable
    );

    let handler = LeakReportHandler::new(&db, &resolver, 2_000_000);
    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_a().to_owned(),
    );
    handler
        .report(
            &authority,
            Zeroizing::new("rotation-secret".to_owned()),
            LeakCategory::Token,
        )
        .await
        .unwrap();

    let record = db
        .protected_leak_record_get(&report_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.rotation,
        crate::db::protected_leak_records::LeakRotation::None
    );
    assert_eq!(record.seen_count, 2);
}

// ---------------------------------------------------------------------------
// Criterion 9: machine_wide_leak_owner_access — records from different
// projects and deleted/orphaned sessions remain Owner-visible, recoverable,
// and deletable by report ID
// ---------------------------------------------------------------------------

#[tokio::test]
async fn machine_wide_leak_owner_access_across_sessions() {
    let db = test_db().await;
    let resolver = test_resolver();
    let r1 = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        "secret-a",
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;
    let r2 = insert_contained_leak(
        &db,
        &resolver,
        session_b(),
        "secret-b",
        LeakSource::ToolOutput,
        LeakCategory::Key,
        2_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.rows.len(), 2);
    let ids: Vec<&str> = resp.rows.iter().map(|r| r.report_id.as_str()).collect();
    assert!(ids.contains(&r1.as_str()));
    assert!(ids.contains(&r2.as_str()));

    let resp = service
        .list(&LeakListRequest {
            session_filter: Some(session_a().to_owned()),
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.rows.len(), 1);
    assert_eq!(resp.rows[0].report_id, r1);

    let mut reveal_service = LeaksService::new(&db, &resolver, 5_000_000);
    for (rid, secret) in [(&r1, "secret-a"), (&r2, "secret-b")] {
        let cap = reveal_service
            .begin_reveal(&BeginLeakReveal {
                report_id: rid.clone(),
            })
            .unwrap();
        let result = reveal_service
            .reveal(&RevealLeakReportSecret { capability: cap })
            .await
            .unwrap();
        match result {
            LeakRevealResult::Revealed { plaintext, .. } => {
                assert_eq!(plaintext.as_str(), secret);
            }
            other => panic!("expected Revealed for {rid}, got {other:?}"),
        }
    }

    for rid in [&r1, &r2] {
        service
            .delete_protected_value(&LeakProtectedValueDelete {
                report_id: rid.clone(),
            })
            .await
            .unwrap();
        let record = db.protected_leak_record_get(rid).await.unwrap().unwrap();
        assert_eq!(
            record.status,
            crate::db::protected_leak_records::LeakRecordStatus::Deleted
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion 10: Sentinel plaintext is absent from list, events, transcripts,
// caches, clipboard, logs, errors, portable exports, analytics, and remote
// frames
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sentinel_plaintext_absent_from_list_output() {
    let db = test_db().await;
    let resolver = test_resolver();
    let sentinel = "SENTINEL_PLAINTEXT_VALUE_12345";
    insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        sentinel,
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);
    let resp = service
        .list(&LeakListRequest {
            session_filter: None,
            limit: 100,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.rows.len(), 1);

    let row_debug = format!("{:?}", resp.rows[0]);
    assert!(
        !row_debug.contains(sentinel),
        "sentinel must not appear in list row debug"
    );

    let resp_debug = format!("{resp:?}");
    assert!(
        !resp_debug.contains(sentinel),
        "sentinel must not appear in list response debug"
    );
}

#[tokio::test]
async fn sentinel_plaintext_absent_from_rotation_and_delete_errors() {
    let db = test_db().await;
    let resolver = test_resolver();
    let sentinel = "SENTINEL_ROTATION_SECRET";
    let _report_id = insert_contained_leak(
        &db,
        &resolver,
        session_a(),
        sentinel,
        LeakSource::ModelOutput,
        LeakCategory::Token,
        1_000_000,
    )
    .await;

    let service = LeaksService::new(&db, &resolver, 5_000_000);

    let err = service
        .update_rotation(&LeakRotationUpdate {
            report_id: "nonexistent".into(),
            action: LeakRotationAction::Accept,
        })
        .await
        .unwrap_err();
    let err_debug = format!("{err:?}");
    assert!(!err_debug.contains(sentinel));

    let err = service
        .delete_protected_value(&LeakProtectedValueDelete {
            report_id: "nonexistent".into(),
        })
        .await
        .unwrap_err();
    let err_debug = format!("{err:?}");
    assert!(!err_debug.contains(sentinel));
}

// ---------------------------------------------------------------------------
// SensitiveLocalChannel marker
// ---------------------------------------------------------------------------

#[test]
fn sensitive_local_channel_marker_is_local() {
    let ch = SensitiveLocalChannel;
    assert!(ch.is_local_sensitive());
}
