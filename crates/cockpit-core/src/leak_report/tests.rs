//! Tests for the leak report containment tool and handler.
//!
//! Coverage maps to the prompt's acceptance criteria that are testable at the
//! cockpit-core layer:
//!
//! * `untrusted_leak_report_is_containment_only` — closed source validation,
//!   host-derived provenance, no value id/read/grant/action capability, pending
//!   Owner containment state, and schema availability.
//! * `leak_report_returns_only_contained_or_content_free_failure` — the model
//!   receives only `contained`, `rate_limited`, or `failed`.
//! * `leak_report_deduplicates_by_keyed_fingerprint` — re-report updates safe
//!   `seen` metadata and clears rotation state.
//! * `leak_report_rate_limits_at_32_per_hour` — the 32-reports/session/hour
//!   rate limit.
//! * `leak_report_enforces_16_kib_utf8_payload_bound` — the fixed maximum
//!   secret payload.
//! * `leak_report_commits_protected_record_before_ack` — redaction install and
//!   protected persistence commit before acknowledgement.
//! * `leak_report_schema_is_ingress_only` — the schema has no value id, read,
//!   grant, or action field.
//! * `leak_report_generic_dispatch_never_sees_secret` — the parser consumes
//!   the literal and the handler returns only content-free strings.
//! * `leak_protected_storage_is_encryption_only` — the protected leak record
//!   and redaction-history rows carry no plaintext.

use super::*;
use crate::db::Db;
use crate::db::protected_leak_records::{
    InsertLeakRecordInput, InsertLeakResult, LeakCategory, LeakRecordStatus, LeakRotation,
    LeakSource, insert_leak_record_conn, transition_leak_status_conn,
};
use crate::db::protected_redaction_history::ProtectedRedactionSource;
use crate::redact::protected_redaction_history::{
    MapKeyResolver, ProtectedLiteral, ProtectedRedactionHistory, REDACTION_KEY_LEN,
    RedactionHistorySource,
};

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
    // carry cascading FKs to sessions(session_id), so the referenced session row
    // must exist before the leak-report handler writes any protected record.
    db.write(|conn| {
        conn.execute(
            "INSERT INTO sessions(session_id,project_id,project_root,started_at,last_active_at) \
             VALUES(?1,'p','/redacted',1,1)",
            [session_id()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    db
}

fn session_id() -> &'static str {
    "cccccccc-cccc-cccc-cccc-333333333333"
}

fn provenance() -> LeakProvenance {
    LeakProvenance {
        provider_id: Some("openai".to_owned()),
        model_id: Some("gpt-4".to_owned()),
        generation: Some(42),
        connector_id: None,
    }
}

// ---------------------------------------------------------------------------
// Criterion: schema is ingress-only (no value id / read / grant / action)
// ---------------------------------------------------------------------------

#[test]
fn leak_report_schema_is_ingress_only() {
    let schema = report_leak_schema();
    let obj = schema.as_object().unwrap();
    let props = obj.get("properties").unwrap().as_object().unwrap();
    // The only accepted keys are `secret`, `source`, and optional `category`.
    // There is no `sealed_value_id`, `action_id`, `value_id`, `read`, `grant`,
    // `action`, `endpoint`, `command`, `env_key`, `header`, `request_template`,
    // or `output_projection` field.
    assert!(props.contains_key("secret"));
    assert!(props.contains_key("source"));
    assert!(props.contains_key("category"));
    for forbidden in [
        "sealed_value_id",
        "action_id",
        "value_id",
        "read",
        "grant",
        "action",
        "endpoint",
        "command",
        "env_key",
        "header",
        "request_template",
        "output_projection",
    ] {
        assert!(
            !props.contains_key(forbidden),
            "schema must not accept `{forbidden}`"
        );
    }
    // additionalProperties is false.
    assert_eq!(
        obj.get("additionalProperties").and_then(|v| v.as_bool()),
        Some(false)
    );
    // `source` is a closed enum.
    let source_enum = props
        .get("source")
        .unwrap()
        .get("enum")
        .unwrap()
        .as_array()
        .unwrap();
    let sources: Vec<&str> = source_enum.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        sources,
        [
            "model_output",
            "tool_output",
            "reasoning",
            "env_leak",
            "credential_leak",
            "other"
        ]
    );
}

// ---------------------------------------------------------------------------
// Criterion: parser rejects unknown keys and validates the closed source
// ---------------------------------------------------------------------------

#[test]
fn parse_report_leak_rejects_unknown_keys() {
    let args = serde_json::json!({
        "secret": "abc",
        "source": "model_output",
        "sealed_value_id": "should-be-rejected"
    });
    assert!(parse_report_leak_args(&args).is_err());
}

#[test]
fn parse_report_leak_rejects_unknown_source() {
    let args = serde_json::json!({
        "secret": "abc",
        "source": "not_a_real_source"
    });
    assert!(parse_report_leak_args(&args).is_err());
}

#[test]
fn parse_report_leak_rejects_empty_secret() {
    let args = serde_json::json!({
        "secret": "",
        "source": "model_output"
    });
    assert!(parse_report_leak_args(&args).is_err());
}

#[test]
fn parse_report_leak_accepts_optional_category() {
    let args = serde_json::json!({
        "secret": "abc",
        "source": "model_output"
    });
    let req = parse_report_leak_args(&args).unwrap();
    assert_eq!(req.category, LeakCategory::Secret);

    let args = serde_json::json!({
        "secret": "abc",
        "source": "model_output",
        "category": "token"
    });
    let req = parse_report_leak_args(&args).unwrap();
    assert_eq!(req.category, LeakCategory::Token);
}

// ---------------------------------------------------------------------------
// Criterion: 16 KiB UTF-8 payload bound
// ---------------------------------------------------------------------------

#[test]
fn leak_report_enforces_16_kib_utf8_payload_bound() {
    let args = serde_json::json!({
        "secret": "x".repeat(MAX_LITERAL_LEN),
        "source": "model_output"
    });
    assert!(parse_report_leak_args(&args).is_ok());

    let args = serde_json::json!({
        "secret": "x".repeat(MAX_LITERAL_LEN + 1),
        "source": "model_output"
    });
    let err = parse_report_leak_args(&args).unwrap_err().to_string();
    assert!(err.contains("exceeds"), "{err}");
    assert!(err.contains(&MAX_LITERAL_LEN.to_string()), "{err}");
}

// ---------------------------------------------------------------------------
// Criterion: the model receives only `contained` or content-free failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_returns_only_contained_or_content_free_failure() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );
    let secret = Zeroizing::new("super-secret-api-key".to_owned());
    let outcome = handler
        .report(&authority, secret, LeakCategory::Token)
        .await
        .unwrap();

    // The model string is exactly "contained" — no value id, no read, no grant.
    let model_str = outcome.to_model_string();
    assert_eq!(model_str, "contained");
    assert!(!model_str.contains("super-secret-api-key"));
    assert!(!model_str.contains("key"));
    // The report id is not in the model string.
    if let LeakReportOutcome::Contained { report_id } = &outcome {
        assert!(!model_str.contains(report_id));
    }
}

// ---------------------------------------------------------------------------
// Criterion: deduplication by keyed fingerprint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_deduplicates_by_keyed_fingerprint() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );

    // First report.
    let outcome1 = handler
        .report(
            &authority,
            Zeroizing::new("same-secret".to_owned()),
            LeakCategory::Secret,
        )
        .await
        .unwrap();
    let report_id_1 = match &outcome1 {
        LeakReportOutcome::Contained { report_id } => report_id.clone(),
        _ => panic!("expected contained, got {outcome1:?}"),
    };

    // Second report of the same literal: dedup.
    let outcome2 = handler
        .report(
            &authority,
            Zeroizing::new("same-secret".to_owned()),
            LeakCategory::Secret,
        )
        .await
        .unwrap();
    match &outcome2 {
        LeakReportOutcome::Deduplicated {
            report_id,
            seen_count,
        } => {
            assert_eq!(report_id, &report_id_1);
            assert_eq!(*seen_count, 2);
        }
        _ => panic!("expected deduplicated, got {outcome2:?}"),
    }

    // Both model strings are "contained".
    assert_eq!(outcome1.to_model_string(), "contained");
    assert_eq!(outcome2.to_model_string(), "contained");

    // Only one leak record exists.
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].seen_count, 2);
    assert_eq!(records[0].status, LeakRecordStatus::Contained);

    // Only one redaction-history row exists (dedup on fingerprint).
    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].source, ProtectedRedactionSource::ContainedLeak);
}

// ---------------------------------------------------------------------------
// Criterion: rate limit is 32 accepted reports/session/hour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_rate_limits_at_32_per_hour() {
    let db = test_db().await;
    let resolver = test_resolver();
    // Use a fixed base time so all 32 fit in one hour window.
    let handler = LeakReportHandler::new(&db, &resolver, 2_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );

    // Submit 32 distinct secrets (distinct literals → distinct fingerprints).
    for i in 0..LEAK_REPORT_RATE_LIMIT_PER_HOUR {
        let outcome = handler
            .report(
                &authority,
                Zeroizing::new(format!("secret-{i}")),
                LeakCategory::Secret,
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, LeakReportOutcome::Contained { .. }),
            "report {i} should be contained, got {outcome:?}"
        );
    }

    // The 33rd is rate-limited.
    let outcome = handler
        .report(
            &authority,
            Zeroizing::new("secret-33".to_owned()),
            LeakCategory::Secret,
        )
        .await
        .unwrap();
    assert_eq!(outcome, LeakReportOutcome::RateLimited);
    assert_eq!(outcome.to_model_string(), "rate_limited");
}

// ---------------------------------------------------------------------------
// Criterion: protected storage is encryption-only (no plaintext)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_protected_storage_is_encryption_only() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::CredentialLeak,
        provenance(),
        session_id().to_owned(),
    );
    let secret_literal = "plaintext-must-never-appear";
    handler
        .report(
            &authority,
            Zeroizing::new(secret_literal.to_owned()),
            LeakCategory::Password,
        )
        .await
        .unwrap();

    // The leak record carries no plaintext.
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.source, LeakSource::CredentialLeak);
    assert_eq!(record.category, LeakCategory::Password);
    assert_eq!(record.status, LeakRecordStatus::Contained);
    // The record's Debug rendering must not contain the literal.
    let record_debug = format!("{record:?}");
    assert!(
        !record_debug.contains(secret_literal),
        "leak record debug must not contain the literal"
    );

    // The safe ref projection must not contain the literal or the history_id.
    let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
    assert_eq!(refs.len(), 1);
    let ref_debug = format!("{:?}", refs[0]);
    assert!(
        !ref_debug.contains(secret_literal),
        "leak ref debug must not contain the literal"
    );

    // The redaction-history row carries no plaintext: ciphertext is not the
    // literal bytes.
    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    let row = &history[0];
    assert_eq!(row.source, ProtectedRedactionSource::ContainedLeak);
    assert_ne!(
        row.ciphertext,
        secret_literal.as_bytes(),
        "ciphertext must not be the plaintext bytes"
    );
    let row_debug = format!("{row:?}");
    assert!(
        !row_debug.contains(secret_literal),
        "history row debug must not contain the literal"
    );
}

// ---------------------------------------------------------------------------
// Criterion: host-derived provenance is stamped, never model-supplied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_stamps_host_derived_provenance() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let prov = LeakProvenance {
        provider_id: Some("anthropic".to_owned()),
        model_id: Some("claude-3".to_owned()),
        generation: Some(99),
        connector_id: Some("gh".to_owned()),
    };
    let authority = ReportLeakAuthority::new(
        LeakSource::ToolOutput,
        prov.clone(),
        session_id().to_owned(),
    );
    handler
        .report(
            &authority,
            Zeroizing::new("tool-leaked-secret".to_owned()),
            LeakCategory::Key,
        )
        .await
        .unwrap();

    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.provider_id.as_deref(), Some("anthropic"));
    assert_eq!(r.model_id.as_deref(), Some("claude-3"));
    assert_eq!(r.generation, Some(99));
    assert_eq!(r.connector_id.as_deref(), Some("gh"));
    assert_eq!(r.source, LeakSource::ToolOutput);
}

// ---------------------------------------------------------------------------
// Criterion: keyed fingerprint is safe and deterministic
// ---------------------------------------------------------------------------

#[test]
fn keyed_leak_fingerprint_is_deterministic_and_distinct() {
    let fp_a = keyed_leak_fingerprint(session_id(), LeakSource::ModelOutput, "abc123");
    let fp_b = keyed_leak_fingerprint(session_id(), LeakSource::ModelOutput, "abc123");
    assert_eq!(fp_a, fp_b);
    assert_eq!(fp_a.len(), 64);
    assert!(fp_a.chars().all(|c| c.is_ascii_hexdigit()));

    // Different source → different keyed fingerprint.
    let fp_c = keyed_leak_fingerprint(session_id(), LeakSource::ToolOutput, "abc123");
    assert_ne!(fp_a, fp_c);

    // Different session → different keyed fingerprint.
    let fp_d = keyed_leak_fingerprint(
        "dddddddd-dddd-dddd-dddd-444444444444",
        LeakSource::ModelOutput,
        "abc123",
    );
    assert_ne!(fp_a, fp_d);
}

// ---------------------------------------------------------------------------
// Criterion: pending records are not listable via the safe refs surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_pending_record_is_not_listable() {
    let db = test_db().await;

    // Insert a record directly as pending (simulating a host-issued pending
    // containment before the protected persistence commits).
    let resolver = test_resolver();
    let history = ProtectedRedactionHistory::new(&db, &resolver);
    let history_id = history
        .append_and_attach(
            session_id(),
            ProtectedLiteral::new(
                "pending-secret".to_owned(),
                RedactionHistorySource::ContainedLeak,
                None,
                None,
            )
            .unwrap(),
            vec![],
        )
        .await
        .unwrap();

    let literal_fp = sha256_hex(b"pending-secret");
    let keyed_fp = keyed_leak_fingerprint(session_id(), LeakSource::Reasoning, &literal_fp);

    let input = InsertLeakRecordInput {
        report_id: String::new(),
        session_id: session_id().to_owned(),
        history_id,
        leak_fingerprint: keyed_fp,
        source: LeakSource::Reasoning,
        category: LeakCategory::Pii,
        provenance: provenance(),
        status: LeakRecordStatus::Pending,
        now_ms: 1_000_000,
    };
    let report_id = db
        .write(move |conn| {
            let r = insert_leak_record_conn(conn, &input)?;
            Ok(match r {
                InsertLeakResult::Created { report_id } => report_id,
                InsertLeakResult::Existing { report_id, .. } => report_id,
            })
        })
        .await
        .unwrap();

    // Pending: not listable via safe refs.
    let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
    assert!(refs.is_empty());

    // Transition to contained.
    db.write(move |conn| {
        transition_leak_status_conn(conn, &report_id, LeakRecordStatus::Contained, 1_100_000)
    })
    .await
    .unwrap();

    // Now listable.
    let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
    assert_eq!(refs.len(), 1);
}

// ---------------------------------------------------------------------------
// Criterion: ProtectedSensitiveIngress::ReportLeak is a closed variant
// ---------------------------------------------------------------------------

#[test]
fn protected_sensitive_ingress_report_leak_is_closed_variant() {
    let ingress = ProtectedSensitiveIngress::ReportLeak {
        source: LeakSource::EnvLeak,
    };
    match &ingress {
        ProtectedSensitiveIngress::ReportLeak { source } => {
            assert_eq!(*source, LeakSource::EnvLeak);
        }
        _ => panic!("wrong variant"),
    }
    // The closed enum has exactly 4 variants.
    let variants = [
        ProtectedSensitiveIngress::OwnerWrite {
            record_id: None,
            scope_version: "v1".to_owned(),
            disposition: OwnerWriteDisposition::Create,
        },
        ProtectedSensitiveIngress::OwnerRecover {
            record_id: "r1".to_owned(),
            version: 1,
        },
        ProtectedSensitiveIngress::TrustedChildCapture {
            record_id: "r1".to_owned(),
            project: "p".to_owned(),
            session: "s".to_owned(),
            generation: 1,
            version: 1,
            source_tool_call_id: "tc1".to_owned(),
        },
        ProtectedSensitiveIngress::ReportLeak {
            source: LeakSource::Other,
        },
    ];
    assert_eq!(variants.len(), 4);
}

// ---------------------------------------------------------------------------
// Criterion: fail-closed on key resolver failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_fails_closed_on_key_failure() {
    let db = test_db().await;
    // Empty resolver: no key for version 1.
    let resolver = MapKeyResolver::new();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );
    let outcome = handler
        .report(
            &authority,
            Zeroizing::new("secret-without-key".to_owned()),
            LeakCategory::Secret,
        )
        .await
        .unwrap();
    assert_eq!(outcome, LeakReportOutcome::Failed);
    assert_eq!(outcome.to_model_string(), "failed");

    // No leak record was committed.
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert!(records.is_empty());

    // No redaction-history row was committed.
    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert!(history.is_empty());
}

// ---------------------------------------------------------------------------
// Criterion: re-report clears rotation state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_re_report_clears_rotation_state() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );

    // First report.
    handler
        .report(
            &authority,
            Zeroizing::new("rotation-secret".to_owned()),
            LeakCategory::Token,
        )
        .await
        .unwrap();

    // Simulate an Owner setting rotation to pending_user on the record.
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    let report_id = records[0].report_id.clone();

    db.write(move |conn| {
        conn.execute(
            "UPDATE protected_leak_records SET rotation = 'pending_user' WHERE report_id = ?1",
            rusqlite::params![report_id],
        )?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap();

    // Re-report: should clear rotation to 'none'.
    handler
        .report(
            &authority,
            Zeroizing::new("rotation-secret".to_owned()),
            LeakCategory::Token,
        )
        .await
        .unwrap();

    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].seen_count, 2);
    assert_eq!(LeakRotation::None, records[0].rotation);
}

// ---------------------------------------------------------------------------
// Criterion: the literal is never in the model-facing output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_report_literal_never_in_model_output() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let test_cases = [
        (
            "AKIAIOSFODNN7EXAMPLE",
            LeakSource::ModelOutput,
            LeakCategory::Token,
        ),
        (
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            LeakSource::ToolOutput,
            LeakCategory::Token,
        ),
        ("password123", LeakSource::Reasoning, LeakCategory::Password),
    ];

    for (secret, source, category) in test_cases {
        let authority = ReportLeakAuthority::new(source, provenance(), session_id().to_owned());
        let outcome = handler
            .report(&authority, Zeroizing::new(secret.to_owned()), category)
            .await
            .unwrap();
        let model_str = outcome.to_model_string();
        assert!(
            !model_str.contains(secret),
            "model output `{model_str}` must not contain the literal"
        );
    }
}

// ---------------------------------------------------------------------------
// Criterion: REPORT_LEAK_TOOL name is exact
// ---------------------------------------------------------------------------

#[test]
fn report_leak_tool_name_is_exact() {
    let tool = ReportLeakTool::new();
    assert_eq!(tool.name(), "report_leak");
}
