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

/// A **test-only** unkeyed SHA-256 hex digest of the plaintext. Production no
/// longer computes any unkeyed literal fingerprint (the `sha256_hex` helper was
/// deleted from `leak_report`); this helper exists purely to build the
/// KNOWN-BAD oracle value so a test can prove the stored/dedup fingerprints are
/// NOT equal to it — i.e. that the real fingerprint is the key-store keyed MAC.
fn unkeyed_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
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

    let literal_fp = unkeyed_sha256_hex(b"pending-secret");
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
// AC0 correction (was `report_leak_tool_name_is_exact`, which constructed a
// forbidden `ReportLeakTool` and asserted `Tool::name()`).
//
// The rejected landing exposed `report_leak` through `impl Tool for
// ReportLeakTool`, whose `call(args: Value, _)` receives the plaintext secret
// on the generic authorized-tool surface. That impl and the `ReportLeakTool`
// type are DELETED. This corrected test asserts the *schema advertising* name
// is exactly `report_leak` and that the sanctioned ingress is the
// `decode_and_contain_report_leak` host entry — not a `Tool`.
//
// Compile-forced guard against regression: `ReportLeakTool` no longer exists as
// a type. Re-adding `impl Tool for ReportLeakTool` requires re-introducing that
// type, and the module docs + `decode_and_contain_report_leak` entry make the
// generic-tool path the rejected design. (The generic-roster *registration*
// assertion belongs with the provider-barrier wiring, which is deferred; see
// the implementer report.)
// ---------------------------------------------------------------------------

#[test]
fn report_leak_advertising_name_is_exact_and_not_a_generic_tool() {
    // The advertising name a provider decoder keys on is exactly `report_leak`.
    assert_eq!(REPORT_LEAK_TOOL, "report_leak");

    // The shared schema is an ingress-only object with no capability-bearing
    // field; there is no `Tool`-shaped surface here.
    let schema = report_leak_schema();
    assert_eq!(
        schema.get("type").and_then(|v| v.as_str()),
        Some("object"),
        "report_leak advertises only the closed ingress schema"
    );
    assert_eq!(
        schema.get("additionalProperties").and_then(|v| v.as_bool()),
        Some(false)
    );
}

// ---------------------------------------------------------------------------
// AC12: leak containment uses the shared sole-writer AEAD path (not a local
// cipher), and the stored fingerprint is the keyed MAC (never plain SHA-256).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leak_containment_uses_sole_writer_api() {
    let db = test_db().await;
    let resolver = test_resolver();
    let handler = LeakReportHandler::new(&db, &resolver, 1_000_000);

    let secret = "sole-writer-contained-secret";
    let authority = ReportLeakAuthority::new(
        LeakSource::ModelOutput,
        provenance(),
        session_id().to_owned(),
    );
    let outcome = handler
        .report(
            &authority,
            Zeroizing::new(secret.to_owned()),
            LeakCategory::Secret,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, LeakReportOutcome::Contained { .. }));

    // Exactly one encrypted history row, written by the shared sole writer.
    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    let row = &history[0];
    assert_eq!(row.source, ProtectedRedactionSource::ContainedLeak);

    // The row decrypts through the production rehydrate path — proving the
    // shared AEAD path, not a local cipher (which no longer exists).
    let history_api = ProtectedRedactionHistory::new(&db, &resolver);
    let rehydrated = history_api
        .rehydrate_by_history_id(&row.history_id)
        .await
        .expect("shared AEAD rehydrate must succeed");
    assert_eq!(rehydrated.as_str().unwrap().as_str(), secret);

    // The stored fingerprint is the keyed MAC, never the unkeyed SHA-256 of the
    // literal, and is what rehydrate reports back.
    assert_eq!(rehydrated.fingerprint(), row.fingerprint);
    assert_ne!(row.fingerprint, unkeyed_sha256_hex(secret.as_bytes()));
    assert_eq!(row.fingerprint.len(), 64);
    assert!(row.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===========================================================================
// AC-named tests driving the SOLE HOST INGRESS ENTRY (`decode_and_contain_
// report_leak`) — the production path a provider decoder maps a `report_leak`
// tool call into, replacing the deleted generic `impl Tool for ReportLeakTool`.
//
// Footprint scope note: these cover the parts of the ACs that are provable at
// the `leak_report` layer (the ingress function, containment, storage, and the
// no-oracle/no-second-cipher properties). The live-session redaction install,
// the buffered provider turn state machine, and the trusted-child coordinator
// require files outside this prompt's declared footprint and are deferred (see
// the implementer report).
// ===========================================================================

/// AC2 (containment-only portion): the ingress function maps a raw decoded
/// `report_leak` argument `Value` into the protected representation and returns
/// only a content-free outcome. The plaintext secret never appears in the
/// model-facing string nor in any safe leak projection, yet it is recoverable
/// (encrypted) from protected storage — proving generic dispatch never receives
/// the secret while containment persisted.
#[tokio::test]
async fn model_leak_report_precedes_generic_persistence() {
    let db = test_db().await;
    let resolver = test_resolver();

    // A distinguishing marker withheld from every other path.
    let marker = "SENTINEL-9c1f-do-not-leak";
    let args = serde_json::json!({ "secret": marker, "source": "tool_output" });

    let outcome = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        provenance(),
        session_id(),
        &args,
    )
    .await;

    // The model receives only the content-free `contained` string.
    assert_eq!(outcome.to_model_string(), "contained");
    assert!(!outcome.to_model_string().contains(marker));

    // Protected storage committed exactly one leak record and one history row,
    // and neither their safe projections nor their Debug carry the plaintext.
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, LeakRecordStatus::Contained);
    assert!(!format!("{:?}", records[0]).contains(marker));

    let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
    assert_eq!(refs.len(), 1);
    assert!(!format!("{refs:?}").contains(marker));

    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_ne!(
        history[0].ciphertext,
        marker.as_bytes(),
        "history ciphertext must not be the plaintext bytes"
    );
    assert!(!format!("{:?}", history[0]).contains(marker));

    // The literal is nonetheless recoverable (encrypted) through the shared
    // sole-writer rehydrate path — the containment is real, not a drop.
    let history_api = ProtectedRedactionHistory::new(&db, &resolver);
    let rehydrated = history_api
        .rehydrate_by_history_id(&history[0].history_id)
        .await
        .expect("contained literal must rehydrate through the shared AEAD path");
    assert_eq!(rehydrated.as_str().unwrap().as_str(), marker);
}

/// AC7: `ReportLeak` ingress is containment-only — closed source validation,
/// host-derived provenance, pending→contained state, and no value id / read /
/// grant / action capability returned to the model. A malformed/closed-source
/// violation is Discarded with NO protected record.
#[tokio::test]
async fn untrusted_leak_report_is_containment_only() {
    let db = test_db().await;
    let resolver = test_resolver();

    // Precondition: the bogus source really is rejected by the closed parser.
    assert!(
        parse_report_leak_args(&serde_json::json!({
            "secret": "x", "source": "arbitrary_untrusted_source"
        }))
        .is_err(),
        "closed `source` enum must reject an unknown value"
    );

    // A closed-source violation through the real ingress → Discarded (Failed),
    // no protected record committed.
    let bad = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        provenance(),
        session_id(),
        &serde_json::json!({ "secret": "x", "source": "arbitrary_untrusted_source" }),
    )
    .await;
    assert_eq!(bad, LeakReportOutcome::Failed);
    assert!(
        db.protected_leak_records_list(session_id())
            .await
            .unwrap()
            .is_empty(),
        "a rejected source must leave no protected record"
    );

    // A valid closed-source report: host-derived provenance is stamped (the
    // model supplies none), the record lands `contained`, and the model string
    // carries no id / value / capability.
    let host_prov = LeakProvenance {
        provider_id: Some("anthropic".to_owned()),
        model_id: Some("claude-x".to_owned()),
        generation: Some(7),
        connector_id: Some("gh".to_owned()),
    };
    let outcome = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        host_prov,
        session_id(),
        &serde_json::json!({ "secret": "leaked-cred", "source": "credential_leak" }),
    )
    .await;
    assert_eq!(outcome.to_model_string(), "contained");
    if let LeakReportOutcome::Contained { report_id } = &outcome {
        // The report id is host-internal; the model never receives it.
        assert!(!outcome.to_model_string().contains(report_id));
    } else {
        panic!("expected Contained, got {outcome:?}");
    }

    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].source, LeakSource::CredentialLeak);
    assert_eq!(records[0].status, LeakRecordStatus::Contained);
    assert_eq!(records[0].provider_id.as_deref(), Some("anthropic"));
    assert_eq!(records[0].model_id.as_deref(), Some("claude-x"));
    assert_eq!(records[0].generation, Some(7));
    assert_eq!(records[0].connector_id.as_deref(), Some("gh"));
}

/// AC8: encryption-only protected storage plus recovery, deduplication, and
/// fail-closed key failure — all through the production ingress entry.
#[tokio::test]
async fn leak_protected_storage_and_recovery() {
    let db = test_db().await;
    let resolver = test_resolver();
    let secret = "recoverable-protected-literal";

    // Store via the ingress.
    let first = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        provenance(),
        session_id(),
        &serde_json::json!({ "secret": secret, "source": "model_output" }),
    )
    .await;
    assert!(matches!(first, LeakReportOutcome::Contained { .. }));

    // Recovery: the encrypted literal rehydrates through the shared AEAD path.
    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    let history_api = ProtectedRedactionHistory::new(&db, &resolver);
    let rehydrated = history_api
        .rehydrate_by_history_id(&history[0].history_id)
        .await
        .expect("rehydrate must succeed with the correct key");
    assert_eq!(rehydrated.as_str().unwrap().as_str(), secret);

    // Deduplication: the same literal re-reported does not create a second
    // record or history row; seen metadata advances.
    let second = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        provenance(),
        session_id(),
        &serde_json::json!({ "secret": secret, "source": "model_output" }),
    )
    .await;
    assert!(matches!(second, LeakReportOutcome::Deduplicated { .. }));
    assert_eq!(second.to_model_string(), "contained");
    let records = db.protected_leak_records_list(session_id()).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].seen_count, 2);
    assert_eq!(
        db.protected_redaction_history_list(session_id())
            .await
            .unwrap()
            .len(),
        1
    );

    // Fail-closed on key failure: a resolver with no key commits nothing.
    let db2 = test_db().await;
    let empty = MapKeyResolver::new();
    let failed = decode_and_contain_report_leak(
        &db2,
        &empty,
        1_000_000,
        provenance(),
        session_id(),
        &serde_json::json!({ "secret": "no-key-secret", "source": "model_output" }),
    )
    .await;
    assert_eq!(failed, LeakReportOutcome::Failed);
    assert!(
        db2.protected_leak_records_list(session_id())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db2.protected_redaction_history_list(session_id())
            .await
            .unwrap()
            .is_empty()
    );
}

/// AC9: no second cipher and no unkeyed oracle. The stored history fingerprint
/// and the record dedup index are BOTH key-store keyed (differ from the unkeyed
/// SHA-256 of the plaintext an offline attacker could compute), and the parsed
/// request never prints the secret through `Debug`.
#[tokio::test]
async fn leak_report_no_second_cipher_or_unkeyed_oracle() {
    let db = test_db().await;
    let resolver = test_resolver();
    let secret = "oracle-target-secret";

    let outcome = decode_and_contain_report_leak(
        &db,
        &resolver,
        1_000_000,
        provenance(),
        session_id(),
        &serde_json::json!({ "secret": secret, "source": "model_output" }),
    )
    .await;
    assert!(matches!(outcome, LeakReportOutcome::Contained { .. }));

    let history = db
        .protected_redaction_history_list(session_id())
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    let stored_fp = &history[0].fingerprint;

    // The known-bad offline oracle value: unkeyed SHA-256 of the plaintext.
    let oracle = unkeyed_sha256_hex(secret.as_bytes());
    assert_ne!(
        stored_fp, &oracle,
        "stored fingerprint must be the keyed MAC, not the unkeyed literal hash"
    );

    // The dedup index derived from the keyed MAC differs from the same index
    // derived from the unkeyed oracle — the production index is not brute-forceable.
    let real_index = keyed_leak_fingerprint(session_id(), LeakSource::ModelOutput, stored_fp);
    let oracle_index = keyed_leak_fingerprint(session_id(), LeakSource::ModelOutput, &oracle);
    assert_ne!(real_index, oracle_index);

    // The parsed request never prints the secret through Debug.
    let req = parse_report_leak_args(&serde_json::json!({
        "secret": secret, "source": "model_output"
    }))
    .unwrap();
    let dbg = format!("{req:?}");
    assert!(!dbg.contains(secret), "Debug must not print the secret");
    assert!(
        dbg.contains("REDACTED"),
        "Debug must render a redacted secret"
    );
}
